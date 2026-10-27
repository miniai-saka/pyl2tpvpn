"""IKEv2 PSK with IPv4 tunnel/transport ESP, rekey and encrypted liveness.

RFC 7296 subset: IPv4, MODP DH, AES-CBC, PRF-HMAC-SHA1,
AUTH-HMAC-SHA1-96, no ESN. EAP/certificates/MOBIKE/fragmentation are
not advertised. Native tunnel mode obtains an address and DNS using CP.
"""
import asyncio
import hashlib
import hmac
import ipaddress
import logging
import secrets
import struct
import time
from contextlib import asynccontextmanager
from .crypto import DH, ESP, prf, expand, encrypt, decrypt
from .errors import AuthenticationError, NegotiationError, ProtocolError, TunnelClosed
from .transport import Exchanges
from .selectors import (Selector, encode_selectors, parse_selectors,
                        check_narrowing, configuration_request, configuration_reply)
from .wire import (IKEPacket, Payload, encode_payloads, decode_payloads, one,
                   attributes, parse_attributes, need, integer, u16, u32)

log = logging.getLogger(__name__)


class TemporaryFailure(NegotiationError):
    """Authenticated peer is busy; retry later while current keys remain valid."""


def notify(code, data=b"", protocol=0, spi=b""):
    return Payload(41, bytes([protocol, len(spi)])+u16(code)+spi+data)


def parse_notify(body):
    need(len(body) >= 4 and 4+body[1] <= len(body), "short IKEv2 notification")
    return integer(body[2:4]), body[0], body[4:4+body[1]], body[4+body[1]:]


def proposal(protocol, spi, transforms):
    data = b""
    for i, (kind, tid, attrs) in enumerate(transforms):
        a = attributes(attrs)
        data += struct.pack("!BBHBBH", 3 if i+1 < len(transforms) else 0, 0, 8+len(a), kind, 0, tid)+a
    p = bytes([1, protocol, len(spi), len(transforms)])+spi+data
    return b"\0\0"+u16(len(p)+4)+p


def parse_sa(data):
    result = []
    while data:
        need(len(data) >= 8, "short IKEv2 proposal")
        nxt, _, length, number, protocol, spi_len, count = struct.unpack("!BBHBBBB", data[:8])
        need(8+spi_len <= length <= len(data) and count > 0, "invalid IKEv2 proposal length")
        spi, rest = data[8:8+spi_len], data[8+spi_len:length]
        transforms = []
        for i in range(count):
            need(len(rest) >= 8, "short IKEv2 transform")
            tn, _, tl, kind, _, tid = struct.unpack("!BBHBBH", rest[:8])
            need(8 <= tl <= len(rest), "bad IKEv2 transform length")
            transforms.append((kind, tid, parse_attributes(rest[8:tl])))
            need(tn == (3 if i+1 < count else 0), "bad IKEv2 transform chain")
            rest = rest[tl:]
        need(not rest, "IKEv2 transform count mismatch")
        result.append((number, protocol, spi, transforms))
        data = data[length:]
        need(nxt == (2 if data else 0), "bad IKEv2 proposal chain")
    need(result, "empty IKEv2 SA")
    return result


def selector(ip, port):
    address = ipaddress.IPv4Address(ip).packed
    return b"\x01\0\0\0"+struct.pack("!BBHHH", 7, 17, 16, port, port)+address+address


def check_selector(body, ip, port):
    need(body == selector(ip, port), "IKEv2 traffic selectors changed")


class IKEv2(Exchanges):
    def __init__(self, link, config, install, fail, *, ci=None, cr=None, initiator_role=True):
        super().__init__(link, config)
        self.ci, self.cr = ci or secrets.token_bytes(8), cr or b"\0"*8
        self.initiator_role = initiator_role
        self.install, self.fail = install, fail
        self.natt = self.established = False
        self.created = time.monotonic()
        self.ike_lifetime, self.child_lifetime = config.ike_lifetime, config.child_lifetime
        self.child_in = self.child_out = None
        self.children = {}
        self.closing = False
        self.busy = None
        self.child_rekeys = {}
        self.ike_candidates = []
        self.my_mid = self.peer_mid = 0
        self.cache = {}
        self.tasks = set()
        self.exchange_lock = asyncio.Lock()
        self.successor = None
        self.local_ip = None
        self.dns_servers = ()
        self.netmask = None
        self.ts_local = (Selector(),)
        self.ts_remote = (Selector(),)
        self.link.sessions[self.ci] = self

    def _task(self, coro):
        task = asyncio.create_task(coro)
        self.tasks.add(task)
        def done(t):
            self.tasks.discard(t)
            if not t.cancelled() and t.exception():
                self.fail(t.exception())
        task.add_done_callback(done)

    def receive(self, packet, raw, natt):
        if self.closed or (self.established and time.monotonic() >= self.created+self.ike_lifetime):
            return
        if packet.version != 0x20 or packet.initiator != self.ci or packet.flags & ~0x38:
            return
        if self.cr != b"\0"*8 and packet.responder != self.cr:
            return
        if bool(packet.flags & 8) == self.initiator_role:
            return
        if packet.flags & 0x20:
            if packet.first == 46 and hasattr(self, "auth_in"):
                try:
                    self._open(packet)
                except (ProtocolError, AuthenticationError):
                    return
            self.deliver(packet, raw)
        elif self.established and natt and packet.first == 46:
            if packet.message_id in self.cache:
                response = self.cache[packet.message_id]
                if response is not None:
                    self.link.send(response, natt=True)
            elif packet.message_id == self.peer_mid:
                # Authentication is checked before accepting the peer's counter.
                try:
                    ps = self._open(packet)
                except (ProtocolError, AuthenticationError):
                    return
                self.cache[packet.message_id] = None
                self.peer_mid += 1
                self._task(self._incoming(packet, ps))

    def _transforms(self, *, child=False, rekey=False):
        ts = [(1, 12, [(14, b)]) for b in self.config.aes_bits]
        if not child:
            ts.append((2, 2, []))
        ts.append((3, 2, []))
        if child:
            if rekey and self.config.pfs_group:
                ts.append((4, self.config.pfs_group, []))
            ts.append((5, 0, []))
        else:
            ts += [(4, g, []) for g in self.config.dh_groups]
        return ts

    def _select(self, body, protocol, *, offered=False, child_dh=False):
        ps = parse_sa(body)
        need(offered or len(ps) == 1, "multiple selected IKEv2 proposals")
        for _, proto, spi, ts in ps:
            if proto != protocol or len(spi) != (4 if protocol == 3 else 0):
                # IKE rekey uses eight-byte SPI, validated by caller after stripping.
                continue
            values = {}
            for kind, tid, attrs in ts:
                values.setdefault(kind, []).append((tid, attrs))
            if not offered and any(len(v) != 1 for v in values.values()):
                raise NegotiationError("IKEv2 response selected multiple algorithms")
            encr = next((v for v in values.get(1, []) if v[0] == 12 and dict(v[1]).get(14, 128) in self.config.aes_bits), None)
            integ = next((v for v in values.get(3, []) if v[0] == 2 and not v[1]), None)
            if not encr or not integ or any(k not in (1,2,3,4,5) for k in values):
                continue
            chosen = [(1,12,encr[1]), (3,2,[])]
            bits, group = dict(encr[1]).get(14,128), None
            if protocol == 1:
                if not any(tid == 2 and not a for tid,a in values.get(2, [])):
                    continue
                group = next((tid for tid,a in values.get(4, []) if tid in self.config.dh_groups and not a), None)
                if group is None or 5 in values:
                    continue
                chosen += [(2,2,[]), (4,group,[])]
            else:
                if 2 in values or not any(tid == 0 and not a for tid,a in values.get(5, [(0,[])])):
                    continue
                if child_dh and self.config.pfs_group:
                    if not any(tid == self.config.pfs_group and not a for tid,a in values.get(4, [])):
                        continue
                    group = self.config.pfs_group
                    chosen.append((4,group,[]))
                elif 4 in values:
                    continue
                chosen.append((5,0,[]))
            return spi, bits, group, chosen
        raise NegotiationError("IKEv2 peer selected no acceptable proposal")

    def _select_rekey(self, body, *, offered=False):
        ps = parse_sa(body)
        need(len(ps) == 1 and ps[0][1] == 1 and len(ps[0][2]) == 8, "invalid IKE rekey proposal")
        spi = ps[0][2]
        _, bits, group, ts = self._select(proposal(1,b"",ps[0][3]),1,offered=offered)
        return spi, bits, group, ts

    def _keys(self, shared, ni, nr, bits, old_sk_d=None):
        seed = prf(old_sk_d, shared+ni+nr) if old_sk_d else prf(ni+nr, shared)
        length = bits//8
        data = expand(seed, ni+nr+self.ci+self.cr, 100+2*length, counters=True)
        def take(n):
            nonlocal data
            result, data = data[:n], data[n:]
            return result
        self.sk_d = take(20)
        ai, ar, ei, er, pi, pr = take(20), take(20), take(length), take(length), take(20), take(20)
        self.sk_pi, self.sk_pr = pi, pr
        self.key_out, self.auth_out = (ei, ai) if self.initiator_role else (er, ar)
        self.key_in, self.auth_in = (er, ar) if self.initiator_role else (ei, ai)
        self.bits = bits

    def _packet(self, exchange, mid, ps, *, encrypted=True, response=False):
        flags = (8 if self.initiator_role else 0) | (0x20 if response else 0)
        first = ps[0].kind if ps else 0
        body = encode_payloads(ps)
        if encrypted:
            pad = (-len(body)-1) % 16
            iv = secrets.token_bytes(16)
            ciphertext = encrypt(self.key_out, iv, body+secrets.token_bytes(pad)+bytes([pad]))
            body = bytes([first,0])+u16(4+16+len(ciphertext)+12)+iv+ciphertext+b"\0"*12
            first = 46
        raw = IKEPacket(self.ci,self.cr,first,0x20,exchange,flags,mid,body).encode()
        if encrypted:
            raw = raw[:-12]+prf(self.auth_out,raw[:-12])[:12]
        return raw

    def _open(self, packet):
        need(packet.first == 46 and len(packet.body) >= 48, "IKEv2 requires SK encryption")
        raw = packet.encode()
        need(integer(packet.body[2:4]) == len(packet.body), "invalid SK length")
        if not hmac.compare_digest(prf(self.auth_in,raw[:-12])[:12],raw[-12:]):
            raise AuthenticationError("IKEv2 integrity check failed")
        plain = decrypt(self.key_in,packet.body[4:20],packet.body[20:-12])
        pad = plain[-1]
        need(pad < len(plain), "invalid IKEv2 padding")
        ps = decode_payloads(packet.body[0],plain[:-pad-1])
        for p in ps:
            need(p.kind in (33,34,35,36,37,38,39,40,41,42,43,44,45,47,48) or not p.raw[1]&0x80,
                 "unrecognized critical IKEv2 payload")
        return ps

    @staticmethod
    def _check_notifications(ps):
        for p in ps:
            if p.kind == 41:
                code, _, _, _ = parse_notify(p.body)
                if code == 24:
                    raise AuthenticationError("IKEv2 peer returned AUTHENTICATION_FAILED (24)")
                if code == 43:
                    raise TemporaryFailure("IKEv2 peer is temporarily busy (43)")
                if code < 16384:
                    raise NegotiationError(f"IKEv2 peer notification {code}")

    def _auth(self, signed, nonce, identity, sk_p):
        return prf(prf(self.config.psk.encode(),b"Key Pad for IKEv2"),signed+nonce+prf(sk_p,identity))

    async def connect(self):
        group, cookie = self.config.dh_groups[0], None
        ni = secrets.token_bytes(32)
        dh = DH(group)
        for _ in range(4):
            nd_src = secrets.token_bytes(20) if self.config.force_natt else hashlib.sha1(
                self.ci+b"\0"*8+ipaddress.IPv4Address(self.link.local_ip).packed+u16(self.link.local_port)).digest()
            nd_dst = hashlib.sha1(self.ci+b"\0"*8+ipaddress.IPv4Address(self.link.peer).packed+u16(self.config.server_ike_port)).digest()
            ps = [Payload(33,proposal(1,b"",self._transforms())),Payload(34,u16(group)+b"\0\0"+dh.public),
                  Payload(40,ni),notify(16388,nd_src),notify(16389,nd_dst)]
            if cookie:
                ps.insert(0,notify(16390,cookie))
            request = self._packet(34,0,ps,encrypted=False)
            response, raw_response = await self.request(request,34,0,natt=False)
            need(response.flags & 0x20 and not response.flags & 8, "invalid SA_INIT flags")
            ps = decode_payloads(response.first,response.body)
            notes = [parse_notify(p.body) for p in ps if p.kind == 41]
            challenge = next((data for code,_,_,data in notes if code == 16390),None)
            if challenge is not None:
                need(1 <= len(challenge) <= 64, "invalid IKEv2 cookie")
                cookie = challenge
                continue
            suggested = next((integer(data) for code,_,_,data in notes if code == 17 and len(data) == 2),None)
            if suggested is not None:
                need(suggested in self.config.dh_groups, "unoffered IKEv2 DH group requested")
                group = suggested
                dh = DH(group)
                continue
            self._check_notifications(ps)
            self.cr = response.responder
            need(self.cr != b"\0"*8, "zero IKEv2 responder SPI")
            _, bits, chosen_group, _ = self._select(one(ps,33),1)
            ke, nr = one(ps,34), one(ps,40)
            need(chosen_group == group and len(ke) >= 4 and integer(ke[:2]) == group and 16 <= len(nr) <= 256,
                 "invalid SA_INIT KE/nonce")
            need(any(code in (16388,16389) for code,_,_,_ in notes), "peer did not negotiate NAT-T")
            self._keys(dh.shared(ke[4:]),ni,nr,bits)
            break
        else:
            raise NegotiationError("IKEv2 SA_INIT retry limit")
        self.group, self.natt = group, True
        idi = (b"\x02\0\0\0"+self.config.local_id.encode() if self.config.local_id else
               b"\x01\0\0\0"+ipaddress.IPv4Address(self.link.local_ip).packed)
        spi = secrets.token_bytes(4)
        ps = [Payload(35,idi), Payload(39,b"\x02\0\0\0"+self._auth(request,nr,idi,self.sk_pi)),
              Payload(33,proposal(3,spi,self._transforms(child=True)))]
        if self.config.remote_id and self.config.request_remote_id:
            try:
                requested_id=b"\x01\0\0\0"+ipaddress.IPv4Address(self.config.remote_id).packed
            except ipaddress.AddressValueError:
                requested_id=b"\x02\0\0\0"+self.config.remote_id.encode()
            ps.insert(1,Payload(36,requested_id))
        if self.config.uses_l2tp:
            ps += [Payload(44,selector(self.link.local_ip,self.config.l2tp_port)),
                   Payload(45,selector(self.link.peer,self.config.l2tp_port)),notify(16391)]
        else:
            ps += [Payload(47,configuration_request()),Payload(44,encode_selectors(self.ts_local)),
                   Payload(45,encode_selectors(self.ts_remote))]
        response, _ = await self.request(self._packet(35,1,ps),35,1,natt=True)
        ps = self._open(response)
        self._check_notifications(ps)
        idr, auth = one(ps,36), one(ps,39)
        need(len(idr) >= 4 and len(auth) == 24 and auth[:4] == b"\x02\0\0\0", "peer did not use PSK authentication")
        if not hmac.compare_digest(auth[4:], self._auth(raw_response,ni,idr,self.sk_pr)):
            raise AuthenticationError("IKEv2 responder PSK authentication failed")
        self.peer_identity_type=idr[0]
        need(idr[1:4] == b"\0"*3, "invalid IKEv2 identity reserved bytes")
        if idr[0] in (2,3,11):
            self.peer_identity=idr[4:]
        else:
            need(idr[0] in (1,5) and len(idr[4:]) == (4 if idr[0] == 1 else 16),
                 "unsupported or malformed IKEv2 identity")
            self.peer_identity=str(ipaddress.ip_address(idr[4:])).encode()
        if self.config.remote_id:
            actual = self.peer_identity
            if actual != self.config.remote_id.encode():
                raise AuthenticationError(f"unexpected IKEv2 responder identity (type {idr[0]}, value {actual!r})")
        transport = any(p.kind == 41 and parse_notify(p.body)[0] == 16391 for p in ps)
        need(transport == self.config.uses_l2tp, "IKEv2 ESP mode does not match requested mode")
        if not self.config.uses_l2tp:
            self.local_ip,self.dns_servers,self.netmask=configuration_reply(one(ps,47))
        self._check_selectors(ps)
        peer_spi, bits, _, _ = self._select(one(ps,33),3)
        self._install(spi,peer_spi,bits,ni,nr)
        self.established = True
        self.my_mid, self.peer_mid = 2, 0
        self.created = time.monotonic()
        log.info("IKEv2 PSK authenticated; AES-%s-CBC/HMAC-SHA1, NAT-T %s", bits,
                 "transport" if self.config.uses_l2tp else "tunnel")

    def _check_selectors(self, ps, *, incoming=False):
        if not self.config.uses_l2tp:
            local=parse_selectors(one(ps,45 if incoming else 44))
            remote=parse_selectors(one(ps,44 if incoming else 45))
            check_narrowing(local,self.ts_local)
            check_narrowing(remote,self.ts_remote)
            need(any(s.first <= int(ipaddress.IPv4Address(self.local_ip)) <= s.last for s in local),
                 "assigned address excluded by selectors")
            self.ts_local,self.ts_remote=local,remote
            return
        check_selector(one(ps,44),self.link.peer if incoming else self.link.local_ip,self.config.l2tp_port)
        check_selector(one(ps,45),self.link.local_ip if incoming else self.link.peer,self.config.l2tp_port)

    def _install(self, spi_in, spi_out, bits, ni, nr, shared=b"", *, exchange_initiator=True):
        need(len(spi_in) == len(spi_out) == 4 and spi_in != b"\0"*4 and spi_out != b"\0"*4, "invalid ESP SPI")
        n = bits//8
        data = expand(self.sk_d,shared+ni+nr,2*(n+20),counters=True)
        ei, ai, er, ar = data[:n],data[n:n+20],data[n+20:2*n+20],data[2*n+20:]
        key_in, auth_in, key_out, auth_out = (er,ar,ei,ai) if exchange_initiator else (ei,ai,er,ar)
        self.child_in = ESP(spi_in,key_in,auth_in,self.child_lifetime,self.config.child_byte_limit)
        self.child_out = ESP(spi_out,key_out,auth_out,self.child_lifetime,self.config.child_byte_limit)
        self.children[spi_in] = self.child_out
        self.install(self.child_in,self.child_out)

    async def _exchange(self, exchange, ps):
        mid = self.my_mid
        self.my_mid += 1
        raw = self._packet(exchange,mid,ps)
        packet, _ = await self.request(raw,exchange,mid,natt=True)
        result = self._open(packet)
        self._check_notifications(result)
        self.link.last_received = time.monotonic()
        return result

    async def rekey_child(self):
        async with self._operation("child"):
            old_spi = self.child_in.spi
            spi, ni = secrets.token_bytes(4),secrets.token_bytes(32)
            dh = DH(self.config.pfs_group) if self.config.pfs_group else None
            ps = [notify(16393,protocol=3,spi=self.child_in.spi),
                  Payload(33,proposal(3,spi,self._transforms(child=True,rekey=True))),Payload(40,ni)]
            if self.config.uses_l2tp:
                ps += [Payload(44,selector(self.link.local_ip,self.config.l2tp_port)),
                       Payload(45,selector(self.link.peer,self.config.l2tp_port)),notify(16391)]
            else:
                ps += [Payload(44,encode_selectors(self.ts_local)),Payload(45,encode_selectors(self.ts_remote))]
            if dh:
                ps.append(Payload(34,u16(dh.group)+b"\0\0"+dh.public))
            result = await self._exchange(36,ps)
            peer_spi,bits,group,_ = self._select(one(result,33),3,child_dh=True)
            nr = one(result,40)
            need(16 <= len(nr) <= 256, "invalid rekey nonce")
            self._check_selectors(result)
            shared = b""
            if dh:
                ke = one(result,34)
                need(len(ke) >= 4 and integer(ke[:2]) == group, "wrong rekey KE group")
                shared = dh.shared(ke[4:])
            self._install(spi,peer_spi,bits,ni,nr,shared)
            self._record_child(old_spi, ni, nr, True)

    async def rekey_ike(self):
        async with self._operation("ike"):
            ci, ni = secrets.token_bytes(8),secrets.token_bytes(32)
            dh = DH(self.group)
            ps = [Payload(33,proposal(1,ci,self._transforms())),Payload(40,ni),
                  Payload(34,u16(dh.group)+b"\0\0"+dh.public)]
            result = await self._exchange(36,ps)
            cr,bits,group,_ = self._select_rekey(one(result,33))
            nr,ke = one(result,40),one(result,34)
            need(16 <= len(nr) <= 256 and group == dh.group and integer(ke[:2]) == group, "bad IKE rekey parameters")
            child = IKEv2(self.link,self.config,self.install,self.fail,ci=ci,cr=cr)
            child._keys(dh.shared(ke[4:]),ni,nr,bits,self.sk_d)
            child.group, child.natt, child.established = group,True,True
            child.child_in,child.child_out = self.child_in,self.child_out
            self._inherit(child)
            self._record_ike(child, ni, nr, True)
            return self.successor

    @asynccontextmanager
    async def _operation(self, kind):
        async with self.exchange_lock:
            self.busy = kind
            try:
                yield
            finally:
                self.busy = None

    def _record_child(self, old_spi, ni, nr, initiated):
        records = self.child_rekeys.setdefault(old_spi, [])
        record = dict(pair=(self.child_in, self.child_out), nonce=min(ni, nr), initiated=initiated)
        records.append(record)
        need(len(records) <= 2, "too many competing CHILD rekeys")
        winner = max(records, key=lambda r: r["nonce"])
        self.child_in, self.child_out = winner["pair"]
        if winner is not record:
            self.install(self.child_in, self.child_out)
        if len(records) == 2:
            for other in records:
                if other is not winner and other["initiated"]:
                    self._task(self._discard_child(other["pair"][0].spi))

    async def _discard_child(self, spi):
        await asyncio.sleep(self.config.rekey_overlap)
        if self.child_in.spi != spi:
            try:
                await self.delete_child(spi)
            except (NegotiationError, TimeoutError):
                log.debug("Redundant CHILD delete was not acknowledged")

    def _record_ike(self, child, ni, nr, initiated):
        self.ike_candidates.append((child, min(ni, nr), initiated))
        need(len(self.ike_candidates) <= 2, "too many competing IKE rekeys")
        winner = max(self.ike_candidates, key=lambda record: record[1])[0]
        self._inherit(winner)
        self.successor = winner
        if len(self.ike_candidates) == 2:
            for other, _, locally_created in self.ike_candidates:
                if other is not winner:
                    other.successor = winner
                    other.children = {}
                    if locally_created:
                        self._task(self._discard_ike(other))

    async def _discard_ike(self, session):
        await asyncio.sleep(self.config.rekey_overlap)
        try:
            await session.close()
        except (NegotiationError, TimeoutError):
            await session.close(notify=False)

    def _inherit(self, child):
        child.local_ip,child.dns_servers,child.netmask=self.local_ip,self.dns_servers,self.netmask
        child.ts_local,child.ts_remote=self.ts_local,self.ts_remote
        child.children=self.children.copy()
        child.peer_identity_type=self.peer_identity_type
        child.peer_identity=self.peer_identity

    async def _incoming(self, packet, ps):
        try:
            response_ps = []
            if packet.exchange == 37:
                for p in ps:
                    if p.kind != 42:
                        continue
                    need(len(p.body) >= 4, "short IKEv2 DELETE")
                    proto,size,count = p.body[0],p.body[1],integer(p.body[2:4])
                    need(len(p.body) == 4+size*count, "invalid DELETE count")
                    if proto == 1:
                        need(size == count == 0, "invalid IKE DELETE")
                        raw = self._packet(37,packet.message_id,[],response=True)
                        self._respond(packet,raw)
                        if not self.successor and not self.closing:
                            self.fail(TunnelClosed("Peer deleted IKEv2 SA"))
                        return
                    need(proto == 3 and size == 4, "unsupported IPsec DELETE")
                    spis = [p.body[i:i+4] for i in range(4,len(p.body),4)]
                    matches = [spi for spi, child in self.children.items() if child.spi in spis]
                    if matches:
                        response_ps.append(Payload(42,b"\x03\x04"+u16(len(matches))+b"".join(matches)))
                    for spi in matches:
                        self.children.pop(spi, None)
                        self.child_rekeys.pop(spi, None)
                    if self.child_out and self.child_out.spi in spis and not self.successor and not self.closing:
                        self.child_out.lifetime = 0
                        self._task(self.rekey_child())
            elif packet.exchange == 36:
                if self.closing:
                    self._respond(packet,self._packet(36,packet.message_id,[notify(43)],response=True))
                    return
                sa = one(ps,33)
                parsed = parse_sa(sa)
                if parsed[0][1] == 1:
                    if self.busy == "child" or (self.successor and
                            not (len(self.ike_candidates) == 1 and self.ike_candidates[0][2])):
                        self._respond(packet,self._packet(36,packet.message_id,[notify(43)],response=True))
                        return
                    ci,bits,group,ts = self._select_rekey(sa,offered=True)
                    ni,ke = one(ps,40),one(ps,34)
                    need(16 <= len(ni) <= 256 and integer(ke[:2]) == group, "bad IKE rekey KE/nonce")
                    nr,cr,dh = secrets.token_bytes(32),secrets.token_bytes(8),DH(group)
                    child = IKEv2(self.link,self.config,self.install,self.fail,ci=ci,cr=cr,initiator_role=False)
                    child._keys(dh.shared(ke[4:]),ni,nr,bits,self.sk_d)
                    child.group,child.natt,child.established = group,True,True
                    child.child_in,child.child_out = self.child_in,self.child_out
                    self._inherit(child)
                    self._record_ike(child, ni, nr, False)
                    response_ps = [Payload(33,proposal(1,cr,ts)),Payload(40,nr),
                                   Payload(34,u16(group)+b"\0\0"+dh.public)]
                else:
                    if self.busy == "ike" or self.successor:
                        self._respond(packet,self._packet(36,packet.message_id,[notify(43)],response=True))
                        return
                    rekeys = [parse_notify(p.body) for p in ps if p.kind == 41 and parse_notify(p.body)[0] == 16393]
                    need(len(rekeys) == 1 and rekeys[0][1] == 3, "missing CHILD rekey notification")
                    old_spi = next((spi for spi, child in self.children.items() if child.spi == rekeys[0][2]), None)
                    if old_spi is None:
                        self._respond(packet,self._packet(36,packet.message_id,
                            [notify(44, protocol=3, spi=rekeys[0][2])],response=True))
                        return
                    self._check_selectors(ps,incoming=True)
                    peer_spi,bits,group,ts = self._select(sa,3,offered=True,child_dh=True)
                    ni = one(ps,40)
                    need(16 <= len(ni) <= 256, "bad child rekey nonce")
                    nr,spi = secrets.token_bytes(32),secrets.token_bytes(4)
                    shared,dh = b"",None
                    if group:
                        dh = DH(group)
                        ke = one(ps,34)
                        need(integer(ke[:2]) == group, "wrong child DH group")
                        shared = dh.shared(ke[4:])
                    response_ps = [Payload(33,proposal(3,spi,ts)),Payload(40,nr),
                                   Payload(44,one(ps,44)),Payload(45,one(ps,45))]
                    if self.config.uses_l2tp:
                        response_ps.append(notify(16391))
                    if dh:
                        response_ps.append(Payload(34,u16(group)+b"\0\0"+dh.public))
                    self._install(spi,peer_spi,bits,ni,nr,shared,exchange_initiator=False)
                    self._record_child(old_spi, ni, nr, False)
            else:
                response_ps = [notify(7)]
            self._respond(packet,self._packet(packet.exchange,packet.message_id,response_ps,response=True))
        except (ProtocolError,AuthenticationError,NegotiationError):
            self._respond(packet,self._packet(packet.exchange,packet.message_id,[notify(14)],response=True))

    def _respond(self, packet, raw):
        self.cache[packet.message_id] = raw
        if len(self.cache) > 64:
            self.cache.pop(next(iter(self.cache)))
        self.link.send(raw,natt=True)

    async def dpd(self):
        async with self.exchange_lock:
            if not self.closed and not self.closing and not self.successor:
                await self._exchange(37,[])

    async def delete_child(self, spi):
        if self.closed or not self.established:
            return
        async with self.exchange_lock:
            if not self.closed and not self.closing:
                await self._exchange(37,[Payload(42,b"\x03\x04\0\x01"+spi)])
                self.children.pop(spi, None)
                self.child_rekeys.pop(spi, None)

    async def close(self, *, notify=True):
        if self.closed:
            return
        self.closing = True
        try:
            if notify and self.established:
                async with asyncio.timeout(self.config.shutdown_timeout):
                    async with self.exchange_lock:
                        await self._exchange(37,[Payload(42,b"\x01\0\0\0")])
        finally:
            self.closed = True
            self.link.sessions.pop(self.ci,None)
            tasks = [t for t in self.tasks if t is not asyncio.current_task()]
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks,return_exceptions=True)
