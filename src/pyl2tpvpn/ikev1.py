"""IKEv1 Main Mode PSK, Quick Mode, NAT-T, RFC 3706 DPD.

Only authenticated packets can create SAs, acknowledge DPD, or delete SAs.
The CBC chain is committed after validating HASH; retransmissions reuse bytes.
"""
import asyncio
import hashlib
import hmac
import ipaddress
import logging
import secrets
import struct
import time
from .crypto import DH, ESP, prf, expand, encrypt, decrypt
from .errors import AuthenticationError, NegotiationError, ProtocolError, TunnelClosed
from .transport import Exchanges
from .wire import (IKEPacket, Payload, decode_payloads, encode_payloads, one,
                   parse_sa_v1, proposal_v1, integer, u16, u32, need)

log = logging.getLogger(__name__)
NATT_VENDOR = bytes.fromhex("4a131c81070358455c5728f20e95452f")
DPD_VENDOR = bytes.fromhex("afcad71368a1f1c96b8696fc77570100")


def lifetime(attrs, type_id, value_id, default):
    result, kind = float(default), None
    for key, value in attrs:
        if key == type_id:
            kind = value if isinstance(value, int) else integer(value)
        elif key == value_id and kind == 1:
            n = value if isinstance(value, int) else integer(value)
            need(n > 0, "invalid SA lifetime")
            result = min(result, n)
    return result


class IKEv1(Exchanges):
    def __init__(self, link, config, install, fail, *, start_natt=False):
        super().__init__(link, config)
        self.ci, self.cr = secrets.token_bytes(8), b"\0"*8
        self.install, self.fail = install, fail
        self.natt, self.established = False, False
        self.start_natt = start_natt
        self.retiring = False
        self.created = time.monotonic()
        self.ike_lifetime = config.ike_lifetime
        self.child_lifetime = config.child_lifetime
        self.child_in, self.child_out = None, None
        self.children = {}
        self.cache, self.inbound_quick = {}, {}
        self.dpd_waiters = {}
        self.tasks = set()
        self.exchange_lock = asyncio.Lock()
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
        if packet.version != 0x10 or packet.initiator != self.ci:
            return
        if self.cr != b"\0"*8 and packet.responder != self.cr:
            return
        if self.established and (not natt or not packet.flags & 1):
            return
        if packet.flags & ~1:
            return
        if self.deliver(packet, raw):
            return
        if self.established and packet.exchange in (5, 32):
            fingerprint = hashlib.sha256(raw).digest()
            if fingerprint in self.cache:
                response = self.cache[fingerprint]
                if response:
                    self.link.send(response, natt=self.natt)
                return
            # Reserve before scheduling so a burst of duplicates cannot create tasks.
            if len(self.cache) >= 128:
                self.cache.pop(next(iter(self.cache)))
            self.cache[fingerprint] = None
            self._task(self._incoming(packet, fingerprint))

    def _packet(self, exchange, mid, payloads, iv=None):
        body = encode_payloads(payloads)
        flags = 0
        if iv is not None:
            flags = 1
            body = encrypt(self.key, iv, body + secrets.token_bytes((-len(body)) % 16))
        raw = IKEPacket(self.ci, self.cr, payloads[0].kind if payloads else 0, 0x10,
                        exchange, flags, mid, body).encode()
        return raw

    @staticmethod
    def _notifications(payloads):
        for p in payloads:
            if p.kind == 11:
                need(len(p.body) >= 8, "short IKE notification")
                doi, proto, size, code = struct.unpack("!IBBH", p.body[:8])
                if code < 16384:
                    raise NegotiationError(f"IKEv1 peer notification {code}")

    def _open(self, packet, iv):
        need(packet.flags == 1, "expected encrypted IKE")
        return decode_payloads(packet.first, decrypt(self.key, iv, packet.body), padding=True)

    def _base_iv(self, mid):
        return hashlib.sha1(self.phase1_iv + u32(mid)).digest()[:16]

    def _hashed(self, exchange, mid, payloads, prefix=b"", iv=None):
        digest = prf(self.skeyid_a, u32(mid) + prefix + encode_payloads(payloads))
        return self._packet(exchange, mid, [Payload(8, digest)]+payloads, iv or self._base_iv(mid))

    def _verify(self, packet, payloads, prefix=b""):
        need(payloads and payloads[0].kind == 8, "missing leading HASH")
        expected = prf(self.skeyid_a, u32(packet.message_id) + prefix + b"".join(p.raw for p in payloads[1:]))
        if not hmac.compare_digest(expected, payloads[0].body):
            raise AuthenticationError("IKEv1 exchange HASH verification failed")
        self._notifications(payloads)

    async def connect(self):
        transforms = []
        for group in self.config.dh_groups:
            for bits in self.config.aes_bits:
                transforms.append((1, [(1, 7), (2, 2), (3, 1), (4, group), (14, bits),
                                       (11, 1), (12, u32(int(self.config.ike_lifetime)))]))
        self.sa_i = u32(1)+u32(1)+proposal_v1(1, b"", transforms)
        ps = [Payload(1, self.sa_i), Payload(13, NATT_VENDOR), Payload(13, DPD_VENDOR)]
        request = self._packet(2, 0, ps)
        response, _ = await self.request(request, 2, 0, natt=self.start_natt,
                                          accept=lambda p: not p.flags and p.first in (1, 11))
        need(response.responder != b"\0"*8, "zero responder cookie")
        self.cr = response.responder
        ps = decode_payloads(response.first, response.body)
        self._notifications(ps)
        proposals = parse_sa_v1(one(ps, 1))
        need(len(proposals) == 1, "multiple selected IKE proposals")
        _, proto, spi, ts = proposals[0]
        need(proto == 1 and not spi and len(ts) == 1, "bad selected IKE proposal")
        tid, attrs = ts[0]
        selected = dict(attrs)
        need(tid == 1 and selected.get(1) == 7 and selected.get(2) == 2 and selected.get(3) == 1,
             "peer selected an unoffered IKE algorithm")
        self.group, self.bits = selected.get(4), selected.get(14, 128)
        need(self.group in self.config.dh_groups and self.bits in self.config.aes_bits,
             "unoffered DH group/AES key size")
        self.ike_lifetime = lifetime(attrs, 11, 12, self.config.ike_lifetime)
        self.peer_dpd = any(p.kind == 13 and p.body == DPD_VENDOR for p in ps)
        self.peer_natt = any(p.kind == 13 and p.body == NATT_VENDOR for p in ps)
        dh = DH(self.group)
        ni = secrets.token_bytes(32)
        peer_hash = hashlib.sha1(self.ci+self.cr+ipaddress.ip_address(self.link.peer).packed+
                                  u16(self.config.server_natt_port if self.start_natt else self.config.server_ike_port)).digest()
        local_hash = hashlib.sha1(self.ci+self.cr+ipaddress.ip_address(self.link.local_ip).packed+
                                   u16(self.link.natt_local_port if self.start_natt else self.link.local_port)).digest()
        if self.config.force_natt:
            local_hash = secrets.token_bytes(20)  # RFC 3947: deliberately indicate NAT for UDP-only operation.
        ps = [Payload(4, dh.public), Payload(10, ni)]
        if self.peer_natt:
            ps += [Payload(20, peer_hash), Payload(20, local_hash)]
        request = self._packet(2, 0, ps)
        response, _ = await self.request(request, 2, 0, natt=self.start_natt,
                                          accept=lambda p: not p.flags and p.first in (4, 11))
        ps = decode_payloads(response.first, response.body)
        self._notifications(ps)
        peer_public, nr = one(ps, 4), one(ps, 10)
        need(8 <= len(nr) <= 256, "invalid IKE nonce size")
        shared = dh.shared(peer_public)
        if not self.peer_natt or not any(p.kind == 20 for p in ps):
            raise NegotiationError("Peer did not negotiate RFC 3947 NAT-T; raw ESP is not enabled")
        self.natt = True
        self.skeyid = prf(self.config.psk.encode(), ni+nr)
        self.skeyid_d = prf(self.skeyid, shared+self.ci+self.cr+b"\0")
        self.skeyid_a = prf(self.skeyid, self.skeyid_d+shared+self.ci+self.cr+b"\1")
        skeyid_e = prf(self.skeyid, self.skeyid_a+shared+self.ci+self.cr+b"\2")
        key_len = self.bits//8
        if key_len <= len(skeyid_e):
            self.key = skeyid_e[:key_len]
        else:
            last = prf(skeyid_e, b"\0")
            material = last
            while len(material) < key_len:
                last = prf(skeyid_e, last)
                material += last
            self.key = material[:key_len]
        if self.config.local_id:
            idi = b"\x02\0\0\0"+self.config.local_id.encode()
        else:
            idi = b"\x01\0\0\0"+ipaddress.ip_address(self.link.local_ip).packed
        hash_i = prf(self.skeyid, dh.public+peer_public+self.ci+self.cr+self.sa_i+idi)
        iv = hashlib.sha1(dh.public+peer_public).digest()[:16]
        request = self._packet(2, 0, [Payload(5, idi), Payload(8, hash_i)], iv)
        response, _ = await self.request(request, 2, 0, natt=True,
                                          accept=lambda p: p.flags == 1)
        ps = self._open(response, request[-16:])
        idr, received_hash = one(ps, 5), one(ps, 8)
        expected = prf(self.skeyid, peer_public+dh.public+self.cr+self.ci+self.sa_i+idr)
        if not hmac.compare_digest(expected, received_hash):
            raise AuthenticationError("IKEv1 peer PSK authentication failed")
        need(len(idr) >= 4, "short IKE identity")
        if self.config.remote_id is not None:
            expected_id = self.config.remote_id.encode()
            actual_id = idr[4:] if idr[0] in (2, 3, 11) else str(ipaddress.ip_address(idr[4:])).encode()
            if actual_id != expected_id:
                raise AuthenticationError("unexpected IKE peer identity")
        self.phase1_iv = response.body[-16:]
        self.established = True
        self.created = time.monotonic()
        log.info("IKEv1 authenticated; AES-%s-CBC/HMAC-SHA1, DH%s, NAT-T", self.bits, self.group)
        await self.rekey_child()

    def _esp_attrs(self, bits):
        attrs = [(1, 1), (2, u32(int(self.config.child_lifetime))), (4, 4), (5, 2), (6, bits)]
        if self.config.pfs_group:
            attrs.append((3, self.config.pfs_group))
        return attrs

    def _select_esp(self, body, *, selected=True):
        proposals = parse_sa_v1(body)
        need(len(proposals) == 1, "only one ESP proposal is supported")
        num, proto, spi, ts = proposals[0]
        need(proto == 3 and len(spi) == 4 and spi != b"\0"*4, "invalid ESP proposal/SPI")
        if selected:
            need(len(ts) == 1, "multiple selected ESP transforms")
        for tid, attrs in ts:
            a = dict(attrs)
            if (tid == 12 and a.get(4) == 4 and a.get(5) == 2 and
                    a.get(6, 128) in self.config.aes_bits and a.get(3) == self.config.pfs_group and
                    a.get(11, 0) == 0):
                duration = lifetime(attrs, 1, 2, self.config.child_lifetime)
                return num, spi, tid, attrs, a.get(6, 128), duration
        raise NegotiationError("No acceptable AES-CBC/HMAC-SHA1 NAT-T transport ESP proposal")

    def _selectors(self):
        return [Payload(5, b"\x01\x11"+u16(self.config.l2tp_port)+ipaddress.ip_address(ip).packed)
                for ip in (self.link.local_ip, self.link.peer)]

    def _validate_selectors(self, ps, expected=None):
        ids = [p.body for p in ps if p.kind == 5]
        need(len(ids) == 2, "Quick Mode requires UDP L2TP selectors")
        for value in ids:
            need(len(value) == 8 and value[0] == 1 and value[1] in (0, 17) and
                 integer(value[2:4]) in (0, self.config.l2tp_port), "unacceptable IPsec traffic selector")
        if expected:
            # Yamaha gateways can clear protocol/port to wildcard in the reply.
            # Addresses must match and the data path independently admits only
            # UDP to/from the negotiated L2TP port.
            need([v[4:] for v in ids] == [p.body[4:] for p in expected], "Quick Mode changed selector addresses")

    def _install(self, spi_in, spi_out, bits, ni, nr, duration, shared=b""):
        length = bits//8+20
        def derive(spi):
            material = expand(self.skeyid_d, shared+b"\x03"+spi+ni+nr, length)
            return ESP(spi, material[:bits//8], material[bits//8:], duration, self.config.child_byte_limit)
        self.child_in, self.child_out = derive(spi_in), derive(spi_out)
        self.children[spi_in] = self.child_out
        self.child_lifetime = duration
        if not self.retiring:
            self.install(self.child_in, self.child_out)
        log.info("ESP SA installed (lifetime %.0fs)", duration)
        log.debug("ESP in=%s out=%s IKE=%s retiring=%s", spi_in.hex(), spi_out.hex(), self.ci.hex(), self.retiring)

    async def rekey_child(self):
        async with self.exchange_lock:
            mid = secrets.randbelow(0xffffffff)+1
            spi = secrets.token_bytes(4)
            ni = secrets.token_bytes(32)
            sa = u32(1)+u32(1)+proposal_v1(3, spi, [(12, self._esp_attrs(b)) for b in self.config.aes_bits])
            dh = DH(self.config.pfs_group) if self.config.pfs_group else None
            selectors = self._selectors()
            ps = [Payload(1, sa), Payload(10, ni)]
            if dh:
                ps.append(Payload(4, dh.public))
            ps += selectors
            request = self._hashed(32, mid, ps)
            response, _ = await self.request(request, 32, mid, natt=True)
            ps = self._open(response, request[-16:])
            self._verify(response, ps, ni)
            _, peer_spi, _, _, bits, duration = self._select_esp(one(ps, 1))
            nr = one(ps, 10)
            need(8 <= len(nr) <= 256, "bad Quick Mode nonce")
            self._validate_selectors(ps, selectors)
            shared = dh.shared(one(ps, 4)) if dh else b""
            digest = prf(self.skeyid_a, b"\0"+u32(mid)+ni+nr)
            final = self._packet(32, mid, [Payload(8, digest)], response.body[-16:])
            self.link.send(final, natt=True)
            self.cache[hashlib.sha256(response.encode()).digest()] = final
            if len(self.cache) > 128:
                self.cache.pop(next(iter(self.cache)))
            self._install(spi, peer_spi, bits, ni, nr, duration, shared)

    async def _incoming(self, packet, fingerprint):
        try:
            if packet.exchange == 5:
                ps = self._open(packet, self._base_iv(packet.message_id))
                self._verify(packet, ps)
                self.link.last_received = time.monotonic()
                responses = []
                for p in ps[1:]:
                    if p.kind == 11:
                        need(len(p.body) >= 8, "short notification")
                        doi, proto, size, code = struct.unpack("!IBBH", p.body[:8])
                        need(len(p.body) >= 8+size, "bad notify SPI")
                        spi, data = p.body[8:8+size], p.body[8+size:]
                        if code in (36136, 36137):
                            need(doi == 1 and proto == 1 and size == 16 and spi == self.ci+self.cr and len(data) == 4,
                                 "invalid DPD notification")
                            if code == 36136:
                                responses.append(Payload(11, struct.pack("!IBBH", 1, 1, 16, 36137)+spi+data))
                            else:
                                waiter = self.dpd_waiters.get(data)
                                if waiter and not waiter.done():
                                    waiter.set_result(None)
                    elif p.kind == 12:
                        need(len(p.body) >= 8, "short DELETE")
                        doi, proto, size, count = struct.unpack("!IBBH", p.body[:8])
                        need(doi == 1 and len(p.body) == 8+size*count, "invalid DELETE")
                        spis = [p.body[i:i+size] for i in range(8, len(p.body), size)] if size else []
                        if proto == 1 and size == 16 and self.ci+self.cr in spis:
                            if self.retiring:
                                await self.close(notify=False)
                                return
                            raise TunnelClosed("Peer deleted IKE SA")
                        if proto == 3 and size == 4 and self.child_out and self.child_out.spi in spis and not self.retiring:
                            # Keep old SA until authenticated replacement is installed, but cease using deleted keys.
                            self.child_out.lifetime = 0
                            self._task(self.rekey_child())
                if responses:
                    mid = secrets.randbelow(0xffffffff)+1
                    response = self._hashed(5, mid, responses)
                    self.cache[fingerprint] = response
                    self.link.send(response, natt=True)
            else:
                await self._incoming_quick(packet, fingerprint)
        except (AuthenticationError, ProtocolError) as e:
            log.debug("Rejected unsolicited IKEv1 packet: %s", e)

    async def _incoming_quick(self, packet, fingerprint):
        mid = packet.message_id
        state = self.inbound_quick.get(mid)
        if state:
            ps = self._open(packet, state["iv"])
            need(len(ps) == 1 and ps[0].kind == 8, "expected Quick Mode HASH(3)")
            expected = prf(self.skeyid_a, b"\0"+u32(mid)+state["ni"]+state["nr"])
            if not hmac.compare_digest(expected, ps[0].body):
                raise AuthenticationError("Quick Mode HASH(3) mismatch")
            self._install(state["spi"], state["peer_spi"], state["bits"], state["ni"], state["nr"], state["duration"], state["shared"])
            del self.inbound_quick[mid]
            return
        ps = self._open(packet, self._base_iv(mid))
        self._verify(packet, ps)
        num, peer_spi, tid, attrs, bits, duration = self._select_esp(one(ps, 1), selected=False)
        self._validate_selectors(ps)
        ni = one(ps, 10)
        need(8 <= len(ni) <= 256, "invalid Quick Mode nonce")
        nr, spi = secrets.token_bytes(32), secrets.token_bytes(4)
        dh = DH(self.config.pfs_group) if self.config.pfs_group else None
        shared = dh.shared(one(ps, 4)) if dh else b""
        reply = [Payload(1, u32(1)+u32(1)+proposal_v1(3, spi, [(tid, attrs)], num)), Payload(10, nr)]
        if dh:
            reply.append(Payload(4, dh.public))
        reply += [Payload(5, p.body) for p in ps if p.kind == 5]
        raw = self._hashed(32, mid, reply, ni, packet.body[-16:])
        need(len(self.inbound_quick) < 8, "too many pending Quick Mode exchanges")
        state = dict(iv=raw[-16:], spi=spi, peer_spi=peer_spi, bits=bits, ni=ni, nr=nr,
                     duration=duration, shared=shared)
        self.inbound_quick[mid] = state
        self.cache[fingerprint] = raw
        self.link.send(raw, natt=True)
        async def retransmit():
            for attempt in range(self.config.retransmit_attempts):
                await asyncio.sleep(min(8, self.config.retransmit_initial*2**attempt))
                if self.inbound_quick.get(mid) is not state:
                    return
                self.link.send(raw, natt=True)
            self.inbound_quick.pop(mid, None)
        self._task(retransmit())

    async def dpd(self):
        if self.closed or self.retiring or not self.peer_dpd:
            return  # PPP echo and L2TP HELLO provide liveness if RFC 3706 was not negotiated.
        if time.monotonic() >= self.created+self.ike_lifetime:
            raise TunnelClosed("IKEv1 SA hard lifetime expired")
        seq = secrets.token_bytes(4)
        waiter = asyncio.get_running_loop().create_future()
        self.dpd_waiters[seq] = waiter
        mid = secrets.randbelow(0xffffffff)+1
        payload = Payload(11, struct.pack("!IBBH", 1, 1, 16, 36136)+self.ci+self.cr+seq)
        raw = self._hashed(5, mid, [payload])
        try:
            for i in range(3):
                self.link.send(raw, natt=True)
                try:
                    await asyncio.wait_for(asyncio.shield(waiter), min(8, self.config.retransmit_initial*2**i))
                    return
                except TimeoutError:
                    pass
            raise TunnelClosed("IKE DPD response timed out")
        finally:
            self.dpd_waiters.pop(seq, None)
            waiter.cancel()

    async def delete_child(self, spi):
        if self.closed or not self.established or time.monotonic() >= self.created+self.ike_lifetime:
            return
        mid = secrets.randbelow(0xffffffff)+1
        body = struct.pack("!IBBH",1,3,4,1)+spi
        self.link.send(self._hashed(5,mid,[Payload(12,body)]),natt=True)
        self.children.pop(spi, None)

    async def close(self, *, notify=True):
        if self.closed:
            return
        if notify and self.established and time.monotonic() < self.created+self.ike_lifetime:
            for spi in tuple(self.children):
                await self.delete_child(spi)
            mid = secrets.randbelow(0xffffffff)+1
            delete = struct.pack("!IBBH", 1, 1, 16, 1)+self.ci+self.cr
            self.link.send(self._hashed(5, mid, [Payload(12, delete)]), natt=True)
        self.closed = True
        self.link.sessions.pop(self.ci, None)
        tasks = [t for t in self.tasks if t is not asyncio.current_task()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for waiter in self.dpd_waiters.values():
            waiter.cancel()
