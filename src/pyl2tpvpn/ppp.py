"""PPP LCP/IPCP, PAP, CHAP-MD5 and mutually authenticated MSCHAP-v2."""
import asyncio
import hashlib
import hmac
import ipaddress
import logging
import secrets
import struct
from .crypto import mschapv2_response, mschapv2_authenticator
from .errors import AuthenticationError, NegotiationError, TunnelClosed, VPNTimeout
from .wire import need, u16, integer

log = logging.getLogger(__name__)
LCP, IPCP, PAP, CHAP, IP = 0xc021, 0x8021, 0xc023, 0xc223, 0x0021
AUTH_OPTIONS = {"mschapv2": b"\x03\x05\xc2\x23\x81", "chap-md5": b"\x03\x05\xc2\x23\x05",
                "pap": b"\x03\x04\xc0\x23"}


def options(data):
    out = []
    seen = set()
    while data:
        need(len(data) >= 2 and 2 <= data[1] <= len(data), "invalid PPP option length")
        value, data = data[:data[1]], data[data[1]:]
        need(value[0] not in seen, "duplicate PPP option")
        seen.add(value[0])
        out.append(value)
    return out


class PPP:
    def __init__(self, config, send, fail):
        self.config, self.send, self.fail = config, send, fail
        self.ip_receive = lambda data: None
        self.magic = secrets.token_bytes(4)
        self.lcp_options = b"\x01\x04"+u16(config.mtu)+b"\x05\x06"+self.magic
        self.ipcp_options = b"\x03\x06"+b"\0"*4+b"\x81\x06"+b"\0"*4+b"\x83\x06"+b"\0"*4
        self.mid = secrets.randbelow(255)
        self.pending = {}
        self.lcp_local = self.lcp_peer = self.ipcp_local = self.ipcp_peer = False
        self.authenticated = False
        self.auth_method = None
        self.local_ip = self.peer_ip = None
        self.dns_servers = ()
        self.peer_mru = 1500
        self.closed = False
        self.terminate_waiter = None
        self.terminate_id = None
        self.started = False
        self.queue = asyncio.Queue(maxsize=128)
        self.auth_state = None
        self.echo_waiters = {}
        self.last_peer_lcp = None
        self.peer_protocol_compression = self.peer_address_compression = False

    def receive(self, data):
        if not self.queue.full():
            self.queue.put_nowait(data)

    def _send(self, proto, code, mid, body=b""):
        frame = b"\xff\x03"+u16(proto)+struct.pack("!BBH", code, mid, len(body)+4)+body
        self.send(frame)

    def _next(self):
        self.mid = (self.mid+1) & 255
        return self.mid

    def _configure(self, proto):
        body = self.lcp_options if proto == LCP else self.ipcp_options
        mid = self._next()
        self.pending[proto] = [mid, body, 0, 0.0]
        self._send_config(proto)

    def _send_config(self, proto):
        state = self.pending[proto]
        if state[2] >= self.config.retransmit_attempts+5:
            raise VPNTimeout(f"PPP {'LCP' if proto == LCP else 'IPCP'} configuration timeout")
        state[2] += 1
        state[3] = asyncio.get_running_loop().time() + min(5, self.config.retransmit_initial*2**min(2, state[2]-1))
        self._send(proto, 1, state[0], state[1])

    async def run(self):
        self.ready = asyncio.get_running_loop().create_future()
        self.started = True
        self._configure(LCP)
        try:
            while not self.closed:
                try:
                    data = await asyncio.wait_for(self.queue.get(), 0.25)
                    self._handle(data)
                except TimeoutError:
                    pass
                now = asyncio.get_running_loop().time()
                for proto in tuple(self.pending):
                    if now >= self.pending[proto][3]:
                        self._send_config(proto)
                if self.lcp_local and self.lcp_peer and not self.authenticated:
                    if not self.auth_method:
                        raise AuthenticationError("PPP peer did not request user authentication")
                    if self.auth_method == "pap" and not self.auth_state:
                        self._pap()
                if self.auth_state and self.auth_state.get("retry_at", float("inf")) <= now and not self.authenticated:
                    if self.auth_state["attempt"] >= self.config.retransmit_attempts+2:
                        raise VPNTimeout("PPP authentication timed out")
                    self.auth_state["attempt"] += 1
                    self.auth_state["retry_at"] = now+3
                    self._send(self.auth_state["proto"], self.auth_state["code"], self.auth_state["mid"], self.auth_state["body"])
                if self.authenticated and self.lcp_local and self.lcp_peer and IPCP not in self.pending and not self.ipcp_local:
                    self._configure(IPCP)
                if self.authenticated and self.ipcp_local and self.ipcp_peer and not self.ready.done():
                    if not self.local_ip or self.local_ip == "0.0.0.0":
                        raise NegotiationError("PPP did not assign an IPv4 address")
                    log.info("PPP authenticated via %s; assigned %s", self.auth_method, self.local_ip)
                    self.ready.set_result(None)
        except BaseException as e:
            if not self.ready.done():
                if isinstance(e, asyncio.CancelledError):
                    self.ready.cancel()
                else:
                    self.ready.set_exception(e)
            if not isinstance(e, asyncio.CancelledError):
                self.fail(e)
            raise

    def _handle(self, frame):
        if frame.startswith(b"\xff\x03"):
            frame = frame[2:]
        need(frame, "empty PPP frame")
        if frame[0] & 1:
            proto, body = frame[0], frame[1:]
        else:
            need(len(frame) >= 2, "short PPP protocol")
            proto, body = integer(frame[:2]), frame[2:]
        if proto == IP:
            if self.authenticated and self.ipcp_local and self.ipcp_peer:
                self.ip_receive(body)
            return
        if proto not in (LCP, IPCP, CHAP, PAP):
            if self.lcp_local and self.lcp_peer:
                self._send(LCP, 8, self._next(), (u16(proto)+body)[:self.config.mtu-6])
            return
        need(len(body) >= 4, "short PPP control packet")
        code, mid, length = struct.unpack("!BBH", body[:4])
        need(4 <= length <= len(body), "PPP control length mismatch")
        data = body[4:length]
        if proto in (LCP, IPCP):
            self._ncp(proto, code, mid, data, body[:length])
        else:
            need(self.lcp_local and self.lcp_peer, "authentication before LCP opened")
            self._auth(proto, code, mid, data)

    def _ncp(self, proto, code, mid, data, raw):
        if proto == IPCP and not self.authenticated:
            return
        if code == 1:
            if proto == LCP and self.lcp_local and self.lcp_peer and self.last_peer_lcp != (mid, data):
                raise TunnelClosed("PPP peer restarted LCP; reconnect required")
            rejected, nak = [], []
            opts = options(data)
            auth = None
            for opt in opts:
                kind = opt[0]
                if proto == LCP:
                    if kind == 1 and len(opt) == 4:
                        self.peer_mru = integer(opt[2:])
                        if self.peer_mru < 576:
                            nak.append(b"\x01\x04"+u16(576))
                    elif kind == 2 and len(opt) == 6:
                        pass  # ACCM has no effect on synchronous L2TP framing.
                    elif kind == 3:
                        auth = next((a for a in self.config.auth_methods if opt == AUTH_OPTIONS[a]), None)
                        if auth is None:
                            nak.append(AUTH_OPTIONS[self.config.auth_methods[0]])
                    elif kind == 5 and len(opt) == 6:
                        if opt[2:] == self.magic:
                            nak.append(b"\x05\x06"+secrets.token_bytes(4))
                    elif kind in (7, 8) and len(opt) == 2:
                        pass
                    else:
                        rejected.append(opt)
                else:
                    if kind == 3 and len(opt) == 6 and opt[2:] != b"\0"*4:
                        self.peer_ip = str(ipaddress.ip_address(opt[2:]))
                    else:
                        rejected.append(opt)
            if rejected:
                self._send(proto, 4, mid, b"".join(rejected))
            elif nak:
                self._send(proto, 3, mid, b"".join(nak))
            else:
                self._send(proto, 2, mid, data)
                if proto == LCP:
                    self.auth_method = auth
                    self.lcp_peer = True
                    self.last_peer_lcp = (mid, data)
                else:
                    self.ipcp_peer = True
        elif code in (2, 3, 4):
            state = self.pending.get(proto)
            if not state or state[0] != mid:
                return
            if code == 2:
                need(data == state[1], "PPP Configure-Ack changed request options")
                del self.pending[proto]
                if proto == LCP:
                    self.lcp_local = True
                else:
                    self.ipcp_local = True
                    opts = {o[0]: o for o in options(data)}
                    need(3 in opts, "IPCP address option was rejected")
                    self.local_ip = str(ipaddress.ip_address(opts[3][2:]))
                    self.dns_servers = tuple(str(ipaddress.ip_address(opts[k][2:])) for k in (129,131)
                                             if k in opts and opts[k][2:] != b"\0"*4)
            else:
                current = {o[0]: o for o in options(state[1])}
                for opt in options(data):
                    if code == 4:
                        need(current.get(opt[0]) == opt, "PPP rejected an unrequested/changed option")
                        del current[opt[0]]
                    elif proto == IPCP and opt[0] in (3,129,131) and len(opt) == 6:
                        current[opt[0]] = opt
                    elif proto == LCP and opt[0] == 1 and len(opt) == 4:
                        current[1] = b"\x01\x04"+u16(min(self.config.mtu, max(576, integer(opt[2:]))))
                    elif proto == LCP and opt[0] == 5 and len(opt) == 6:
                        self.magic = secrets.token_bytes(4)
                        current[5] = b"\x05\x06"+self.magic
                updated = b"".join(current.values())
                if proto == LCP:
                    self.lcp_options = updated
                else:
                    need(3 in current, "IPCP IPv4 address rejected")
                    self.ipcp_options = updated
                # Count negotiation changes too, preventing infinite NAK loops.
                attempts = state[2]
                self._configure(proto)
                self.pending[proto][2] = attempts+1
        elif code == 5:
            self._send(proto, 6, mid, data)
            raise TunnelClosed("PPP peer terminated link")
        elif proto == LCP and code == 9:
            need(len(data) >= 4, "short PPP echo")
            need(data[:4] != self.magic, "PPP loopback detected")
            self._send(LCP, 10, mid, self.magic+data[4:])
        elif proto == LCP and code == 10:
            need(len(data) >= 4 and data[:4] != self.magic, "invalid PPP echo response")
            waiter = self.echo_waiters.get(mid)
            if waiter and not waiter.done() and data[4:] == self.echo_tokens.get(mid):
                waiter.set_result(None)
        elif code in (6, 7, 8, 11):
            if (code == 6 and proto == LCP and mid == self.terminate_id and
                    self.terminate_waiter and not self.terminate_waiter.done()):
                self.terminate_waiter.set_result(None)
            if code in (7, 8) and proto == LCP:
                raise NegotiationError("PPP peer rejected a required protocol/code")
        else:
            self._send(proto, 7, self._next(), raw[:self.config.mtu-4])

    def _remember_auth(self, proto, code, mid, body, **extras):
        self.auth_state = dict(proto=proto, code=code, mid=mid, body=body, attempt=1,
                               retry_at=asyncio.get_running_loop().time()+3, **extras)
        self._send(proto, code, mid, body)

    def _pap(self):
        user, password = self.config.username.encode(), self.config.password.encode()
        need(len(user) <= 255 and len(password) <= 255, "PAP credentials too long")
        self._remember_auth(PAP, 1, self._next(), bytes([len(user)])+user+bytes([len(password)])+password)

    def _auth(self, proto, code, mid, data):
        if self.auth_method == "pap":
            need(proto == PAP, "unexpected PPP authentication protocol")
            if not self.auth_state or mid != self.auth_state["mid"]:
                return
            if code == 2:
                need(data and data[0] <= len(data)-1, "malformed PAP acknowledgment")
                self.authenticated = True
            elif code == 3:
                raise AuthenticationError("PAP authentication rejected")
            return
        need(proto == CHAP and self.auth_method in ("mschapv2", "chap-md5"), "unexpected CHAP")
        if code == 1:
            need(data and 1 <= data[0] <= len(data)-1, "invalid CHAP challenge")
            challenge = data[1:1+data[0]]
            if self.auth_state and self.auth_state.get("challenge") == challenge and self.auth_state["mid"] == mid:
                self._send(CHAP, 2, mid, self.auth_state["body"])
                return
            user = self.config.username.encode()
            if self.auth_method == "mschapv2":
                peer = secrets.token_bytes(16)
                response = mschapv2_response(challenge, peer, self.config.username, self.config.password)
                expected = mschapv2_authenticator(challenge, peer, self.config.username, self.config.password, response)
                body = b"\x31"+peer+b"\0"*8+response+b"\0"+user
            else:
                response = hashlib.md5(bytes([mid])+self.config.password.encode()+challenge).digest()
                expected, body = None, b"\x10"+response+user
            self.authenticated = False
            self._remember_auth(CHAP, 2, mid, body, challenge=challenge, expected=expected)
        elif code in (3, 4):
            if not self.auth_state or self.auth_state["mid"] != mid:
                return
            if code == 4:
                raise AuthenticationError("CHAP/MSCHAP-v2 authentication rejected")
            expected = self.auth_state.get("expected")
            if expected and not hmac.compare_digest(data[:42].upper(), expected):
                raise AuthenticationError("MSCHAP-v2 server authenticator response mismatch")
            self.authenticated = True

    def send_ip(self, data):
        if not self.authenticated or not self.ipcp_local or not self.ipcp_peer or self.closed:
            raise TunnelClosed("PPP IP layer is not open")
        need(len(data) <= min(self.config.mtu, self.peer_mru), "IP packet exceeds PPP MRU")
        self.send(b"\xff\x03\x00\x21"+data)

    async def echo(self):
        mid, token = self._next(), secrets.token_bytes(8)
        waiter = asyncio.get_running_loop().create_future()
        # Store token separately: asyncio Future has no portable arbitrary attributes.
        self.echo_waiters[mid] = waiter
        self.echo_tokens = getattr(self, "echo_tokens", {})
        self.echo_tokens[mid] = token
        try:
            for _ in range(3):
                self._send(LCP, 9, mid, self.magic+token)
                try:
                    await asyncio.wait_for(asyncio.shield(waiter), 3)
                    return
                except TimeoutError:
                    pass
            raise TunnelClosed("PPP LCP echo timed out")
        finally:
            self.echo_waiters.pop(mid, None)
            self.echo_tokens.pop(mid, None)
            waiter.cancel()

    def close(self):
        if not self.closed and self.lcp_local:
            self._send(LCP, 5, self._next())
        self.closed = True

    async def aclose(self):
        if self.closed:
            return
        try:
            if self.lcp_local and self.started:
                self.terminate_id = self._next()
                self.terminate_waiter = asyncio.get_running_loop().create_future()
                async with asyncio.timeout(self.config.shutdown_timeout):
                    for attempt in range(self.config.retransmit_attempts):
                        self._send(LCP, 5, self.terminate_id)
                        try:
                            await asyncio.wait_for(asyncio.shield(self.terminate_waiter),
                                min(2, self.config.retransmit_initial*2**attempt))
                            break
                        except TimeoutError:
                            pass
        finally:
            self.closed = True
            if self.terminate_waiter and not self.terminate_waiter.done():
                self.terminate_waiter.cancel()
