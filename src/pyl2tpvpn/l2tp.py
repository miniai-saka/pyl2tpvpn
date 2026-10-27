"""RFC 2661 voluntary LAC, one tunnel/session, reliable control channel."""
import asyncio
import logging
import secrets
import struct
from .errors import NegotiationError, ProtocolError, TunnelClosed, VPNTimeout
from .wire import need, u16, u32, integer

log = logging.getLogger(__name__)
KNOWN_AVPS = set(range(40))


def avp(kind, value, mandatory=True):
    return struct.pack("!HHH", (0x8000 if mandatory else 0) | (len(value)+6), 0, kind) + value


def parse_avps(data):
    result = {}
    while data:
        need(len(data) >= 6, "short L2TP AVP")
        flags, vendor, kind = struct.unpack("!HHH", data[:6])
        length = flags & 0x3ff
        need(6 <= length <= len(data), "bad L2TP AVP length")
        mandatory, hidden = bool(flags & 0x8000), bool(flags & 0x4000)
        need(not flags & 0x3c00, "reserved L2TP AVP flags")
        if mandatory and (vendor or kind not in KNOWN_AVPS):
            raise NegotiationError("unrecognized mandatory L2TP AVP")
        if not vendor and kind in KNOWN_AVPS:
            need(not hidden, "hidden L2TP AVPs require tunnel authentication (unsupported)")
            need(kind not in result, "duplicate L2TP AVP")
            result[kind] = data[6:length]
        data = data[length:]
    return result


def parse_packet(data):
    need(len(data) >= 6, "short L2TP packet")
    flags = integer(data[:2])
    need(flags & 0xf == 2 and not flags & 0x34f0, "invalid L2TP flags/version")
    control = bool(flags & 0x8000)
    pos = 2
    if flags & 0x4000:
        need(len(data) >= 8, "short L2TP length header")
        length = integer(data[pos:pos+2])
        need(length == len(data), "L2TP length mismatch")
        pos += 2
    need(len(data) >= pos+4, "short L2TP IDs")
    tunnel, session = struct.unpack("!HH", data[pos:pos+4])
    pos += 4
    ns = nr = None
    if flags & 0x0800:
        need(len(data) >= pos+4, "short L2TP sequence header")
        ns, nr = struct.unpack("!HH", data[pos:pos+4])
        pos += 4
    if flags & 0x0200:
        need(len(data) >= pos+2, "short L2TP offset")
        offset = integer(data[pos:pos+2])
        pos += 2+offset
        need(pos <= len(data), "invalid L2TP offset")
    if control:
        need(flags == 0xc802, "invalid L2TP control flags")
    return control, tunnel, session, ns, nr, data[pos:]


def before(a, b):
    return 0 < ((b-a) & 0xffff) < 0x8000


class L2TP:
    def __init__(self, config, send, fail):
        self.config, self.send, self.fail = config, send, fail
        self.tunnel_id, self.session_id = secrets.randbelow(65535)+1, secrets.randbelow(65535)+1
        self.peer_tunnel = self.peer_session = 0
        self.ns = self.nr = 0
        self.data_ns = self.data_nr = 0
        self.sequence_data = False
        self.pending = None
        self.expected = {}
        self.control_lock = asyncio.Lock()
        self.ppp_receive = lambda data: None
        self.connected = self.closed = False

    def _control(self, body, ns, session=0):
        return struct.pack("!HHHHHH", 0xc802, len(body)+12, self.peer_tunnel, session, ns, self.nr)+body

    def _ack(self):
        self.send(self._control(b"", self.ns))

    async def control(self, message, values=(), *, session=0, expect=None):
        async with self.control_lock:
            seq = self.ns
            self.ns = (self.ns+1) & 0xffff
            body = avp(0, u16(message)) + b"".join(avp(*v) for v in values)
            ack = asyncio.get_running_loop().create_future()
            response = asyncio.get_running_loop().create_future() if expect else ack
            self.pending = (seq, ack)
            if expect:
                self.expected[expect] = response
            try:
                for attempt in range(self.config.retransmit_attempts):
                    # Nr may advance during retransmission; Ns and AVPs remain fixed.
                    self.send(self._control(body, seq, session))
                    try:
                        return await asyncio.wait_for(asyncio.shield(response),
                            min(8, self.config.retransmit_initial*2**attempt))
                    except TimeoutError:
                        pass
                raise VPNTimeout(f"L2TP control message {message} was not acknowledged")
            finally:
                self.pending = None
                if expect:
                    self.expected.pop(expect, None)
                if not response.done():
                    response.cancel()
                if not ack.done():
                    ack.cancel()

    async def connect(self):
        attrs = await self.control(1, [(2, b"\x01\0"), (3, u32(1)), (7, b"pyl2tpvpn"),
                                       (9, u16(self.tunnel_id)), (10, u16(1))], expect=2)
        need(attrs.get(2) == b"\x01\0", "unsupported L2TP protocol version")
        need(len(attrs.get(9, b"")) == 2, "missing peer L2TP tunnel ID")
        self.peer_tunnel = integer(attrs[9])
        need(self.peer_tunnel != 0, "zero L2TP tunnel ID")
        if 11 in attrs:
            raise NegotiationError("L2TP tunnel challenge authentication is not configured")
        await self.control(3)
        attrs = await self.control(10, [(14, u16(self.session_id)), (15, secrets.token_bytes(4))], expect=11)
        need(len(attrs.get(14, b"")) == 2, "missing peer L2TP session ID")
        self.peer_session = integer(attrs[14])
        need(self.peer_session != 0, "zero L2TP session ID")
        self.sequence_data = 39 in attrs
        # PPP can arrive immediately after ICCN; enable the data path before send.
        self.connected = True
        await self.control(12, [(24, u32(100000000)), (19, u32(1))], session=self.peer_session)
        log.info("L2TP control and data session established")

    def receive(self, data):
        control, tunnel, session, ns, nr, body = parse_packet(data)
        need(tunnel == self.tunnel_id, "wrong L2TP tunnel ID")
        if not control:
            need(self.connected and session == self.session_id, "wrong L2TP data session")
            if ns is not None:
                if before(ns, self.data_nr):
                    return
                self.data_nr = (ns+1) & 0xffff
            self.ppp_receive(body)
            return
        need(session in (0, self.session_id), "wrong L2TP control session")
        need(not before(self.ns, nr), "L2TP acknowledgment beyond send sequence")
        if self.pending and before(self.pending[0], nr) and not self.pending[1].done():
            self.pending[1].set_result({})
        if not body:  # ZLB consumes no sequence number and is never itself acknowledged.
            return
        if ns != self.nr:
            self._ack()  # Cumulative ACK provokes retransmission of missing control.
            return
        attrs = parse_avps(body)
        need(len(attrs.get(0, b"")) == 2 and body[4:6] == b"\0\0", "missing first Message Type AVP")
        message = integer(attrs[0])
        self.nr = (self.nr+1) & 0xffff
        # SCCRP contains the ID needed for its first cumulative ACK.
        if message == 2 and len(attrs.get(9, b"")) == 2 and not self.peer_tunnel:
            self.peer_tunnel = integer(attrs[9])
        self._ack()
        if message in (4, 14):
            self.fail(TunnelClosed(f"L2TP peer closed tunnel/session (result {integer(attrs.get(1, b'')[:2])})"))
            return
        waiter = self.expected.get(message)
        if waiter and not waiter.done():
            waiter.set_result(attrs)

    def send_ppp(self, frame):
        if not self.connected or self.closed:
            raise TunnelClosed("L2TP session is closed")
        flags = 0x0802 if self.sequence_data else 2
        packet = struct.pack("!HHH", flags, self.peer_tunnel, self.peer_session)
        if self.sequence_data:
            packet += struct.pack("!HH", self.data_ns, self.data_nr)
            self.data_ns = (self.data_ns+1) & 0xffff
        self.send(packet+frame)

    async def hello(self):
        await self.control(6)

    async def close(self):
        if self.closed:
            return
        try:
            if self.peer_tunnel:
                async with asyncio.timeout(self.config.shutdown_timeout):
                    await self.control(4, [(9, u16(self.tunnel_id)), (1, u16(1))])
        finally:
            self.closed, self.connected = True, False
