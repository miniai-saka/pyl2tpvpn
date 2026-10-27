"""Bounded binary codecs. Network validation never relies on assert."""
import struct
from dataclasses import dataclass
from .errors import ProtocolError


def need(ok, message="malformed packet"):
    if not ok:
        raise ProtocolError(message)


def u16(n):
    return struct.pack("!H", n)


def u32(n):
    return struct.pack("!I", n)


def integer(data):
    return int.from_bytes(data, "big")


def attributes(values):
    return b"".join(struct.pack("!HH", k | 0x8000, v) if isinstance(v, int)
                    else struct.pack("!HH", k, len(v)) + v for k, v in values)


def parse_attributes(data):
    result = []
    while data:
        need(len(data) >= 4, "truncated attribute")
        kind, value = struct.unpack("!HH", data[:4])
        data = data[4:]
        if kind & 0x8000:
            kind &= 0x7fff
        else:
            need(len(data) >= value, "truncated variable attribute")
            value, data = data[:value], data[value:]
        result.append((kind, value))
    return result


@dataclass(frozen=True)
class Payload:
    kind: int
    body: bytes
    raw: bytes = b""


def encode_payloads(payloads):
    return b"".join(struct.pack("!BBH", payloads[i+1].kind if i+1 < len(payloads) else 0,
                                0, len(p.body)+4) + p.body for i, p in enumerate(payloads))


def decode_payloads(first, data, *, padding=False):
    result = []
    while first:
        need(len(result) < 128 and len(data) >= 4, "invalid IKE payload chain")
        nxt, flags, length = struct.unpack("!BBH", data[:4])
        need(4 <= length <= len(data), "invalid IKE payload length")
        result.append(Payload(first, data[4:length], data[:length]))
        first, data = nxt, data[length:]
    need(padding or not data, "trailing payload bytes")
    if padding:
        need(len(data) < 16, "excess IKE padding")
    return result


def one(payloads, kind):
    found = [p for p in payloads if p.kind == kind]
    need(len(found) == 1, f"expected one IKE payload type {kind}")
    return found[0].body


@dataclass(frozen=True)
class IKEPacket:
    initiator: bytes
    responder: bytes
    first: int
    version: int
    exchange: int
    flags: int
    message_id: int
    body: bytes

    @classmethod
    def parse(cls, data):
        need(len(data) >= 28, "short IKE header")
        h = struct.unpack("!8s8sBBBBII", data[:28])
        need(h[-1] == len(data), "IKE length mismatch")
        return cls(*h[:-1], data[28:])

    def encode(self):
        return struct.pack("!8s8sBBBBII", self.initiator, self.responder, self.first, self.version,
                           self.exchange, self.flags, self.message_id, len(self.body)+28) + self.body


def proposal_v1(protocol, spi, transforms, number=1):
    ts = b""
    for i, (tid, attrs) in enumerate(transforms):
        a = attributes(attrs)
        ts += struct.pack("!BBHBBBB", 3 if i+1 < len(transforms) else 0, 0, len(a)+8,
                          i+1, tid, 0, 0) + a
    body = bytes([number, protocol, len(spi), len(transforms)]) + spi + ts
    return struct.pack("!BBH", 0, 0, len(body)+4) + body


def parse_sa_v1(data):
    need(len(data) >= 8 and data[:8] == u32(1)+u32(1), "unsupported IPsec DOI/situation")
    data = data[8:]
    proposals = []
    while data:
        need(len(data) >= 8, "short SA proposal")
        nxt, _, length, num, proto, spi_len, count = struct.unpack("!BBHBBBB", data[:8])
        need(8+spi_len <= length <= len(data), "bad proposal length")
        spi, tail = data[8:8+spi_len], data[8+spi_len:length]
        transforms = []
        for i in range(count):
            need(len(tail) >= 8, "short transform")
            tn, _, tl, tnum, tid, _, _ = struct.unpack("!BBHBBBB", tail[:8])
            need(8 <= tl <= len(tail), "bad transform length")
            transforms.append((tid, parse_attributes(tail[8:tl])))
            tail = tail[tl:]
            # Some gateways preserve Next=Transform when copying the chosen
            # transform from a multi-transform offer. Count and enclosing length
            # must still agree exactly; no trailing transform bytes are accepted.
            need(tn == 3 if i+1 < count else tn in (0, 3), "bad transform chain")
        need(not tail and count > 0, "invalid transform count")
        proposals.append((num, proto, spi, transforms))
        data = data[length:]
        need(nxt == (2 if data else 0), "bad proposal chain")
    need(proposals, "empty SA")
    return proposals
