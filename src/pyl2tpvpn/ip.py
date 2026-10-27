"""IPv4/UDP/ICMP codecs and bounded fragment reassembly."""
import ipaddress
import secrets
import struct
import time
from .wire import need, integer


def checksum(data):
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data)//2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def ipv4(src, dst, proto, body, *, identification=None, fragment=0, ttl=64):
    need(len(body) <= 65515, "IPv4 payload too large")
    identification = secrets.randbelow(65536) if identification is None else identification
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, len(body)+20, identification, fragment, ttl, proto, 0,
                         ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    return header[:10]+struct.pack("!H", checksum(header))+header[12:]+body


def parse_ipv4(data):
    need(len(data) >= 20 and data[0] >> 4 == 4, "invalid IPv4 header")
    ihl, length = (data[0] & 15)*4, integer(data[2:4])
    need(20 <= ihl <= 60 and ihl <= length <= len(data), "bad IPv4 lengths")
    need(checksum(data[:ihl]) == 0, "IPv4 checksum failure")
    need(not integer(data[6:8]) & 0x8000, "reserved IPv4 fragment flag")
    return (str(ipaddress.ip_address(data[12:16])), str(ipaddress.ip_address(data[16:20])),
            data[9], integer(data[4:6]), integer(data[6:8]), data[ihl:length])


def pseudo(src, dst, proto, length):
    return ipaddress.IPv4Address(src).packed+ipaddress.IPv4Address(dst).packed+struct.pack("!BBH", 0, proto, length)


def udp(src_port, dst_port, data, src=None, dst=None):
    need(len(data) <= 65507, "UDP datagram too large")
    packet = struct.pack("!HHHH", src_port, dst_port, len(data)+8, 0)+data
    if src is not None:
        crc = checksum(pseudo(src, dst, 17, len(packet))+packet) or 0xffff
        packet = packet[:6]+struct.pack("!H", crc)+packet[8:]
    return packet


def parse_udp(data, src=None, dst=None):
    need(len(data) >= 8, "short UDP packet")
    sp, dp, length, crc = struct.unpack("!HHHH", data[:8])
    need(8 <= length == len(data), "UDP length mismatch")
    if crc and src is not None:
        need(checksum(pseudo(src, dst, 17, length)+data) == 0, "UDP checksum failure")
    return sp, dp, data[8:]


class Reassembly:
    def __init__(self, max_entries=64, max_bytes=1 << 20, timeout=15):
        self.entries = {}
        self.max_entries, self.max_bytes, self.timeout = max_entries, max_bytes, timeout

    def add(self, src, dst, proto, ident, flags, body):
        now = time.monotonic()
        for key, item in list(self.entries.items()):
            if now-item[0] > self.timeout:
                del self.entries[key]
        if not flags & 0x3fff:
            return body
        offset, more = (flags & 0x1fff)*8, bool(flags & 0x2000)
        need(not flags & 0x4000 and body and offset+len(body) <= 65515 and
             (not more or len(body) % 8 == 0), "invalid IP fragment")
        key = (src, dst, proto, ident)
        if key not in self.entries:
            need(len(self.entries) < self.max_entries, "fragment table full")
            self.entries[key] = [now, {}, None]
        item = self.entries[key]
        # Drop the complete datagram on any overlap, including exact duplicates.
        for old, part in item[1].items():
            if offset < old+len(part) and old < offset+len(body):
                del self.entries[key]
                need(False, "overlapping IP fragments")
        total_bytes = sum(sum(len(p) for p in e[1].values()) for e in self.entries.values())
        need(total_bytes+len(body) <= self.max_bytes, "fragment memory limit")
        item[1][offset] = body
        if not more:
            need(item[2] in (None, offset+len(body)), "conflicting last fragment")
            item[2] = offset+len(body)
        length = item[2]
        pos, parts = 0, []
        for start, part in sorted(item[1].items()):
            if start != pos:
                return None
            parts.append(part)
            pos += len(part)
        if length is not None:
            need(pos <= length, "fragment extends past datagram end")
        if pos == length:
            del self.entries[key]
            return b"".join(parts)
        return None
