"""Bounded IPv4 IKEv2 traffic selectors and Configuration Payload codecs."""
import ipaddress
import struct
from dataclasses import dataclass
from .wire import need, u16


@dataclass(frozen=True)
class Selector:
    first: int = 0
    last: int = 0xffffffff
    protocol: int = 0
    port_first: int = 0
    port_last: int = 65535

    def __post_init__(self):
        need(0 <= self.first <= self.last <= 0xffffffff and 0 <= self.protocol <= 255 and
             0 <= self.port_first <= self.port_last <= 65535, "invalid IPv4 traffic selector")

    def contains(self, other):
        return (self.first <= other.first <= other.last <= self.last and
                (self.protocol == 0 or self.protocol == other.protocol) and
                self.port_first <= other.port_first <= other.port_last <= self.port_last)

    def matches(self, address, protocol, port=0):
        return (self.first <= int(ipaddress.IPv4Address(address)) <= self.last and
                self.protocol in (0,protocol) and self.port_first <= port <= self.port_last)


def encode_selectors(selectors):
    need(1 <= len(selectors) <= 16, "invalid selector count")
    return bytes([len(selectors),0,0,0])+b"".join(struct.pack("!BBHHHII",7,s.protocol,16,
                     s.port_first,s.port_last,s.first,s.last) for s in selectors)


def parse_selectors(data):
    need(len(data) >= 4 and 1 <= data[0] <= 16 and data[1:4] == b"\0"*3, "bad TS header")
    count, tail = data[0],data[4:]
    result=[]
    for _ in range(count):
        need(len(tail) >= 16, "short IPv4 selector")
        kind,protocol,length,lo,hi,first,last=struct.unpack("!BBHHHII",tail[:16])
        need(kind == 7 and length == 16, "only IPv4 selectors were offered")
        result.append(Selector(first,last,protocol,lo,hi))
        tail=tail[16:]
    need(not tail, "trailing TS bytes")
    return tuple(result)


def check_narrowing(selected, offered):
    need(all(any(o.contains(s) for o in offered) for s in selected), "peer widened traffic selectors")


def address_selector(address):
    n=int(ipaddress.IPv4Address(address))
    return Selector(n,n)


def packet_allowed(local, remote, src, dst, protocol, body, incoming=False):
    sp = dp = 0
    if protocol in (6, 17):
        need(len(body) >= 4, "short transport header for traffic selectors")
        sp, dp = struct.unpack("!HH", body[:4])
    elif protocol in (1, 58):
        need(len(body) >= 2, "short ICMP header for traffic selectors")
        sp = dp = (body[0] << 8) | body[1]
    if incoming:
        src, dst, sp, dp = dst, src, dp, sp
    return (any(s.matches(src, protocol, sp) for s in local) and
            any(s.matches(dst, protocol, dp) for s in remote))


def configuration_request():
    return b"\x01\0\0\0"+b"".join(u16(k)+b"\0\0" for k in (1,2,3))


def configuration_reply(data):
    need(len(data) >= 4 and data[:4] == b"\x02\0\0\0", "expected CFG_REPLY")
    tail=data[4:]
    addresses,dns,netmask=[],[],None
    while tail:
        need(len(tail) >= 4, "short CP attribute")
        kind,length=struct.unpack("!HH",tail[:4])
        need(not kind & 0x8000 and length <= len(tail)-4, "bad CP attribute")
        value,tail=tail[4:4+length],tail[4+length:]
        if kind in (1,2,3):
            need(length == 4, "bad IPv4 configuration address")
            address=str(ipaddress.IPv4Address(value))
            if kind == 1:
                need(not ipaddress.IPv4Address(address).is_unspecified and not ipaddress.IPv4Address(address).is_multicast,
                     "unusable assigned IPv4 address")
                addresses.append(address)
            elif kind == 2:
                need(netmask is None, "duplicate IPv4 netmask")
                netmask=address
            elif address != "0.0.0.0":
                dns.append(address)
    need(len(addresses) == 1, "expected one assigned IPv4 address")
    return addresses[0],tuple(dict.fromkeys(dns)),netmask
