"""IPv4 sockets, DNS and ICMP that exclusively use the PPP data path."""
import asyncio
import ipaddress
import logging
import secrets
import ssl as ssl_module
import struct
import time
from .errors import TunnelClosed, VPNTimeout, NegotiationError, ProtocolError
from .ip import ipv4, parse_ipv4, udp, parse_udp, checksum, Reassembly
from .tcp import TCPConnection
from .wire import need, integer, u16

log = logging.getLogger(__name__)


class Datagram:
    def __init__(self, network, address, port, local_port):
        self.network, self.address, self.port, self.local_port = network, address, port, local_port
        self.queue = asyncio.Queue(maxsize=128)
        self.closed = False

    def send(self, data):
        if self.closed:
            raise TunnelClosed("UDP socket closed")
        self.network.send(self.address, 17, udp(self.local_port, self.port, data, self.network.address, self.address))

    async def recv(self, *, timeout=None):
        if self.closed and self.queue.empty():
            raise TunnelClosed("UDP socket closed")
        if timeout is None:
            item = await self.queue.get()
        else:
            item = await asyncio.wait_for(self.queue.get(), timeout)
        if isinstance(item, Exception):
            raise item
        return item

    def close(self, error=None):
        if self.closed:
            return
        self.closed = True
        self.network.datagrams.pop(self.local_port, None)
        if self.queue.full():
            self.queue.get_nowait()
        self.queue.put_nowait(error or TunnelClosed("UDP socket closed"))

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        self.close()


def dns_name(message, offset):
    labels, seen, end = [], set(), None
    for _ in range(128):
        need(offset < len(message) and offset not in seen, "DNS name pointer loop/bounds")
        seen.add(offset)
        length = message[offset]
        offset += 1
        if length & 0xc0 == 0xc0:
            need(offset < len(message), "short DNS pointer")
            end = end if end is not None else offset+1
            offset = ((length & 0x3f) << 8) | message[offset]
        elif length == 0:
            return ".".join(labels).lower(), end if end is not None else offset
        else:
            need(length <= 63 and offset+length <= len(message), "bad DNS label")
            labels.append(message[offset:offset+length].decode("ascii"))
            offset += length
    raise ProtocolError("DNS name exceeds pointer depth")


class Network:
    def __init__(self, address, send_ip, mtu, dns_servers, *, policy=None):
        self.address, self.send_ip, self.mtu = address, send_ip, mtu
        self.dns_servers = tuple(dns_servers)
        self.tcp, self.datagrams, self.pings = {}, {}, {}
        self.reassembly = Reassembly()
        self.dns_cache = {}
        self.closed = False
        self.policy = policy
        self.stats = {"tcp_received":0,"tcp_unmatched":0,"udp_received":0,"icmp_received":0,"invalid":0}

    def _port(self, table):
        for _ in range(20000):
            p = secrets.randbelow(16384)+49152
            if p not in table:
                return p
        raise OSError("VPN ephemeral port pool exhausted")

    def send(self, dst, proto, payload):
        if self.closed:
            raise TunnelClosed("VPN IP stack closed")
        if self.policy:
            self.policy(self.address, dst, proto, payload, False)
        if len(payload)+20 <= self.mtu:
            self.send_ip(ipv4(self.address, dst, proto, payload))
        else:
            size = ((self.mtu-20)//8)*8
            ident = secrets.randbelow(65536)
            for start in range(0, len(payload), size):
                more = start+size < len(payload)
                self.send_ip(ipv4(self.address, dst, proto, payload[start:start+size],
                                  identification=ident, fragment=(start//8) | (0x2000 if more else 0)))

    def receive(self, packet):
        try:
            src, dst, proto, ident, fragment, body = parse_ipv4(packet)
            need(dst == self.address, "IPv4 destination does not match PPP address")
            body = self.reassembly.add(src, dst, proto, ident, fragment, body)
            if body is None:
                return
            if self.policy:
                self.policy(src, dst, proto, body, True)
            if proto == 17:
                self.stats["udp_received"] += 1
                sp, dp, data = parse_udp(body, src, dst)
                channel = self.datagrams.get(dp)
                if channel and channel.address == src and channel.port == sp and not channel.queue.full():
                    channel.queue.put_nowait(data)
            elif proto == 6:
                self.stats["tcp_received"] += 1
                need(len(body) >= 20, "short TCP")
                sp, dp = struct.unpack("!HH", body[:4])
                conn = self.tcp.get((dp, src, sp))
                if conn:
                    conn.receive(body)
                else:
                    self.stats["tcp_unmatched"] += 1
            elif proto == 1:
                self.stats["icmp_received"] += 1
                need(len(body) >= 8 and checksum(body) == 0, "bad ICMP checksum/header")
                if body[:2] == b"\0\0":
                    ident, seq = struct.unpack("!HH", body[4:8])
                    entry = self.pings.get((src, ident, seq))
                    if entry and body[8:] == entry[1] and not entry[0].done():
                        entry[0].set_result(None)
                elif body[:2] == b"\x08\0":
                    reply = b"\0\0\0\0"+body[4:]
                    reply = reply[:2]+u16(checksum(reply))+reply[4:]
                    self.send(src, 1, reply)
                elif body[0] in (3, 11):
                    # Deliver authenticated network errors to the matching UDP socket.
                    if len(body) >= 36 and body[8] >> 4 == 4:
                        inner = body[8:]
                        ihl = (inner[0] & 15)*4
                        if len(inner) >= ihl+8 and inner[9] == 17:
                            port = integer(inner[ihl:ihl+2])
                            channel = self.datagrams.get(port)
                            if channel and not channel.queue.full():
                                channel.queue.put_nowait(OSError(f"ICMP error {body[0]}/{body[1]}"))
        except (ProtocolError, UnicodeError, ValueError):
            self.stats["invalid"] += 1
            log.debug("Rejected invalid inner IP packet", exc_info=True)

    async def open_datagram(self, host, port):
        need(1 <= port <= 65535, "invalid destination port")
        address = (await self.resolve(host))[0]
        local = self._port(self.datagrams)
        channel = Datagram(self, address, port, local)
        self.datagrams[local] = channel
        return channel

    async def _dns_query(self, server, name, timeout):
        ident = secrets.randbelow(65536)
        labels = name.rstrip(".").encode("idna").split(b".")
        need(all(0 < len(label) <= 63 for label in labels), "invalid DNS name")
        question = b"".join(bytes([len(label)])+label for label in labels)+b"\0\0\x01\0\x01"
        need(len(question) <= 259, "DNS name too long")
        query = struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0)+question
        port = self._port(self.datagrams)
        channel = Datagram(self, server, 53, port)
        self.datagrams[port] = channel
        try:
            channel.send(query)
            async with asyncio.timeout(timeout):
                while True:
                    data = await channel.recv()
                    if len(data) >= 12 and integer(data[:2]) == ident:
                        break
            flags = integer(data[2:4])
            if flags & 0x0200:
                reader, writer = await self.open_connection(server, 53, timeout=timeout)
                try:
                    writer.write(u16(len(query))+query)
                    await writer.drain()
                    length = integer(await asyncio.wait_for(reader.readexactly(2), timeout))
                    data = await asyncio.wait_for(reader.readexactly(length), timeout)
                    need(len(data) >= 12 and integer(data[:2]) == ident, "invalid DNS TCP response")
                    flags = integer(data[2:4])
                finally:
                    writer.close()
            need(flags & 0x8000 and not flags & 0x7800 and not flags & 0x0200, "invalid DNS response flags")
            need(flags & 0xf == 0, f"DNS response error {flags & 0xf}")
            qd, an, ns, ar = struct.unpack("!HHHH", data[4:12])
            need(qd == 1 and an+ns+ar <= 1024, "invalid DNS counts")
            qname, pos = dns_name(data, 12)
            need(qname == name.rstrip(".").encode("idna").decode().lower() and data[pos:pos+4] == b"\0\x01\0\x01",
                 "DNS question mismatch")
            pos += 4
            addresses, ttl, aliases = [], 300, {qname}
            records = []
            for i in range(an+ns+ar):
                owner, pos = dns_name(data, pos)
                need(pos+10 <= len(data), "short DNS resource record")
                typ, cls, life, size = struct.unpack("!HHIH", data[pos:pos+10])
                pos += 10
                need(pos+size <= len(data), "bad DNS RDATA length")
                if i < an and cls == 1:
                    records.append((owner, typ, life, pos, size))
                pos += size
            for _ in range(16):
                changed = False
                for owner, typ, life, start, size in records:
                    if owner in aliases and typ == 5:
                        target, _ = dns_name(data, start)
                        if target not in aliases:
                            aliases.add(target)
                            changed = True
                        ttl = min(ttl, life)
                if not changed:
                    break
            for owner, typ, life, start, size in records:
                if owner in aliases and typ == 1 and size == 4:
                    addresses.append(str(ipaddress.ip_address(data[start:start+4])))
                    ttl = min(ttl, life)
            need(addresses, "DNS response contains no IPv4 addresses")
            return list(dict.fromkeys(addresses)), ttl
        finally:
            channel.close()

    async def resolve(self, host, *, timeout=5):
        try:
            return [str(ipaddress.IPv4Address(host))]
        except ipaddress.AddressValueError:
            pass
        if self.closed:
            raise TunnelClosed("VPN IP stack closed")
        key = host.lower().rstrip(".")
        cached = self.dns_cache.get(key)
        if cached and cached[0] > time.monotonic():
            return list(cached[1])
        if not self.dns_servers:
            raise NegotiationError("VPN supplied no DNS server; configure dns_servers explicitly")
        last = None
        for server in self.dns_servers:
            for _ in range(2):
                try:
                    result, ttl = await self._dns_query(str(ipaddress.IPv4Address(server)), key, timeout)
                    now = time.monotonic()
                    for old, entry in tuple(self.dns_cache.items()):
                        if entry[0] <= now:
                            self.dns_cache.pop(old, None)
                    if len(self.dns_cache) >= 1024:
                        self.dns_cache.pop(next(iter(self.dns_cache)))
                    self.dns_cache[key] = (time.monotonic()+min(ttl, 300), result)
                    return result
                except (OSError, TimeoutError, ProtocolError) as error:
                    last = error
        raise VPNTimeout(f"VPN DNS lookup failed: {type(last).__name__}") from last

    async def open_connection(self, host, port, *, ssl=None, server_hostname=None, timeout=30):
        need(1 <= port <= 65535, "invalid destination port")
        async with asyncio.timeout(timeout):
            addresses = await self.resolve(host, timeout=min(timeout, 5))
            last_error = None
            for address in addresses:
                local = self._port({key[0]: value for key,value in self.tcp.items()})
                key = (local, address, port)
                conn = TCPConnection(self.address, local, address, port, self.send,
                                     lambda c: self.tcp.pop((c.src_port,c.dst,c.dst_port), None), self.mtu)
                self.tcp[key] = conn
                try:
                    await conn.connected
                    if ssl:
                        from .tls import TLSStream
                        context = ssl_module.create_default_context() if ssl is True else ssl
                        stream = TLSStream(conn.reader, conn.writer, context, server_hostname or host)
                        await stream.handshake()
                        return stream, stream
                    return conn.reader, conn.writer
                except BaseException as e:
                    conn.abort(e if isinstance(e, Exception) else TunnelClosed("TCP connection cancelled"))
                    if isinstance(e, (asyncio.CancelledError, ssl_module.SSLError)):
                        raise
                    last_error = e
            raise last_error or TunnelClosed("No destination address")

    async def ping(self, host, *, timeout=5):
        address = (await self.resolve(host, timeout=timeout))[0]
        ident, seq, data = secrets.randbelow(65536), secrets.randbelow(65536), secrets.token_bytes(24)
        waiter = asyncio.get_running_loop().create_future()
        key = (address, ident, seq)
        self.pings[key] = (waiter, data)
        packet = b"\x08\0\0\0"+u16(ident)+u16(seq)+data
        packet = packet[:2]+u16(checksum(packet))+packet[4:]
        start = time.monotonic()
        try:
            self.send(address, 1, packet)
            await asyncio.wait_for(waiter, timeout)
            return time.monotonic()-start
        finally:
            self.pings.pop(key, None)

    def close(self, error=None):
        self.closed = True
        error = error or TunnelClosed("VPN closed")
        for conn in tuple(self.tcp.values()):
            conn.abort(error)
        for channel in tuple(self.datagrams.values()):
            channel.close(error)
        for waiter, data in self.pings.values():
            if not waiter.done():
                waiter.set_exception(error)
        self.pings.clear()
