import asyncio
import logging
import socket
import time
from .errors import VPNError, VPNTimeout, TunnelClosed
from .wire import IKEPacket

log = logging.getLogger(__name__)


class _UDP(asyncio.DatagramProtocol):
    def __init__(self, owner, natt):
        self.owner, self.natt = owner, natt
        self.closed = asyncio.get_running_loop().create_future()

    def datagram_received(self, data, addr):
        self.owner.receive(data, self.natt)

    def error_received(self, error):
        self.owner.stats.setdefault("udp_errors", 0)
        self.owner.stats["udp_errors"] += 1
        log.debug("UDP transport error: %s", type(error).__name__)

    def connection_lost(self, error):
        if not self.closed.done():
            self.closed.set_result(None)


class UDPLink:
    def __init__(self, config):
        self.config = config
        self.sessions = {}
        self.transports = {}
        self.protocols = {}
        self.esp_receiver = lambda data: None
        self.last_received = time.monotonic()
        self.stats = {"udp_sent": 0, "udp_received": 0, "invalid_packets": 0}

    async def open(self):
        loop = asyncio.get_running_loop()
        addresses = await loop.getaddrinfo(self.config.server, self.config.server_ike_port,
                                          family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.peer = addresses[0][4][0]
        try:
            for natt, local_port, remote_port in (
                (False, self.config.local_ike_port, self.config.server_ike_port),
                (True, self.config.local_natt_port, self.config.server_natt_port),
            ):
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    s.bind((self.config.local_address, local_port))
                    s.connect((self.peer, remote_port))
                    s.setblocking(False)
                    tr, protocol = await loop.create_datagram_endpoint(lambda: _UDP(self, natt), sock=s)
                    self.transports[natt] = tr
                    self.protocols[natt] = protocol
                except BaseException:
                    s.close()
                    raise
            self.local_ip, self.local_port = self.transports[False].get_extra_info("sockname")
            _, self.natt_local_port = self.transports[True].get_extra_info("sockname")
        except BaseException:
            self.close()
            raise
        log.info("UDP sockets ready for %s; host routing unchanged", self.peer)

    def send(self, packet, *, natt=True, ike=True):
        if natt and ike:
            packet = b"\0\0\0\0" + packet
        port = self.config.server_natt_port if natt else self.config.server_ike_port
        self.transports[natt].sendto(packet, (self.peer, port))
        self.stats["udp_sent"] += 1

    def receive(self, data, natt):
        self.stats["udp_received"] += 1
        try:
            if natt:
                if data == b"\xff":
                    return
                if not data.startswith(b"\0\0\0\0"):
                    self.esp_receiver(data)
                    return
                data = data[4:]
            packet = IKEPacket.parse(data)
            session = self.sessions.get(packet.initiator)
            if session:
                session.receive(packet, data, natt)
        except VPNError:
            self.stats["invalid_packets"] += 1
            log.debug("Discarded invalid VPN datagram", exc_info=True)

    def close(self):
        for tr in self.transports.values():
            tr.close()
        self.transports.clear()
        self.sessions.clear()

    async def drain(self):
        while any(tr.get_write_buffer_size() for tr in self.transports.values()):
            await asyncio.sleep(0.01)

    async def aclose(self):
        try:
            async with asyncio.timeout(self.config.shutdown_timeout):
                await self.drain()
                self.close()
                await asyncio.gather(*(p.closed for p in self.protocols.values()))
        finally:
            self.close()
            self.protocols.clear()


class Exchanges:
    def __init__(self, link, config):
        self.link, self.config = link, config
        self.pending = {}
        self.closed = False

    async def request(self, raw, exchange, mid, *, natt=True, accept=None):
        hard_deadline = float("inf")
        if getattr(self, "established", False):
            hard_deadline = self.created+self.ike_lifetime
        queue = asyncio.Queue(maxsize=16)
        key = (exchange, mid)
        if key in self.pending:
            raise RuntimeError("duplicate concurrent IKE exchange")
        self.pending[key] = queue
        try:
            for attempt in range(self.config.retransmit_attempts):
                if self.closed or time.monotonic() >= hard_deadline:
                    raise TunnelClosed("IKE SA closed or hard lifetime expired")
                self.link.send(raw, natt=natt)
                deadline = asyncio.get_running_loop().time() + min(8, self.config.retransmit_initial*2**attempt,
                                                                  hard_deadline-time.monotonic())
                while True:
                    remaining = deadline-asyncio.get_running_loop().time()
                    if remaining <= 0:
                        break
                    try:
                        packet, encoded = await asyncio.wait_for(queue.get(), remaining)
                    except TimeoutError:
                        break
                    if time.monotonic() >= hard_deadline:
                        raise TunnelClosed("IKE SA hard lifetime expired while waiting for response")
                    if accept is None or accept(packet):
                        return packet, encoded
            raise VPNTimeout(f"IKE exchange {exchange}, message {mid}: no valid response after retries")
        finally:
            self.pending.pop(key, None)

    def deliver(self, packet, raw):
        queue = self.pending.get((packet.exchange, packet.message_id))
        if queue is None:
            return False
        if not queue.full():
            queue.put_nowait((packet, raw))
        return True
