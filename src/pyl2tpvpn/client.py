import asyncio
import logging
import secrets
import time
from .config import VPNConfig
from .errors import TunnelClosed, VPNError
from .ikev1 import IKEv1
from .l2tp import L2TP
from .ppp import PPP
from .transport import UDPLink
from .ip import udp, parse_udp
from .wire import need

log = logging.getLogger(__name__)


class VPNClient:
    """An async VPN session. Only sockets created through this object use it."""
    def __init__(self, config: VPNConfig):
        self.config = config
        self.link = UDPLink(config)
        self.ike = self.ppp = self.l2tp = self.network = None
        self.outbound = None
        self.active_inbound = None
        self.inbound = {}
        self.tasks = set()
        self.error = None
        self.connected = self.closed = False
        self._closing = False
        self.rekeys = {"ike": 0, "child": 0, "reauth": 0}
        self.failure_event = asyncio.Event()
        self.ready_event = asyncio.Event()
        self._refreshing = False
        self.ppp_task = None
        self._close_task = None

    def _fail(self, error):
        if self._closing or self.closed or self.error:
            return
        self.error = error if isinstance(error, Exception) else TunnelClosed("VPN task stopped")
        self.connected = False
        self.failure_event.set()
        self.ready_event.set()
        if self.network:
            self.network.close(self.error)
        log.error("VPN stopped: %s", self.error)

    def _task(self, coro):
        task = asyncio.create_task(coro)
        self.tasks.add(task)
        def done(t):
            self.tasks.discard(t)
            if not t.cancelled() and t.exception():
                self._fail(t.exception())
        task.add_done_callback(done)
        return task

    def _install(self, inbound, outbound):
        now = time.monotonic()
        # The previous outbound object is paired with the most recently installed
        # inbound SA, even when the new IKE object is still being authenticated.
        old_inbound = self.active_inbound
        # Peers may continue transmitting on a previous SA until its negotiated
        # hard expiry. Preserve its independent replay window until that time.
        for spi, (_, expires) in tuple(self.inbound.items()):
            if now >= expires:
                self.inbound.pop(spi, None)
        if len(self.inbound) >= 64:
            raise TunnelClosed("Too many overlapping IPsec SAs")
        self.inbound[inbound.spi] = (inbound, inbound.created+inbound.lifetime)
        self.outbound = outbound
        self.active_inbound = inbound
        self.rekeys["child"] += 1
        if old_inbound and self.ike:
            owner = self.ike
            delay = min(self.config.rekey_overlap,max(0.05,(old_inbound.created+old_inbound.lifetime-now)/2))
            async def retire_child():
                await asyncio.sleep(delay)
                if self.active_inbound and self.active_inbound.spi == old_inbound.spi:
                    return  # A simultaneous rekey can select this SA as winner.
                try:
                    await owner.delete_child(old_inbound.spi)
                except (VPNError, TimeoutError):
                    log.debug("Old CHILD SA delete was not acknowledged")
            self._task(retire_child())

    def _send_l2tp(self, payload):
        if self.error and not self._closing:
            raise self.error
        if not self.outbound:
            raise TunnelClosed("ESP is not established")
        datagram = udp(self.config.l2tp_port, self.config.l2tp_port, payload)
        self.link.send(self.outbound.seal(datagram), natt=True, ike=False)

    def _receive_esp(self, data):
        entry = self.inbound.get(data[:4])
        if not entry or time.monotonic() >= entry[1]:
            self.link.stats.setdefault("unknown_or_expired_spi", 0)
            self.link.stats["unknown_or_expired_spi"] += 1
            return
        try:
            nh, payload = entry[0].open(data)
            self.link.stats.setdefault("esp_received",0)
            self.link.stats["esp_received"] += 1
            if not self.config.uses_l2tp:
                need(nh == 4, "expected IPv4 ESP tunnel payload")
                if self.network:
                    self.network.receive(payload)
                self.link.last_received = time.monotonic()
                return
            need(nh == 17, "ESP payload must be L2TP/UDP")
            sp, dp, body = parse_udp(payload)
            need(sp == self.config.l2tp_port and dp == self.config.l2tp_port, "ESP UDP selector mismatch")
            self.link.last_received = time.monotonic()
            if self.l2tp:
                self.l2tp.receive(body)
        except VPNError:
            self.link.stats["invalid_packets"] += 1
            log.debug("Rejected ESP payload", exc_info=True)

    def _new_ike(self, *, start_natt=False):
        if self.config.ike_version == 2:
            from .ikev2 import IKEv2
            return IKEv2(self.link, self.config, self._install, self._fail)
        return IKEv1(self.link, self.config, self._install, self._fail, start_natt=start_natt)

    async def connect(self):
        if self.connected or self.closed or self.ike:
            raise RuntimeError("Create a new VPNClient for each connection")
        if not self.config.psk:
            raise ValueError("A nonempty pre-shared key is required")
        if self.config.uses_l2tp and not self.config.username:
            raise ValueError("L2TP requires a PPP username")
        try:
            async with asyncio.timeout(self.config.connect_timeout):
                await self.link.open()
                self.link.esp_receiver = self._receive_esp
                self.ike = self._new_ike()
                await self.ike.connect()
                if self.config.uses_l2tp:
                    await self._open_ppp()
                else:
                    from .network import Network
                    self.network=Network(self.ike.local_ip,self._send_tunnel_ip,self.config.mtu,
                                         self.config.dns_servers or self.ike.dns_servers,
                                         policy=self._tunnel_policy)
                self.connected = True
                self.ready_event.set()
                self._task(self._maintain())
                self._task(self._periodic(self.config.keepalive_interval, self._nat_keepalive))
                self._task(self._periodic(self.config.dpd_interval, self._dpd))
                if self.l2tp:
                    self._task(self._periodic(self.config.l2tp_hello_interval, self.l2tp.hello))
                    self._task(self._periodic(self.config.lcp_echo_interval, self.ppp.echo))
                return self
        except BaseException:
            await self.close()
            raise

    def _send_tunnel_ip(self, packet):
        if self.error and not self._closing:
            raise self.error
        need(self.outbound is not None, "IPsec is not established")
        self.link.send(self.outbound.seal(packet,4),natt=True,ike=False)

    def _tunnel_policy(self, src, dst, proto, body, incoming):
        from .selectors import packet_allowed
        local = dst if incoming else src
        need(local == self.ike.local_ip, "unexpected assigned IP address")
        need(packet_allowed(self.ike.ts_local, self.ike.ts_remote, src, dst, proto, body, incoming),
             "inner packet excluded by negotiated traffic selectors")

    async def _nat_keepalive(self):
        self.link.send(b"\xff", natt=True, ike=False)

    async def _dpd(self):
        if not self._refreshing:
            await self.ike.dpd()

    async def _periodic(self, interval, operation):
        while not self.closed and not self.error:
            await asyncio.sleep(interval)
            await operation()

    async def _open_ppp(self):
        self.l2tp = L2TP(self.config, self._send_l2tp, self._fail)
        self.ppp = PPP(self.config, self.l2tp.send_ppp, self._fail)
        self.l2tp.ppp_receive = self.ppp.receive
        await self.l2tp.connect()
        self.ppp_task = self._task(self.ppp.run())
        await asyncio.sleep(0)
        await self.ppp.ready
        if self.error:
            raise self.error
        from .network import Network
        self.network = Network(self.ppp.local_ip, self.ppp.send_ip,
                               min(self.config.mtu, self.ppp.peer_mru),
                               self.config.dns_servers or self.ppp.dns_servers)
        self.ppp.ip_receive = self.network.receive

    async def _reauthenticate_v1(self):
        old = self.ike
        old.retiring = True
        try:
            async with asyncio.timeout(self.config.connect_timeout):
                replacement = self._new_ike(start_natt=True)
                await replacement.connect()
                self.ike = replacement
            self.rekeys["ike"] += 1
            self.rekeys["reauth"] += 1
            self._task(self._retire_ike(old))
        except BaseException:
            old.retiring = False
            raise

    async def _reauthenticate_v2(self):
        # Some remote-access gateways release the CP lease when an old,
        # rekeyed IKE SA is deleted. A fresh AUTH obtains the lease again.
        # Keep the IP stack/streams only when the assigned address is stable.
        self._refreshing = True
        self.ready_event.clear()
        old, address = self.ike, self.local_ip
        try:
            await old.close()
            async with asyncio.timeout(self.config.connect_timeout):
                replacement = self._new_ike()
                await replacement.connect()
                if not self.config.uses_l2tp:
                    need(replacement.local_ip == address,
                         "IKEv2 reauthentication changed the assigned IP; reconnect required")
                    self.network.dns_servers = tuple(self.config.dns_servers or replacement.dns_servers)
                    self.network.dns_cache.clear()
                self.ike = replacement
            self.rekeys["ike"] += 1
            self.rekeys["reauth"] += 1
        finally:
            self._refreshing = False
            self.ready_event.set()

    async def _maintain(self):
        retry_at = 0
        while not self.closed and not self.error:
            await asyncio.sleep(0.25)
            now = time.monotonic()
            soft = 1-self.config.rekey_margin
            if getattr(self.ike, "successor", None):
                old = self.ike
                self.ike = old.successor
                self.rekeys["ike"] += 1
                self._task(self._retire_ike(old))
            if now < retry_at:
                continue
            try:
                await self._renew(now, soft)
            except Exception as error:
                from .ikev2 import TemporaryFailure
                if not isinstance(error, TemporaryFailure):
                    raise
                retry_at = time.monotonic()+1+secrets.randbelow(1000)/1000
            for spi, (_, expires) in tuple(self.inbound.items()):
                if now >= expires:
                    self.inbound.pop(spi, None)

    async def _renew(self, now, soft):
        if now-self.ike.created >= self.ike.ike_lifetime*soft:
            if isinstance(self.ike,IKEv1):
                await self._reauthenticate_v1()
                return
            if self.config.ikev2_renewal == "reauthenticate":
                await self._reauthenticate_v2()
                return
            # IKEv2 transfers existing child SAs to the newly keyed IKE SA.
            old = self.ike
            self.ike = await old.rekey_ike()
            self.rekeys["ike"] += 1
            self._task(self._retire_ike(old))
        if (now-self.outbound.created >= self.outbound.lifetime*soft or
                self.outbound.octets >= self.config.child_byte_limit*soft or self.outbound.sequence >= 0xffff0000):
            await self.ike.rekey_child()

    async def _retire_ike(self, session):
        await asyncio.sleep(self.config.rekey_overlap)
        # IKEv1 phase-1 renewal uses reauthentication. Some gateways remove all
        # transport SAs for a peer upon a phase-1 DELETE, including the new SA.
        # Let the old phase-1 SA expire at the gateway after removing it locally.
        try:
            async with asyncio.timeout(self.config.shutdown_timeout):
                await session.close(notify=not isinstance(session, IKEv1))
        except (VPNError, TimeoutError):
            await session.close(notify=False)
            log.debug("Old IKE SA delete was not acknowledged")

    def _check(self):
        if self.error:
            raise self.error
        if not self.connected or self.closed:
            raise TunnelClosed("VPN is not connected")

    async def _ready(self):
        if self._refreshing:
            await self.ready_event.wait()
        self._check()

    @property
    def local_ip(self):
        return self.ppp.local_ip if self.ppp else getattr(self.ike,"local_ip",None)

    async def open_connection(self, host, port, *, ssl=None, server_hostname=None, timeout=30):
        await self._ready()
        return await self.network.open_connection(host, port, ssl=ssl,
                    server_hostname=server_hostname, timeout=timeout)

    async def open_datagram(self, host, port):
        await self._ready()
        return await self.network.open_datagram(host, port)

    async def resolve(self, host, *, timeout=5):
        await self._ready()
        return await self.network.resolve(host, timeout=timeout)

    async def ping(self, host, *, timeout=5):
        await self._ready()
        return await self.network.ping(host, timeout=timeout)

    async def wait_closed(self):
        await self.failure_event.wait()
        if self.error:
            raise self.error

    async def close(self):
        if self.closed:
            return
        if self._close_task is None:
            self._close_task = asyncio.create_task(self._close())
        await asyncio.shield(self._close_task)

    async def _close(self):
        self._closing = True
        current = asyncio.current_task()
        tasks = [t for t in self.tasks if t is not current and t is not self.ppp_task]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if self.network:
            self.network.close(TunnelClosed("VPN closed"))
        try:
            if self.ppp:
                try:
                    await self.ppp.aclose()
                except (VPNError, TimeoutError):
                    log.debug("PPP termination was not acknowledged")
            if self.ppp_task:
                self.ppp_task.cancel()
                await asyncio.gather(self.ppp_task, return_exceptions=True)
            if self.l2tp:
                await self.l2tp.close()
        except Exception:
            log.debug("L2TP termination did not finish", exc_info=True)
        try:
            sessions = set(self.link.sessions.values())
            if self.ike:
                sessions.add(self.ike)
            if sessions:
                async def stop(session):
                    try:
                        async with asyncio.timeout(self.config.shutdown_timeout):
                            await session.close()
                    finally:
                        await session.close(notify=False)
                await asyncio.gather(*(stop(session) for session in sessions),return_exceptions=True)
        finally:
            try:
                await self.link.aclose()
            except (TimeoutError, OSError):
                self.link.close()
        self.inbound.clear()
        self.outbound = None
        self.active_inbound = None
        self.closed, self.connected, self._closing = True, False, False
        self.failure_event.set()
        self.ready_event.set()

    async def __aenter__(self):
        return await self.connect()

    async def __aexit__(self, *exc):
        await self.close()
