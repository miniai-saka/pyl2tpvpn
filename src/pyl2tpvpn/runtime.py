"""Keep VPN I/O running while a synchronous application waits for user input."""
import asyncio
import secrets
import threading
from .client import VPNClient
from .proxy import start_socks_proxy
from .errors import TunnelClosed


class VPNRuntime:
    def __init__(self, config):
        self.config = config
        self.vpn = self.proxy = self.loop = None
        self.proxy_url = None
        self.generation = 0
        self._started = threading.Event()
        self._startup_error = None
        self._stopped = False
        self.thread = threading.Thread(target=self._run, name="pyl2tpvpn-io", daemon=True)
        self.thread.start()
        if not self._started.wait(15):
            raise TimeoutError("VPN event loop could not start")
        if self._startup_error:
            raise self._startup_error

    def _run(self):
        try:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
        except BaseException as error:
            self._startup_error = error
            self._started.set()
            return
        self._started.set()
        try:
            self.loop.run_forever()
        finally:
            tasks = asyncio.all_tasks(self.loop)
            for task in tasks:
                task.cancel()
            if tasks:
                self.loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
            self.loop.run_until_complete(self.loop.shutdown_asyncgens())
            self.loop.close()

    def call(self, coroutine, timeout=15):
        if self._stopped or not self.thread.is_alive():
            coroutine.close()
            raise TunnelClosed("VPN runtime has stopped")
        future = asyncio.run_coroutine_threadsafe(coroutine, self.loop)
        try:
            return future.result(timeout)
        except BaseException:
            future.cancel()
            raise

    async def _connect(self):
        await self._disconnect()
        vpn = VPNClient(self.config)
        try:
            await vpn.connect()
            # The listener belongs to this console and uses ephemeral credentials.
            username, password = secrets.token_hex(16), secrets.token_hex(24)
            proxy = await start_socks_proxy(vpn, port=0, username=username, password=password)
        except BaseException:
            await vpn.close()
            raise
        self.vpn, self.proxy = vpn, proxy
        port = proxy.sockets[0].getsockname()[1]
        self.proxy_url = f"socks5h://{username}:{password}@127.0.0.1:{port}"
        self.generation += 1
        return await self._status()

    def connect(self):
        return self.call(self._connect(), self.config.connect_timeout+3*self.config.shutdown_timeout+10)

    async def _disconnect(self):
        proxy, vpn = self.proxy, self.vpn
        self.proxy = self.vpn = self.proxy_url = None
        try:
            if proxy:
                await proxy.close()
        finally:
            if vpn:
                await vpn.close()

    def disconnect(self):
        return self.call(self._disconnect(), 4*self.config.shutdown_timeout+5)

    async def _status(self):
        vpn = self.vpn
        if not vpn:
            return dict(state="disconnected", server=self.config.server, generation=self.generation)
        state = "failed" if vpn.error else "refreshing" if vpn._refreshing else "connected" if vpn.connected else "disconnected"
        return dict(state=state, server=self.config.server, peer_ip=vpn.link.peer,
                    local_ip=vpn.local_ip, dns_servers=tuple(vpn.network.dns_servers) if vpn.network else (),
                    ike_version=self.config.ike_version, rekeys=dict(vpn.rekeys),
                    data_mode="l2tp" if self.config.uses_l2tp else "tunnel",
                    ikev2_renewal=self.config.ikev2_renewal,
                    transport=dict(vpn.link.stats), network=dict(vpn.network.stats) if vpn.network else {},
                    error=str(vpn.error) if vpn.error else None, generation=self.generation,
                    proxy_port=self.proxy.sockets[0].getsockname()[1] if self.proxy else None)

    def status(self):
        return self.call(self._status())

    async def _request_route(self):
        if not self.vpn or not self.proxy:
            raise TunnelClosed("VPN is disconnected; use connect")
        await self.vpn._ready()
        return self.proxy_url

    def request_route(self):
        return self.call(self._request_route(), self.config.connect_timeout+10)

    async def _resolve(self, host):
        if not self.vpn:
            raise TunnelClosed("VPN is disconnected; use connect")
        return await self.vpn.resolve(host)

    def resolve(self, host):
        return self.call(self._resolve(host), self.config.connect_timeout+25)

    async def _ping(self, host):
        if not self.vpn:
            raise TunnelClosed("VPN is disconnected; use connect")
        return await self.vpn.ping(host)

    def ping(self, host):
        return self.call(self._ping(host), self.config.connect_timeout+15)

    def close(self):
        if self._stopped:
            return
        try:
            self.disconnect()
        finally:
            self._stopped = True
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.thread.join(10)
