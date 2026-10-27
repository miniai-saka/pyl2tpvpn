"""Optional loopback SOCKS5 CONNECT server; names resolve inside the VPN."""
import asyncio
import hmac
import ipaddress
import struct
from .errors import VPNError


async def start_socks_proxy(vpn, host="127.0.0.1", port=1080, *, username=None, password=None):
    if not ipaddress.ip_address(host).is_loopback:
        raise ValueError("The SOCKS proxy must listen on a loopback address")
    if (username is None) != (password is None):
        raise ValueError("Provide both proxy username and password")
    sessions = set()

    async def handle(reader, writer):
        task = asyncio.current_task()
        sessions.add(task)
        remote_writer = None
        copies = []
        try:
            async with asyncio.timeout(15):
                version, count = await reader.readexactly(2)
                if version != 5 or count == 0:
                    return
                methods = await reader.readexactly(count)
                method = 2 if username is not None else 0
                if method not in methods:
                    writer.write(b"\x05\xff")
                    await writer.drain()
                    return
                writer.write(bytes([5,method]))
                await writer.drain()
                if method == 2:
                    auth_version, length = await reader.readexactly(2)
                    user = await reader.readexactly(length)
                    length = (await reader.readexactly(1))[0]
                    secret = await reader.readexactly(length)
                    ok = (auth_version == 1 and hmac.compare_digest(user,username.encode()) and
                          hmac.compare_digest(secret,password.encode()))
                    writer.write(b"\x01\0" if ok else b"\x01\x01")
                    await writer.drain()
                    if not ok:
                        return
                version, command, reserved, atyp = await reader.readexactly(4)
                if version != 5 or reserved != 0:
                    return
                if atyp == 1:
                    destination = str(ipaddress.ip_address(await reader.readexactly(4)))
                elif atyp == 3:
                    length = (await reader.readexactly(1))[0]
                    destination = (await reader.readexactly(length)).decode("ascii")
                else:
                    writer.write(b"\x05\x08\0\x01"+b"\0"*6)
                    await writer.drain()
                    return
                destination_port = int.from_bytes(await reader.readexactly(2),"big")
                if command != 1:
                    writer.write(b"\x05\x07\0\x01"+b"\0"*6)
                    await writer.drain()
                    return
            try:
                remote_reader,remote_writer = await vpn.open_connection(destination,destination_port)
            except (VPNError,OSError,TimeoutError):
                writer.write(b"\x05\x05\0\x01"+b"\0"*6)
                await writer.drain()
                return
            local = remote_writer.get_extra_info("sockname")
            writer.write(b"\x05\0\0\x01"+ipaddress.ip_address(local[0]).packed+struct.pack("!H",local[1]))
            await writer.drain()
            async def copy(source,target):
                while data := await source.read(32768):
                    target.write(data)
                    await target.drain()
                if target.can_write_eof():
                    target.write_eof()
            copies = [asyncio.create_task(copy(reader,remote_writer)),asyncio.create_task(copy(remote_reader,writer))]
            _,pending = await asyncio.wait(copies,return_when=asyncio.FIRST_COMPLETED)
            if pending:
                try:
                    await asyncio.wait_for(asyncio.gather(*pending),5)
                except (TimeoutError,ConnectionError,VPNError):
                    pass
        except (asyncio.IncompleteReadError,TimeoutError,OSError,VPNError,UnicodeError):
            pass
        finally:
            for copy in copies:
                copy.cancel()
            if copies:
                await asyncio.gather(*copies,return_exceptions=True)
            if remote_writer:
                remote_writer.close()
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            sessions.discard(task)

    server = await asyncio.start_server(handle,host,port)
    return SocksProxy(server,sessions)


class SocksProxy:
    def __init__(self, server, sessions):
        self.server,self.sessions = server,sessions

    @property
    def sockets(self):
        return self.server.sockets

    async def close(self):
        self.server.close()
        await self.server.wait_closed()
        for task in tuple(self.sessions):
            task.cancel()
        if self.sessions:
            await asyncio.gather(*tuple(self.sessions),return_exceptions=True)

    async def __aenter__(self):
        return self

    async def __aexit__(self,*exc):
        await self.close()
