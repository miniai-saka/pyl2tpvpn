"""TLS over the userspace stream via stdlib SSLObject/MemoryBIO."""
import asyncio
import ssl as ssl_module
from .errors import TunnelClosed


class TLSStream:
    def __init__(self, reader, writer, context, server_hostname):
        self.reader, self.writer = reader, writer
        self.incoming, self.outgoing = ssl_module.MemoryBIO(), ssl_module.MemoryBIO()
        self.ssl = context.wrap_bio(self.incoming, self.outgoing, server_side=False, server_hostname=server_hostname)
        self.read_lock = asyncio.Lock()
        self.write_lock = asyncio.Lock()
        self.flush_lock = asyncio.Lock()
        self.io_read_lock = asyncio.Lock()
        self.buffer = bytearray()
        self.eof = self.closing = False

    async def _flush(self):
        async with self.flush_lock:
            while self.outgoing.pending:
                self.writer.write(self.outgoing.read())
            await self.writer.drain()

    async def _operate(self, method, *args):
        while True:
            try:
                result = method(*args)
                await self._flush()
                return result
            except ssl_module.SSLWantWriteError:
                await self._flush()
            except ssl_module.SSLWantReadError:
                await self._flush()
                async with self.io_read_lock:
                    data = await self.reader.read(16384)
                if not data:
                    self.incoming.write_eof()
                else:
                    self.incoming.write(data)
            except ssl_module.SSLZeroReturnError:
                self.eof = True
                return b""

    async def handshake(self):
        await self._operate(self.ssl.do_handshake)

    async def _read(self):
        async with self.read_lock:
            await self.drain()
            return await self._operate(self.ssl.read, 16384)

    async def read(self, n=-1):
        if n == 0:
            return b""
        if n < 0:
            pieces = [bytes(self.buffer)]
            self.buffer.clear()
            while not self.eof:
                data = await self._read()
                if not data:
                    self.eof = True
                    break
                pieces.append(data)
            return b"".join(pieces)
        if not self.buffer and not self.eof:
            data = await self._read()
            if not data:
                self.eof = True
            self.buffer.extend(data)
        data = bytes(self.buffer[:n])
        del self.buffer[:n]
        return data

    async def readexactly(self, n):
        pieces = bytearray()
        while len(pieces) < n:
            data = await self.read(n-len(pieces))
            if not data:
                raise asyncio.IncompleteReadError(bytes(pieces), n)
            pieces.extend(data)
        return bytes(pieces)

    async def readuntil(self, separator=b"\n"):
        out = bytearray()
        while not out.endswith(separator):
            out.extend(await self.readexactly(1))
            if len(out) > 262144:
                raise asyncio.LimitOverrunError("TLS line too long", len(out))
        return bytes(out)

    async def readline(self):
        try:
            return await self.readuntil()
        except asyncio.IncompleteReadError as e:
            return e.partial

    def at_eof(self):
        return self.eof and not self.buffer

    def write(self, data):
        if self.closing:
            raise TunnelClosed("TLS stream is closing")
        if not hasattr(self, "write_buffer"):
            self.write_buffer = bytearray()
        if len(self.write_buffer)+len(data) > 4*1024*1024:
            raise BufferError("TLS write buffer full; await drain()")
        self.write_buffer.extend(data)

    async def _drain(self):
        data = bytes(getattr(self, "write_buffer", b""))
        self.write_buffer = bytearray()
        offset = 0
        while offset < len(data):
            offset += await self._operate(self.ssl.write, data[offset:offset+16384])

    async def drain(self):
        async with self.write_lock:
            await self._drain()

    def close(self):
        self.closing = True
        self.writer.close()

    async def wait_closed(self):
        await self.writer.wait_closed()

    def is_closing(self):
        return self.closing

    def can_write_eof(self):
        return False

    def get_extra_info(self, name, default=None):
        if name == "ssl_object":
            return self.ssl
        return self.writer.get_extra_info(name, default)
