import asyncio
from pyl2tpvpn.proxy import start_socks_proxy


def test_socks_name_is_resolved_by_vpn_and_authenticated():
    async def run():
        calls=[]
        remote_reader=asyncio.StreamReader()
        remote_reader.feed_data(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK')
        remote_reader.feed_eof()
        class Writer:
            def write(self,data):
                calls.append(('data',data))
            async def drain(self):
                pass
            def close(self):
                pass
            def can_write_eof(self):
                return True
            def write_eof(self):
                pass
            def get_extra_info(self,name):
                return ('192.0.2.1',50000)
        class VPN:
            async def open_connection(self,host,port):
                calls.append(('connect',host,port))
                return remote_reader,Writer()
        async with await start_socks_proxy(VPN(),port=0,username='user',password='pass') as proxy:
            reader,writer=await asyncio.open_connection('127.0.0.1',proxy.sockets[0].getsockname()[1])
            writer.write(b'\x05\x01\x02')
            assert await reader.readexactly(2) == b'\x05\x02'
            writer.write(b'\x01\x04user\x04pass')
            assert await reader.readexactly(2) == b'\x01\0'
            name=b'example.test'
            writer.write(b'\x05\x01\0\x03'+bytes([len(name)])+name+b'\0\x50')
            assert (await reader.readexactly(10))[:2] == b'\x05\0'
            writer.write(b'GET / HTTP/1.0\r\n\r\n')
            writer.write_eof()
            body=await asyncio.wait_for(reader.read(),2)
            assert body.endswith(b'OK') and ('connect','example.test',80) in calls
            writer.close()
            await writer.wait_closed()
    asyncio.run(run())
