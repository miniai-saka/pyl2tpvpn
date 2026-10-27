import asyncio
import os
from pyl2tpvpn import VPNClient, VPNConfig


async def main():
    config = VPNConfig(
        server=os.environ["VPN_SERVER"],
        username=os.environ["VPN_USERNAME"],
        password=os.environ["VPN_PASSWORD"],
        psk=os.environ["VPN_PSK"],
    )
    async with VPNClient(config) as vpn:
        print("VPN address:", vpn.local_ip)
        print("VPN DNS:", await vpn.resolve("example.com"))
        reader, writer = await vpn.open_connection("example.com", 443, ssl=True)
        try:
            writer.write(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
            await writer.drain()
            async with asyncio.timeout(30):
                print((await reader.read()).decode("utf-8", errors="replace"))
        finally:
            writer.close()


if __name__ == "__main__":
    asyncio.run(main())
