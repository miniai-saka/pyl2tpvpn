"""Send one datagram to your own UDP Echo server through L2TP/IPsec."""
import asyncio
import getpass
import os
from pyl2tpvpn import VPNClient, VPNConfig


async def main():
    config = VPNConfig(
        server=os.environ["VPN_SERVER"],
        username=os.environ["VPN_USERNAME"],
        password=os.getenv("VPN_PASSWORD") or getpass.getpass("PPP password: "),
        psk=os.getenv("VPN_PSK") or getpass.getpass("PSK: "),
    )
    host = os.environ["VPN_UDP_HOST"]
    port = int(os.environ["VPN_UDP_PORT"])
    async with VPNClient(config) as vpn:
        async with asyncio.timeout(10):
            channel = await vpn.open_datagram(host, port)
        try:
            channel.send(b"hello")
            print(await channel.recv(timeout=5))
        finally:
            channel.close()


if __name__ == "__main__":
    asyncio.run(main())
