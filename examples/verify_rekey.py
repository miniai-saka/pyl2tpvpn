"""Short-lifetime integration check. Uses credentials only from environment.

Example: python examples/verify_rekey.py --duration 45 --ike-lifetime 20
Each request opens a fresh stream; use a keep-alive application to test
persistent streams. Accelerated lifetimes should only be used in testing.
"""
import argparse
import asyncio
import json
import os
import time
from pyl2tpvpn import VPNClient, VPNConfig


async def main(args):
    config = VPNConfig(
        server=os.environ["VPN_SERVER"], username=os.getenv("VPN_USERNAME", ""),
        password=os.getenv("VPN_PASSWORD", ""), psk=os.environ["VPN_PSK"],
        ike_version=args.ike_version, local_id=os.getenv("VPN_LOCAL_ID"),
        remote_id=os.getenv("VPN_REMOTE_ID"), ikev2_renewal=args.ikev2_renewal,
        mtu=1280,
        child_lifetime=12, ike_lifetime=args.ike_lifetime,
        rekey_margin=0.3, rekey_overlap=2, keepalive_interval=3,
        dpd_interval=4, l2tp_hello_interval=4, lcp_echo_interval=4,
    )
    async with VPNClient(config) as vpn:
        start, count = time.monotonic(), 0
        while time.monotonic()-start < args.duration:
            reader, writer = await vpn.open_connection("example.com", 443, ssl=True)
            try:
                writer.write(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
                await writer.drain()
                async with asyncio.timeout(15):
                    response = await reader.read()
                if not response.startswith(b"HTTP/1.1 200"):
                    raise RuntimeError("HTTPS verification did not return 200")
                count += 1
            finally:
                writer.close()
            await asyncio.sleep(1)
        print(json.dumps({"https_requests": count, "rekeys": vpn.rekeys,
                          "transport": vpn.link.stats}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=float, default=45)
    parser.add_argument("--ike-lifetime", type=float, default=28800)
    parser.add_argument("--ike-version", type=int, choices=(1,2), default=1)
    parser.add_argument("--ikev2-renewal", choices=("rekey","reauthenticate"), default="rekey")
    asyncio.run(main(parser.parse_args()))
