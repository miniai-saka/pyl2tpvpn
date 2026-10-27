import argparse
import asyncio
import getpass
import json
import logging
import os
import sys
from pathlib import Path
from .client import VPNClient
from .config import VPNConfig
from .proxy import start_socks_proxy


async def run(args, config):
    async with VPNClient(config) as vpn:
        if args.command == "socks":
            async with await start_socks_proxy(vpn,port=args.port) as proxy:
                print(f"SOCKS5: socks5h://127.0.0.1:{proxy.sockets[0].getsockname()[1]}",flush=True)
                await vpn.wait_closed()
        else:
            addresses = await vpn.resolve(args.test_host)
            reader,writer = await vpn.open_connection(args.test_host,443,ssl=True)
            try:
                writer.write(f"GET / HTTP/1.1\r\nHost: {args.test_host}\r\nConnection: close\r\n\r\n".encode("ascii"))
                await writer.drain()
                async with asyncio.timeout(30):
                    line = await reader.readline()
                report = dict(server=config.server,ike_version=config.ike_version,
                              local_ip=vpn.local_ip,ppp_auth=vpn.ppp.auth_method if vpn.ppp else None,
                              data_mode="l2tp" if config.uses_l2tp else "tunnel",dns_servers=vpn.network.dns_servers,
                              test_host=args.test_host,resolved=addresses,https_status=line.decode("ascii").strip(),
                              rekeys=vpn.rekeys,statistics=vpn.link.stats)
                if args.report:
                    Path(args.report).write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
                print(json.dumps(report,ensure_ascii=False,indent=2))
            finally:
                writer.close()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "console":
        from .console import main as console_main
        raise SystemExit(console_main(sys.argv[2:]))
    parser=argparse.ArgumentParser(description="Python専用のL2TP/IPsec VPNクライアント",
        epilog="対話型コンソール: python -m pyl2tpvpn console --help")
    parser.add_argument("command",choices=("check","socks"))
    parser.add_argument("--server",default=os.getenv("VPN_SERVER"))
    parser.add_argument("--username",default=os.getenv("VPN_USERNAME"))
    parser.add_argument("--ike-version",type=int,choices=(1,2),default=1)
    parser.add_argument("--data-mode",choices=("auto","l2tp","tunnel"),default="auto")
    parser.add_argument("--local-id",default=os.getenv("VPN_LOCAL_ID"))
    parser.add_argument("--remote-id",default=os.getenv("VPN_REMOTE_ID"))
    parser.add_argument("--request-remote-id",action="store_true")
    parser.add_argument("--ikev2-renewal",choices=("rekey","reauthenticate"),default="rekey")
    parser.add_argument("--mtu",type=int,default=1280)
    parser.add_argument("--dns",action="append",default=[])
    parser.add_argument("--port",type=int,default=1080,help="loopback SOCKS port")
    parser.add_argument("--test-host",default="example.com")
    parser.add_argument("--report",help="save a report without credentials or keys")
    parser.add_argument("--verbose",action="store_true")
    args=parser.parse_args()
    uses_l2tp=args.data_mode == "l2tp" or (args.data_mode == "auto" and args.ike_version == 1)
    if not args.server or (uses_l2tp and not args.username):
        parser.error("--server と、L2TPの場合は --username が必要です（環境変数での指定も可能）")
    password=os.getenv("VPN_PASSWORD")
    psk=os.getenv("VPN_PSK")
    if uses_l2tp and password is None:
        password=getpass.getpass("PPP password: ")
    if psk is None:
        psk=getpass.getpass("IPsec pre-shared key: ")
    config=VPNConfig(args.server,args.username or "",password or "",psk,ike_version=args.ike_version,
                     local_id=args.local_id,remote_id=args.remote_id,data_mode=args.data_mode,
                     request_remote_id=args.request_remote_id,ikev2_renewal=args.ikev2_renewal,
                     mtu=args.mtu,dns_servers=tuple(args.dns))
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)
    try:
        asyncio.run(run(args,config))
    except KeyboardInterrupt:
        pass
    except Exception as error:
        parser.exit(1,f"{type(error).__name__}: {error}\n")


if __name__ == "__main__":
    main()
