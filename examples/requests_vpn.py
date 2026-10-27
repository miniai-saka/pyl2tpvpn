"""Synchronous Requests through this VPN; no global network changes."""
import getpass
import os
from pyl2tpvpn import VPNConfig
from pyl2tpvpn.runtime import VPNRuntime
from pyl2tpvpn.console import make_requests_session


def main():
    config=VPNConfig(
        server=os.environ['VPN_SERVER'],
        ike_version=2,
        local_id=os.environ['VPN_LOCAL_ID'],
        remote_id=os.environ['VPN_REMOTE_ID'],
        psk=os.getenv('VPN_PSK') or getpass.getpass('PSK: '),
        mtu=1280,
    )
    runtime=VPNRuntime(config)
    try:
        runtime.connect()
        with make_requests_session(runtime.request_route()) as session:
            response=session.get('https://example.com/',timeout=20)
            print(response.status_code,response.text)
    finally:
        runtime.close()


if __name__ == '__main__':
    main()
