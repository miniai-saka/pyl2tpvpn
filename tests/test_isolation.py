import asyncio
import pytest
from pyl2tpvpn.network import Network
from pyl2tpvpn.errors import NegotiationError,TunnelClosed,AuthenticationError
from pyl2tpvpn.transport import Exchanges
from pyl2tpvpn.wire import IKEPacket
from pyl2tpvpn.config import VPNConfig


def test_application_dns_has_no_system_fallback(monkeypatch):
    async def run():
        def forbidden(*a,**kw):
            raise AssertionError('Application DNS attempted the host resolver')
        monkeypatch.setattr('socket.getaddrinfo',forbidden)
        sent=[]
        net=Network('192.0.2.1',sent.append,1360,())
        with pytest.raises(NegotiationError):
            await net.resolve('unresolvable.example')
        assert not sent
        channel=await net.open_datagram('192.0.2.2',53)
        channel.send(b'query')
        assert len(sent) == 1 and sent[0][9] == 17
        net.close()
        with pytest.raises(TunnelClosed):
            await channel.recv()
    asyncio.run(run())


def test_expired_ike_keys_do_not_transmit():
    async def run():
        sent=[]
        class Link:
            def send(self,*a,**kw):
                sent.append(a)
        exchange=Exchanges(Link(),VPNConfig('peer',psk='test'))
        exchange.established=True
        exchange.created=0
        exchange.ike_lifetime=1
        with pytest.raises(TunnelClosed):
            await exchange.request(b'expired',37,0)
        assert not sent and not exchange.pending
    asyncio.run(run())


def test_ike_retransmission_reuses_identical_bytes():
    async def run():
        sent=[]
        class Link:
            def send(self,raw,*,natt=True):
                sent.append(raw)
                if len(sent) == 3:
                    p=IKEPacket(b'i'*8,b'r'*8,0,0x10,32,1,7,b'')
                    exchange.deliver(p,p.encode())
        c=VPNConfig('server','u','p','secret',retransmit_initial=.01,retransmit_attempts=3)
        exchange=Exchanges(Link(),c)
        packet,raw=await exchange.request(b'fixed encrypted exchange',32,7)
        assert packet.message_id == 7 and len(sent) == 3 and len(set(sent)) == 1
    asyncio.run(run())
