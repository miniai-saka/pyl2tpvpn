import asyncio
import struct
from pyl2tpvpn import VPNConfig
from pyl2tpvpn.l2tp import L2TP, parse_packet
from pyl2tpvpn.ppp import PPP, LCP


def test_stopccn_retransmits_and_waits_for_ack():
    async def run():
        sent=[]
        def send(raw):
            sent.append(raw)
            if len(sent) == 2:
                *_,ns,nr,body = parse_packet(raw)
                tunnel.receive(struct.pack('!HHHHHH',0xc802,12,tunnel.tunnel_id,0,0,(ns+1)&65535))
        config=VPNConfig('peer',psk='test',retransmit_initial=.01)
        tunnel=L2TP(config,send,lambda e:None)
        tunnel.peer_tunnel=123
        await tunnel.close()
        assert len(sent) == 2 and sent[0] == sent[1] and tunnel.closed
    asyncio.run(run())


def test_ppp_terminate_waits_for_matching_ack():
    async def run():
        sent=[]
        def send(raw):
            sent.append(raw)
            proto,code,mid,length=struct.unpack('!HBBH',raw[2:8])
            assert proto == LCP and code == 5
            peer._handle(b'\xff\x03'+struct.pack('!HBBH',LCP,6,(mid+1)&255,4))
            assert not peer.terminate_waiter.done()
            peer._handle(b'\xff\x03'+struct.pack('!HBBH',LCP,6,mid,4))
        peer=PPP(VPNConfig('peer',psk='test'),send,lambda e:None)
        peer.lcp_local=peer.started=True
        await peer.aclose()
        assert peer.closed and len(sent) == 1
    asyncio.run(run())
