"""Cross-check key schedules/authentication against qwj/python-vpn fixtures."""
import asyncio
import io
import struct
from types import SimpleNamespace
import pytest
from pyl2tpvpn.config import VPNConfig
from pyl2tpvpn.ikev1 import IKEv1
from pyl2tpvpn.ikev2 import IKEv2
from pyl2tpvpn.wire import IKEPacket
from reference_pvpn import server,message,enums


class ReferenceLink:
    def __init__(self, version, config):
        self.version,self.config = version,config
        self.local_ip,self.peer,self.local_port = '192.0.2.1','192.0.2.2',50000
        self.sessions,self.peer_sessions = {},{}
        self.last_received = 0
        self.packets=[]
        self.last_peer=None

    def send(self, raw, *, natt=True, ike=True):
        if not ike:
            return
        self.packets.append(raw)
        stream=io.BytesIO(raw)
        request=message.Message.parse(stream)
        peer=self.peer_sessions.get(request.spi_r)
        if peer is None:
            cls=server.IKEv1Session if self.version == 1 else server.IKEv2Session
            peer=cls(SimpleNamespace(passwd=self.config.psk,dns='192.0.2.53'),self.peer_sessions,request.spi_i)
            if self.version == 2 and self.config.uses_l2tp:
                original=peer.response
                def response(exchange,payloads,*,crypto=None):
                    if exchange in (enums.Exchange.IKE_AUTH,enums.Exchange.CREATE_CHILD_SA):
                        payloads=payloads+[message.PayloadNOTIFY(0,enums.Notify.USE_TRANSPORT_MODE,b'',b'')]
                    return original(exchange,payloads,crypto=crypto)
                peer.response=response
        self.last_peer=peer
        def reply(encoded):
            packet=IKEPacket.parse(encoded)
            client=self.sessions.get(packet.initiator)
            if client:
                asyncio.get_running_loop().call_soon(client.receive,packet,encoded,natt)
        peer.process(request,stream,(self.local_ip,self.local_port),reply)


@pytest.mark.parametrize('version',[1,2])
def test_reference_handshake_child_rekey_and_liveness(version):
    async def run():
        config=VPNConfig('peer','user','password','test-secret',aes_bits=(128,),dh_groups=(14,),
                         retransmit_initial=.05,retransmit_attempts=2,ike_version=version,data_mode='l2tp')
        link=ReferenceLink(version,config)
        installed=[]
        failures=[]
        cls=IKEv1 if version == 1 else IKEv2
        client=cls(link,config,lambda a,b:installed.append((a,b)),failures.append)
        try:
            await client.connect()
            assert len(installed) == 1
            incoming,outgoing=installed[-1]
            child=link.last_peer.child_sa[-1]
            raw=outgoing.seal(b'packet sent by the Python client')
            child.crypto_in.verify_checksum(raw)
            assert child.crypto_in.decrypt_esp(raw[8:]) == (17,b'packet sent by the Python client')
            # A 14-byte payload needs no ESP padding; the reference server emits
            # zero padding, whereas this client validates the RFC 4303 pattern.
            response=bytearray(child.spi_out+struct.pack('!I',1)+child.crypto_out.encrypt_esp(17,b'peer response!'))
            child.crypto_out.add_checksum(response)
            assert incoming.open(bytes(response)) == (17,b'peer response!')
            old_spi=incoming.spi
            await client.rekey_child()
            assert len(installed) == 2 and installed[-1][0].spi != old_spi
            await client.dpd()
            assert not failures
            if version == 2:
                replacement=await client.rekey_ike()
                try:
                    assert replacement.sk_d != client.sk_d and replacement.ci != client.ci
                    await replacement.dpd()
                    await replacement.rekey_child()
                    assert len(installed) == 3
                finally:
                    await replacement.close()
        finally:
            await client.close()
    asyncio.run(run())


def test_reference_native_ikev2_address_dns_and_rekey():
    async def run():
        config=VPNConfig('peer',psk='test-secret',ike_version=2,dh_groups=(14,),aes_bits=(128,))
        link=ReferenceLink(2,config)
        installed,failures=[],[]
        client=IKEv2(link,config,lambda a,b:installed.append((a,b)),failures.append)
        try:
            await client.connect()
            assert not config.uses_l2tp
            assert client.local_ip == '1.0.0.1' and client.dns_servers == ('192.0.2.53',)
            await client.rekey_child()
            replacement=await client.rekey_ike()
            assert replacement.local_ip == client.local_ip
            await client.close()
            await replacement.rekey_child()
            assert not failures
            await replacement.close()
        finally:
            await client.close(notify=False)
    asyncio.run(run())
