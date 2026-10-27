import hashlib
import hmac
import struct
import time
import pytest
from pyl2tpvpn.crypto import (AH, ESP, DH, ReplayWindow, PRIMES, mschapv2_response,
                              mschapv2_authenticator, nt_password_hash, expand, prf)
from pyl2tpvpn.errors import ProtocolError,AuthenticationError,TunnelClosed
from pyl2tpvpn.ip import ipv4,udp,parse_ipv4


def test_rfc2759_section_9_vector():
    auth = bytes.fromhex('5B5D7C7D7B3F2F3E3C2C602132262628')
    peer = bytes.fromhex('21402324255E262A28295F2B3A337C7E')
    assert nt_password_hash('clientPass').hex().upper() == '44EBBA8D5312B8D611474411F56989AE'
    response = mschapv2_response(auth,peer,'User','clientPass')
    assert response.hex().upper() == '82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF'
    assert mschapv2_response(auth,peer,'DOMAIN\\User','clientPass') == response
    assert mschapv2_authenticator(auth,peer,'User','clientPass',response) == b'S=407A5589115FD0D6209F510FE9C04566932CDA56'


@pytest.mark.parametrize('group,bits', [(2,1024),(5,1536),(14,2048)])
def test_dh_sizes_and_subgroup_validation(group,bits):
    assert PRIMES[group].bit_length() == bits
    a,b = DH(group),DH(group)
    assert a.shared(b.public) == b.shared(a.public)
    for value in (0,1,PRIMES[group]-1):
        with pytest.raises(ProtocolError):
            a.shared(value.to_bytes(a.size,'big'))


def test_replay_window_order_and_window_edges():
    w = ReplayWindow(64)
    for value in (3,1,2,66,65):
        w.commit(value)
    for value in (0,1,2,3,65,66):
        with pytest.raises(ProtocolError):
            w.commit(value)
    w.commit(100000)
    w.commit(99999)
    assert w.bitmap == 3


@pytest.mark.parametrize('size',[0,1,14,15,16,31,32,1400])
def test_esp_authentication_before_replay_commit(size):
    tx = ESP(b'SPI!',b'k'*16,b'a'*20)
    rx = ESP(b'SPI!',b'k'*16,b'a'*20)
    plain = bytes(i%256 for i in range(size))
    raw = tx.seal(plain)
    bad = bytearray(raw)
    bad[25] ^= 1
    with pytest.raises(AuthenticationError):
        rx.open(bytes(bad))
    assert rx.replay.high == 0
    assert rx.open(raw) == (17,plain)
    with pytest.raises(ProtocolError):
        rx.open(raw)


def test_esp_hard_limits():
    sa = ESP(b'SPI!',b'k'*16,b'a'*20,lifetime=0.01)
    sa.created -= 1
    with pytest.raises(TunnelClosed):
        sa.seal(b'payload')
    sa = ESP(b'SPI!',b'k'*16,b'a'*20)
    sa.sequence = 0xfffffffe
    with pytest.raises(TunnelClosed):
        sa.seal(b'payload')


def test_esp_scapy_interoperability_both_directions():
    from scapy.layers.inet import IP,UDP
    from scapy.layers.ipsec import ESP as ScapyESP,SecurityAssociation
    spi = 0x10203040
    ours = ESP(struct.pack('!I',spi),b'k'*16,b'a'*20)
    peer = SecurityAssociation(ScapyESP,spi=spi,crypt_algo='AES-CBC',crypt_key=b'k'*16,
                               auth_algo='HMAC-SHA1-96',auth_key=b'a'*20)
    payload = udp(1701,1701,b'hello')
    packet = IP(src='192.0.2.1',dst='192.0.2.2',proto=50)/ScapyESP(ours.seal(payload))
    clear = peer.decrypt(packet)
    assert bytes(clear.payload) == payload
    inbound = peer.encrypt(IP(src='192.0.2.2',dst='192.0.2.1')/UDP(sport=1701,dport=1701)/b'reply')
    rx = ESP(struct.pack('!I',spi),b'k'*16,b'a'*20)
    nh,body = rx.open(bytes(inbound[ScapyESP]))
    assert nh == 17 and body[8:] == b'reply'


def test_ah_scapy_interoperability_and_mutable_fields():
    from scapy.layers.inet import IP,UDP
    from scapy.layers.ipsec import AH as ScapyAH,SecurityAssociation
    raw = ipv4('192.0.2.1','192.0.2.2',17,udp(1234,80,b'hello'))
    ours = AH(b'SPI!',b'a'*20)
    peer = SecurityAssociation(ScapyAH,spi=int.from_bytes(b'SPI!','big'),auth_algo='HMAC-SHA1-96',auth_key=b'a'*20)
    secured = ours.seal(raw)
    assert bytes(peer.decrypt(IP(secured)).payload) == raw[20:]
    secured2 = bytes(peer.encrypt(IP(raw)))
    rx = AH(b'SPI!',b'a'*20)
    assert rx.open(secured2)[20:] == raw[20:]
    mutable = bytearray(ours.seal(raw))
    mutable[8] = 30
    assert rx.open(bytes(mutable))[20:] == raw[20:]
    modified = bytearray(ours.seal(raw))
    modified[-1] ^= 1
    with pytest.raises(AuthenticationError):
        rx.open(bytes(modified))


def test_prf_expansions_against_explicit_formula():
    key,seed = b'key',b'seed'
    k1 = hmac.digest(key,seed,'sha1')
    k2 = hmac.digest(key,k1+seed,'sha1')
    assert expand(key,seed,32) == (k1+k2)[:32]
    t1 = hmac.digest(key,seed+b'\x01','sha1')
    t2 = hmac.digest(key,t1+seed+b'\x02','sha1')
    assert expand(key,seed,32,counters=True) == (t1+t2)[:32]
