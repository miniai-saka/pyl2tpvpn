import ipaddress
import struct
import pytest
from pyl2tpvpn.selectors import (Selector, address_selector, encode_selectors, parse_selectors,
                                check_narrowing, packet_allowed, configuration_reply)
from pyl2tpvpn.errors import ProtocolError
from pyl2tpvpn.network import Network
from pyl2tpvpn.ip import ipv4, udp


def test_selector_narrowing_and_port_direction():
    local=(address_selector('192.0.2.1'),)
    remote=(Selector(int(ipaddress.IPv4Address('198.51.100.1')),
                     int(ipaddress.IPv4Address('198.51.100.1')),6,443,443),)
    assert parse_selectors(encode_selectors(remote)) == remote
    check_narrowing(local,(Selector(),))
    with pytest.raises(ProtocolError):
        check_narrowing((Selector(),),local)
    assert packet_allowed(local,remote,'192.0.2.1','198.51.100.1',6,struct.pack('!HH',50000,443))
    assert packet_allowed(local,remote,'198.51.100.1','192.0.2.1',6,struct.pack('!HH',443,50000),True)
    assert not packet_allowed(local,remote,'192.0.2.1','198.51.100.1',6,struct.pack('!HH',50000,80))


@pytest.mark.parametrize('data',[b'',b'\0'*4,b'\x01\0\0\0',
    b'\x01\0\0\0'+struct.pack('!BBHHHII',7,0,16,0,65535,10,1)])
def test_malformed_selectors(data):
    with pytest.raises(ProtocolError):
        parse_selectors(data)


def test_configuration_reply_requires_one_usable_address():
    address=ipaddress.IPv4Address('192.0.2.1').packed
    dns=ipaddress.IPv4Address('192.0.2.53').packed
    field=lambda k,v:struct.pack('!HH',k,len(v))+v
    raw=b'\x02\0\0\0'+field(1,address)+field(3,dns)
    assert configuration_reply(raw) == ('192.0.2.1',('192.0.2.53',),None)
    for invalid in (b'',raw+field(1,address),raw[:-1],b'\x02\0\0\0'+field(1,b'\0'*4)):
        with pytest.raises(ProtocolError):
            configuration_reply(invalid)


def test_inner_policy_runs_on_outbound_and_reassembled_inbound():
    seen,sent=[],[]
    def policy(src,dst,proto,body,incoming):
        seen.append((incoming,len(body)))
        if not body.endswith(b'allowed'):
            raise ProtocolError('blocked')
    net=Network('192.0.2.1',sent.append,576,(),policy=policy)
    with pytest.raises(ProtocolError):
        net.send('192.0.2.2',17,b'blocked')
    assert not sent
    net.receive(ipv4('192.0.2.2','192.0.2.1',17,udp(53,50000,b'blocked')))
    assert net.stats['invalid'] == 1
    net.send('192.0.2.2',17,b'x'*600+b'allowed')
    assert len(sent) == 2
    assert seen[-1] == (False,607)
