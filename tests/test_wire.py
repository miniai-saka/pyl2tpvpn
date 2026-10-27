import struct
import pytest
from pyl2tpvpn.wire import *
from pyl2tpvpn.l2tp import avp,parse_avps,parse_packet
from pyl2tpvpn.ip import ipv4,parse_ipv4,udp,parse_udp,Reassembly
from pyl2tpvpn.network import dns_name


def test_ike_length_and_payload_bounds():
    for raw in (b'',b'x'*27,b'x'*40):
        with pytest.raises(ProtocolError):
            IKEPacket.parse(raw)
    ps = [Payload(4,b'x'*16),Payload(10,b'y'*32)]
    assert [p.body for p in decode_payloads(4,encode_payloads(ps))] == [p.body for p in ps]
    for data in (b'\0\0\0\x03',b'\0\0\x10\0',b'\x04\0\0\x04'):
        with pytest.raises(ProtocolError):
            decode_payloads(4,data)


def test_sa_v1_gateway_next_transform_quirk_is_bounded():
    body = u32(1)+u32(1)+proposal_v1(1,b'',[(1,[(1,7),(2,2),(3,1),(4,14),(14,128)])])
    raw = bytearray(body)
    raw[16] = 3
    assert len(parse_sa_v1(bytes(raw))[0][3]) == 1
    raw.extend(b'\0'*8)
    with pytest.raises(ProtocolError):
        parse_sa_v1(bytes(raw))


def test_l2tp_avp_and_data_header_validation():
    assert parse_avps(avp(0,u16(1))+avp(9,u16(4))) == {0:u16(1),9:u16(4)}
    with pytest.raises(ProtocolError):
        parse_avps(b'\x80\0\0\0\0\0')
    with pytest.raises(Exception):
        parse_avps(avp(999,b''))
    assert parse_packet(struct.pack('!HHH',2,1,2)+b'data')[-1] == b'data'
    packet = struct.pack('!HHHHHH',0xc802,12,1,0,0,0)
    assert parse_packet(packet)[0] is True
    with pytest.raises(ProtocolError):
        parse_packet(packet+b'extra')


def test_udp_checksums():
    raw = udp(50000,53,b'hello','192.0.2.1','192.0.2.2')
    assert parse_udp(raw,'192.0.2.1','192.0.2.2') == (50000,53,b'hello')
    with pytest.raises(ProtocolError):
        parse_udp(raw[:-1]+b'!','192.0.2.1','192.0.2.2')


def test_fragment_reordering_and_overlap_rejection():
    r = Reassembly()
    assert r.add('a','b',17,1,2,b'last') is None
    assert r.add('a','b',17,1,0x2000,b'0123456789abcdef') == b'0123456789abcdeflast'
    assert r.add('a','b',17,2,0x2000,b'0123456789abcdef') is None
    with pytest.raises(ProtocolError):
        r.add('a','b',17,2,1,b'overlap!')
    assert not r.entries


def test_dns_pointer_loop_is_rejected():
    with pytest.raises(ProtocolError):
        dns_name(b'\xc0\0',0)
    with pytest.raises(ProtocolError):
        dns_name(b'\x40'+b'a'*64,0)
    assert dns_name(b'\x07example\x03com\0',0) == ('example.com',13)
