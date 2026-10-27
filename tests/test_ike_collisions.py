"""Exercise both authenticated endpoints, including crossed rekey requests."""
import asyncio
from types import SimpleNamespace
import pytest
from pyl2tpvpn import VPNConfig
from pyl2tpvpn.ikev2 import IKEv2, TemporaryFailure, notify
from pyl2tpvpn.wire import IKEPacket


class Link:
    def __init__(self, local, peer):
        self.local_ip, self.peer = local, peer
        self.local_port = 50000
        self.sessions, self.sent = {}, []
        self.last_received = 0

    def send(self, raw, *, natt=True, ike=True):
        self.sent.append(raw)
        packet = IKEPacket.parse(raw)
        session = self.other.sessions.get(packet.initiator)
        if session:
            asyncio.get_running_loop().call_soon(session.receive, packet, raw, natt)


def pair(pfs=None):
    config = VPNConfig('peer', psk='test-only', ike_version=2, data_mode='l2tp',
                       dh_groups=(14,), aes_bits=(128,), pfs_group=pfs, rekey_overlap=.02,
                       retransmit_initial=.02, retransmit_attempts=3)
    a, b = Link('192.0.2.1','192.0.2.2'), Link('192.0.2.2','192.0.2.1')
    a.other, b.other = b, a
    errors, installed_a, installed_b = [], [], []
    x = IKEv2(a,config,lambda *p:installed_a.append(p),errors.append,ci=b'i'*8,cr=b'r'*8)
    y = IKEv2(b,config,lambda *p:installed_b.append(p),errors.append,ci=b'i'*8,cr=b'r'*8,initiator_role=False)
    for p in (x,y):
        p._keys(b'shared secret', b'n'*32, b'm'*32, 128)
        p.group, p.established, p.natt = 14, True, True
        p.peer_identity_type, p.peer_identity = 2, b'peer.test'
    x._install(b'a'*4,b'b'*4,128,b'n'*32,b'm'*32)
    y._install(b'b'*4,b'a'*4,128,b'n'*32,b'm'*32,exchange_initiator=False)
    return x,y,errors


def check_children(x,y):
    assert x.child_out.spi == y.child_in.spi
    assert y.child_out.spi == x.child_in.spi
    assert y.child_in.open(x.child_out.seal(b'forward')) == (17,b'forward')
    assert x.child_in.open(y.child_out.seal(b'return')) == (17,b'return')


async def cleanup(x,y):
    sessions = set(x.link.sessions.values()) | set(y.link.sessions.values())
    for session in sessions:
        await session.close(notify=False)


@pytest.mark.parametrize('kind',['child','ike'])
@pytest.mark.parametrize('pfs',[None,14])
def test_simultaneous_rekey_selects_same_nonce_winner(kind,pfs):
    async def run():
        x,y,errors = pair(pfs)
        try:
            if kind == 'child':
                await asyncio.gather(x.rekey_child(),y.rekey_child())
                check_children(x,y)
                await asyncio.sleep(.08)
                check_children(x,y)
                assert len(x.children) == len(y.children) == 2  # old and winning pair
            else:
                a,b = await asyncio.gather(x.rekey_ike(),y.rekey_ike())
                assert a.ci == b.ci and a.cr == b.cr
                assert a.initiator_role != b.initiator_role
                assert a.key_out == b.key_in and a.auth_out == b.auth_in
                await asyncio.gather(a.dpd(),b.dpd())
                await asyncio.sleep(.08)
                await a.rekey_child()
                check_children(a,b)
            assert not errors
        finally:
            await cleanup(x,y)
    asyncio.run(run())


def test_crossed_ike_child_rekeys_defer_without_changing_keys():
    async def run():
        x,y,errors = pair()
        try:
            before = x.child_in.spi,y.child_in.spi
            results = await asyncio.gather(x.rekey_child(),y.rekey_ike(),return_exceptions=True)
            assert all(isinstance(r,TemporaryFailure) for r in results)
            assert before == (x.child_in.spi,y.child_in.spi)
            await x.rekey_child()
            check_children(x,y)
            assert not errors
        finally:
            await cleanup(x,y)
    asyncio.run(run())


def test_dpd_queued_during_close_does_not_send_on_deleted_sa():
    async def run():
        x,y,errors = pair()
        try:
            x.successor = SimpleNamespace()
            await x.close()
            count = len(x.link.sent)
            await x.dpd()
            assert len(x.link.sent) == count
        finally:
            await cleanup(x,y)
    asyncio.run(run())


def test_bad_integrity_response_is_ignored_then_identical_request_retries():
    async def run():
        x,y,errors = pair()
        send=y.link.send
        first=True
        def corrupt_once(raw,**kw):
            nonlocal first
            if first and IKEPacket.parse(raw).flags & 0x20:
                first=False
                raw=raw[:-1]+bytes([raw[-1]^1])
            send(raw,**kw)
        y.link.send=corrupt_once
        try:
            await x.dpd()
            assert len(x.link.sent) == 2 and x.link.sent[0] == x.link.sent[1]
            assert y.peer_mid == 1 and not errors
        finally:
            await cleanup(x,y)
    asyncio.run(run())


def test_expired_ike_does_not_respond_even_to_authenticated_request():
    async def run():
        x,y,errors = pair()
        x.created-=x.ike_lifetime+1
        raw=y._packet(37,0,[])
        try:
            x.receive(IKEPacket.parse(raw),raw,True)
            await asyncio.sleep(0)
            assert x.peer_mid == 0 and not x.link.sent and not errors
        finally:
            await cleanup(x,y)
    asyncio.run(run())
