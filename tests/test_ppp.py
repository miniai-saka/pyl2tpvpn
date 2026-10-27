import asyncio
import hashlib
import struct
import pytest
from pyl2tpvpn.config import VPNConfig
from pyl2tpvpn.ppp import PPP,LCP,IPCP,CHAP,PAP,AUTH_OPTIONS
from pyl2tpvpn.crypto import mschapv2_authenticator
from pyl2tpvpn.errors import AuthenticationError,ProtocolError


def make_ppp(method='mschapv2'):
    sent=[]
    p=PPP(VPNConfig('server','User','clientPass','secret',auth_methods=(method,)),sent.append,lambda e: None)
    p.lcp_local=p.lcp_peer=True
    p.auth_method=method
    return p,sent


def test_bad_configure_ack_cannot_open_lcp():
    async def run():
        p,_=make_ppp()
        p._configure(LCP)
        mid=p.pending[LCP][0]
        with pytest.raises(ProtocolError):
            p._ncp(LCP,2,mid,b'changed',b'')
    asyncio.run(run())


def test_mschapv2_mutual_authentication_failure():
    async def run():
        p,sent=make_ppp()
        p._auth(CHAP,1,7,b'\x10'+b'a'*16+b'peer')
        reply=p.auth_state['body']
        assert reply[0] == 49
        with pytest.raises(AuthenticationError):
            p._auth(CHAP,3,7,b'S='+b'0'*40)
        assert not p.authenticated
        expected=mschapv2_authenticator(b'a'*16,reply[1:17],'User','clientPass',reply[25:49])
        p._auth(CHAP,3,7,expected+b' M=Success')
        assert p.authenticated
    asyncio.run(run())


def test_chap_md5_response_and_pap_are_opt_in():
    async def run():
        p,sent=make_ppp('chap-md5')
        p._auth(CHAP,1,8,b'\x09challengepeer')
        assert p.auth_state['body'][1:17] == hashlib.md5(b'\x08clientPasschallenge').digest()
        p._auth(CHAP,3,8,b'ok')
        assert p.authenticated
        p,sent=make_ppp('pap')
        p._pap()
        assert p.auth_state['body'] == b'\x04User\x0aclientPass'
        p._auth(PAP,2,p.auth_state['mid'],b'\x02OK')
        assert p.authenticated
        p,sent=make_ppp()
        p.lcp_peer=False
        p._ncp(LCP,1,4,AUTH_OPTIONS['pap'],b'')
        assert sent[-1][4] == 3
        assert sent[-1].endswith(AUTH_OPTIONS['mschapv2'])
    asyncio.run(run())
