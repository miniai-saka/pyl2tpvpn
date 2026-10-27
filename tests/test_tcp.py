import asyncio
import struct
import pytest
from pyl2tpvpn.tcp import TCPConnection,unwrap
from pyl2tpvpn.ip import checksum,pseudo


def reply(c,seq,ack,flags,data=b'',window=65535):
    p=struct.pack('!HHIIBBHHH',c.dst_port,c.src_port,seq & 0xffffffff,ack & 0xffffffff,0x50,flags,window,0,0)+data
    return p[:16]+struct.pack('!H',checksum(pseudo(c.dst,c.src,6,len(p))+p))+p[18:]


def test_wrap_math():
    assert unwrap(3,0xfffffffe) == 0x100000003
    assert unwrap(0xfffffffe,0x100000003) == 0xfffffffe


def test_tcp_reordering_fin_and_reset_challenge():
    async def run():
        sent=[]
        c=TCPConnection('192.0.2.1',50001,'192.0.2.2',80,lambda *a:sent.append(a),lambda c:None,1360)
        await asyncio.sleep(0)
        c.receive(reply(c,0xfffffffc,c.iss+1,0x12))
        await c.connected
        c.receive(reply(c,0x100000000,c.snd_nxt,0x18,b'def'))
        c.receive(reply(c,0xfffffffd,c.snd_nxt,0x18,b'abc'))
        assert await c.reader.readexactly(6) == b'abcdef'
        c.receive(reply(c,c.rcv_nxt+1,c.snd_nxt,0x14))
        assert not c.closed
        c.receive(reply(c,c.rcv_nxt,c.snd_nxt,0x11))
        assert await c.reader.read() == b''
        c.writer.close()
        await asyncio.sleep(.15)
        c.receive(reply(c,c.rcv_nxt,c.snd_nxt,0x10))
        await asyncio.wait_for(c.writer.wait_closed(),1)
    asyncio.run(run())


def test_retransmission_does_not_advance_sequence_twice():
    async def run():
        sent=[]
        c=TCPConnection('192.0.2.1',50001,'192.0.2.2',80,lambda *a:sent.append(a),lambda c:None,1360)
        await asyncio.sleep(0)
        next_seq=c.snd_nxt
        c.outstanding[0]['sent']=0
        c.wakeup.set()
        await asyncio.sleep(.15)
        assert len(sent) >= 2 and c.snd_nxt == next_seq
        assert sent[0][2] == sent[1][2]
        c.connected.cancel()
        c.abort()
    asyncio.run(run())


def test_active_close_retains_tuple_and_acks_repeated_fin():
    async def run():
        sent,removed=[],[]
        c=TCPConnection('192.0.2.1',50001,'192.0.2.2',80,lambda *a:sent.append(a),removed.append,1280)
        await asyncio.sleep(0)
        c.receive(reply(c,100,c.iss+1,0x12))
        await c.connected
        c.writer.close()
        await asyncio.sleep(.12)
        c.receive(reply(c,c.rcv_nxt,c.snd_nxt,0x11))
        await asyncio.wait_for(c.writer.wait_closed(),1)
        assert c.time_wait_until is not None and not removed
        count=len(sent)
        c.receive(reply(c,c.rcv_nxt-1,c.snd_nxt,0x11))
        assert len(sent) == count+1 and not removed
        c.abort()
        await asyncio.gather(c.task,return_exceptions=True)
        assert removed == [c]
    asyncio.run(run())
