"""Small active-open TCP/IPv4 stack for stream-oriented Python clients.

No kernel sockets carry application traffic. Cumulative ACK, bounded receive
reordering, retransmission/backoff, peer windows, zero-window probes, FIN/RST,
and sequence wrap are handled here. Optional extensions are not advertised.
"""
import asyncio
import secrets
import struct
import time
from collections import deque
from .errors import TunnelClosed, VPNTimeout
from .ip import checksum, pseudo
from .wire import need

FIN, SYN, RST, PSH, ACK = 1, 2, 4, 8, 16


def unwrap(value, reference):
    return reference + ((value-(reference & 0xffffffff)+0x80000000) & 0xffffffff)-0x80000000


class TunnelReader(asyncio.StreamReader):
    def __init__(self, connection):
        super().__init__(limit=262144)
        self.connection = connection

    async def read(self, n=-1):
        data = await super().read(n)
        self.connection.window_update()
        return data

    async def readexactly(self, n):
        if n < 0:
            raise ValueError("readexactly size must be nonnegative")
        data = bytearray()
        while len(data) < n:
            part = await self.read(min(65536,n-len(data)))
            if not part:
                raise asyncio.IncompleteReadError(bytes(data),n)
            data.extend(part)
        return bytes(data)

    async def readuntil(self, separator=b"\n"):
        data = await super().readuntil(separator)
        self.connection.window_update()
        return data


class TunnelWriter:
    def __init__(self, connection):
        self.connection = connection

    def write(self, data):
        c = self.connection
        c.check()
        if c.want_fin:
            raise TunnelClosed("write after close")
        if len(c.buffer)+len(data) > 4*1024*1024:
            raise BufferError("VPN TCP write buffer full; await drain() between writes")
        c.buffer.extend(data)
        c.wakeup.set()

    def writelines(self, lines):
        self.write(b"".join(lines))

    async def drain(self):
        c = self.connection
        c.check()
        while c.buffer or c.outstanding:
            c.progress.clear()
            c.check()
            if not c.buffer and not c.outstanding:
                break
            await c.progress.wait()
        c.check()

    def close(self):
        self.connection.want_fin = True
        self.connection.wakeup.set()

    def write_eof(self):
        self.close()

    def can_write_eof(self):
        return True

    def is_closing(self):
        return self.connection.want_fin or self.connection.closed

    async def wait_closed(self):
        await self.connection.closed_event.wait()
        self.connection.check(allow_closed=True)

    def get_extra_info(self, name, default=None):
        c = self.connection
        return {"peername": (c.dst, c.dst_port), "sockname": (c.src, c.src_port)}.get(name, default)


class TCPConnection:
    def __init__(self, src, src_port, dst, dst_port, send, remove, mtu):
        self.src, self.src_port, self.dst, self.dst_port = src, src_port, dst, dst_port
        self.send_ip, self.remove = send, remove
        self.iss = secrets.randbelow(1 << 32)
        self.snd_una = self.snd_nxt = self.iss
        self.rcv_nxt = None
        self.peer_window, self.peer_mss = 65535, 536
        self.mss = mtu-40
        self.buffer = bytearray()
        self.outstanding = deque()
        self.reordered = {}
        self.want_fin = self.sent_fin = self.got_fin = self.closed = False
        self.active_close = False
        self.time_wait_until = None
        self.error = None
        self.connected = asyncio.get_running_loop().create_future()
        self.closed_event, self.wakeup, self.progress = asyncio.Event(), asyncio.Event(), asyncio.Event()
        self.reader, self.writer = TunnelReader(self), TunnelWriter(self)
        self.task = asyncio.create_task(self._run())
        self.last_window = 65535
        self.cwnd, self.ssthresh = 2*self.mss, 65535
        self.rto, self.srtt, self.rttvar = 1.0, None, None
        self.dup_ack = 0
        self.window_seq, self.window_ack = -1, -1
        self.last_probe = time.monotonic()

    def check(self, allow_closed=False):
        if self.error:
            raise self.error
        if self.closed and not allow_closed:
            raise TunnelClosed("VPN TCP stream is closed")

    def _window(self):
        return max(0, min(65535, 262144-len(self.reader._buffer)-sum(len(v[0]) for v in self.reordered.values())))

    def _segment(self, seq, flags, data=b"", options=b""):
        ack = 0 if self.rcv_nxt is None else self.rcv_nxt & 0xffffffff
        window = self._window()
        self.last_window = window
        raw = struct.pack("!HHIIBBHHH", self.src_port, self.dst_port, seq & 0xffffffff,
                          ack, ((20+len(options))//4) << 4, flags, window, 0, 0)+options+data
        crc = checksum(pseudo(self.src, self.dst, 6, len(raw))+raw)
        raw = raw[:16]+struct.pack("!H", crc)+raw[18:]
        self.send_ip(self.dst, 6, raw)

    def _emit(self, flags, data=b"", options=b""):
        seq, now = self.snd_nxt, time.monotonic()
        end = seq+len(data)+bool(flags & SYN)+bool(flags & FIN)
        self._segment(seq, flags, data, options)
        self.snd_nxt = end
        self.outstanding.append(dict(seq=seq, end=end, flags=flags, data=data, options=options,
                                     sent=now, first=now, retries=0))

    def _ack(self):
        if self.rcv_nxt is not None and not self.closed:
            self._segment(self.snd_nxt, ACK)

    def window_update(self):
        if self.last_window < self.mss and self._window() >= self.mss:
            self._ack()

    def _rtt(self, sample):
        if self.srtt is None:
            self.srtt, self.rttvar = sample, sample/2
        else:
            self.rttvar = 0.75*self.rttvar+0.25*abs(self.srtt-sample)
            self.srtt = 0.875*self.srtt+0.125*sample
        self.rto = min(30, max(0.5, self.srtt+4*self.rttvar))

    def receive(self, packet):
        need(len(packet) >= 20, "short TCP segment")
        sp, dp, wire_seq, wire_ack, offset, flags, window, crc, urgent = struct.unpack("!HHIIBBHHH", packet[:20])
        hlen = (offset >> 4)*4
        need(20 <= hlen <= len(packet) and not offset & 0x0e, "invalid TCP header")
        need(checksum(pseudo(self.dst, self.src, 6, len(packet))+packet) == 0, "TCP checksum failure")
        if self.closed:
            return
        ack = unwrap(wire_ack, self.snd_una)
        if self.rcv_nxt is None:
            if flags & RST and flags & ACK and ack == self.iss+1:
                self.abort(ConnectionRefusedError("VPN peer refused TCP connection"))
                return
            if flags & (SYN|ACK|RST) != SYN|ACK or ack != self.iss+1:
                return
            opts = packet[20:hlen]
            while opts:
                kind = opts[0]
                if kind == 0:
                    break
                if kind == 1:
                    opts = opts[1:]
                    continue
                need(len(opts) >= 2 and 2 <= opts[1] <= len(opts), "bad TCP option")
                opt, opts = opts[:opts[1]], opts[opts[1]:]
                if kind == 2 and len(opt) == 4:
                    self.peer_mss = max(64, int.from_bytes(opt[2:], "big"))
            self.rcv_nxt = wire_seq+1
            self.snd_una = ack
            self.outstanding.clear()
            self.peer_window = window
            self.window_seq, self.window_ack = wire_seq, ack
            self.connected.set_result(None)
            self._ack()
            self.wakeup.set()
            return
        seq = unwrap(wire_seq, self.rcv_nxt)
        data = packet[hlen:]
        if self.time_wait_until is not None:
            # Retain the four-tuple for 2*MSL and acknowledge a repeated FIN.
            # A lost last ACK must not leave the peer retransmitting forever.
            if flags & FIN and seq+len(data)+1 == self.rcv_nxt:
                self.time_wait_until = time.monotonic()+120
                self._ack()
            return
        # RFC 5961: reset only at RCV.NXT; challenge ACK other in-window RSTs.
        if flags & RST:
            if seq == self.rcv_nxt:
                self.abort(ConnectionResetError("VPN TCP connection reset"))
            elif self.rcv_nxt <= seq < self.rcv_nxt+self._window():
                self._ack()
            return
        if flags & SYN:
            self._ack()
            return
        if not flags & ACK:
            return
        if seq > self.rcv_nxt+self._window() or seq+len(data)+bool(flags & FIN) < self.rcv_nxt:
            self._ack()
            return
        if not self.snd_una <= ack <= self.snd_nxt:
            self._ack()
            return
        if seq > self.window_seq or (seq == self.window_seq and ack >= self.window_ack):
            self.peer_window, self.window_seq, self.window_ack = window, seq, ack
        if ack > self.snd_una:
            acked = ack-self.snd_una
            self.snd_una, self.dup_ack = ack, 0
            while self.outstanding and self.outstanding[0]["end"] <= ack:
                sent = self.outstanding.popleft()
                if not sent["retries"]:
                    self._rtt(time.monotonic()-sent["first"])
            if self.outstanding and self.outstanding[0]["seq"] < ack:
                sent = self.outstanding[0]
                trimmed = ack-sent["seq"]
                sent["data"], sent["seq"] = sent["data"][trimmed:], ack
            self.cwnd = min(65535, self.cwnd+(min(acked, self.mss) if self.cwnd < self.ssthresh else max(1, self.mss*acked//self.cwnd)))
            self.progress.set()
        elif self.outstanding and not data:
            self.dup_ack += 1
            if self.dup_ack == 3:
                self.ssthresh = max(2*self.mss, self.cwnd//2)
                self.cwnd = self.ssthresh
                self.outstanding[0]["sent"] = 0
        if data or flags & FIN:
            if seq < self.rcv_nxt:
                trim = self.rcv_nxt-seq
                data = data[trim:]
                seq = self.rcv_nxt
            available = self._window()-(seq-self.rcv_nxt)
            fin = bool(flags & FIN) and len(data) < available
            data = data[:max(0, available)]
            if seq == self.rcv_nxt:
                self._consume(data, fin)
                while self.reordered:
                    start = min(self.reordered)
                    if start > self.rcv_nxt:
                        break
                    part, ending = self.reordered.pop(start)
                    trim = self.rcv_nxt-start
                    if trim <= len(part):
                        self._consume(part[trim:], ending)
            elif (data or fin) and len(self.reordered) < 128 and seq-self.rcv_nxt < 65535:
                self.reordered.setdefault(seq, (data, fin))
            self._ack()
        if self.sent_fin and self.got_fin and self.snd_una == self.snd_nxt:
            if self.active_close:
                self.time_wait_until = time.monotonic()+120
                self.closed_event.set()
                self.progress.set()
            else:
                self._finish()
        self.wakeup.set()

    def _consume(self, data, fin):
        if self.got_fin:
            return
        if data:
            self.reader.feed_data(data)
            self.rcv_nxt += len(data)
        if fin:
            self.rcv_nxt += 1
            self.got_fin = True
            self.reader.feed_eof()

    async def _run(self):
        try:
            self._emit(SYN, options=b"\x02\x04"+struct.pack("!H", self.mss))
            closing_since = None
            while not self.closed:
                now = time.monotonic()
                if self.time_wait_until is not None:
                    if now >= self.time_wait_until:
                        self._finish()
                        break
                    await asyncio.sleep(min(1,self.time_wait_until-now))
                    continue
                if self.connected.done() and not self.connected.cancelled() and not self.connected.exception():
                    available = min(self.peer_window, self.cwnd)-(self.snd_nxt-self.snd_una)
                    while self.buffer and available > 0:
                        n = min(available, self.mss, self.peer_mss, len(self.buffer))
                        part = bytes(self.buffer[:n])
                        del self.buffer[:n]
                        self._emit(ACK|PSH, part)
                        available -= n
                    if self.want_fin and not self.buffer and not self.sent_fin and available > 0:
                        self.active_close = not self.got_fin
                        self._emit(ACK|FIN)
                        self.sent_fin = True
                        closing_since = now
                    if self.peer_window == 0 and self.buffer and now-self.last_probe > min(30, self.rto*2):
                        self._segment(self.snd_nxt-1, ACK, b"\0")
                        self.last_probe = now
                if self.outstanding:
                    first = self.outstanding[0]
                    if now-first["sent"] >= min(30, self.rto*2**first["retries"]):
                        if first["retries"] >= 7:
                            raise VPNTimeout("VPN TCP retransmission limit exceeded")
                        first["retries"] += 1
                        first["sent"] = now
                        self.ssthresh, self.cwnd = max(self.cwnd//2, 2*self.mss), self.mss
                        self._segment(first["seq"], first["flags"], first["data"], first["options"])
                if closing_since and now-closing_since > 30:
                    self._finish()
                self.progress.set()
                self.wakeup.clear()
                try:
                    await asyncio.wait_for(self.wakeup.wait(), 0.1)
                except TimeoutError:
                    pass
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.abort(e)

    def _finish(self):
        self.closed = True
        self.reader.feed_eof()
        self.closed_event.set()
        self.progress.set()
        self.wakeup.set()
        self.remove(self)

    def abort(self, error=None):
        if self.closed:
            return
        self.error = error or TunnelClosed("TCP stream aborted")
        if not self.connected.done():
            self.connected.set_exception(self.error)
        self.reader.set_exception(self.error)
        self._finish()
        if self.task is not asyncio.current_task():
            self.task.cancel()
