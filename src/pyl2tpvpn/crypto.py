"""RFC 2409/3526, RFC 2759 and RFC 4303 primitives."""
import hashlib
import hmac
import secrets
import struct
import time
from dataclasses import dataclass, field
from Crypto.Cipher import AES, DES
from Crypto.Hash import MD4
from .errors import AuthenticationError, ProtocolError, TunnelClosed
from .wire import need, u32


def prf(key, data):
    return hmac.digest(key, data, "sha1")


def expand(key, seed, length, *, counters=False):
    out, last = b"", b""
    for i in range(1, 256):
        last = prf(key, last + seed + (bytes([i]) if counters else b""))
        out += last
        if len(out) >= length:
            return out[:length]
    raise ValueError("excessive key expansion")


def encrypt(key, iv, data):
    need(len(iv) == 16 and len(data) % 16 == 0, "invalid CBC input")
    return AES.new(key, AES.MODE_CBC, iv).encrypt(data)


def decrypt(key, iv, data):
    need(len(iv) == 16 and data and len(data) % 16 == 0, "invalid CBC ciphertext")
    return AES.new(key, AES.MODE_CBC, iv).decrypt(data)


_PREFIX = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE"
PRIMES = {
    2: int(_PREFIX + "65381FFFFFFFFFFFFFFFF", 16),
    5: int(_PREFIX + "45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16),
    14: int(_PREFIX + "45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16),
}


class DH:
    def __init__(self, group):
        self.group = group
        self.p = PRIMES[group]
        self.size = (self.p.bit_length()+7)//8
        self.secret = secrets.randbelow((self.p-1)//2-2)+2
        self.public = pow(2, self.secret, self.p).to_bytes(self.size, "big")

    def shared(self, peer):
        need(len(peer) == self.size, "wrong DH public value size")
        value = int.from_bytes(peer, "big")
        need(2 <= value <= self.p-2 and pow(value, (self.p-1)//2, self.p) == 1,
             "invalid DH public value/subgroup")
        return pow(value, self.secret, self.p).to_bytes(self.size, "big")


def nt_password_hash(password):
    return MD4.new(password.encode("utf-16le")).digest()


def _des_key(key7):
    n = int.from_bytes(key7, "big")
    return bytes((((n >> (7*(7-i))) & 0x7f) << 1) for i in range(8))


def mschapv2_response(auth_challenge, peer_challenge, username, password):
    need(len(auth_challenge) == 16 and len(peer_challenge) == 16, "bad MSCHAPv2 challenge")
    username = username.rsplit("\\", 1)[-1].encode("utf-8")
    challenge = hashlib.sha1(peer_challenge + auth_challenge + username).digest()[:8]
    padded = nt_password_hash(password) + b"\0"*5
    return b"".join(DES.new(_des_key(padded[i:i+7]), DES.MODE_ECB).encrypt(challenge)
                    for i in (0, 7, 14))


def mschapv2_authenticator(auth_challenge, peer_challenge, username, password, response):
    phh = MD4.new(nt_password_hash(password)).digest()
    digest = hashlib.sha1(phh + response + b"Magic server to client signing constant").digest()
    user = username.rsplit("\\", 1)[-1].encode("utf-8")
    challenge = hashlib.sha1(peer_challenge+auth_challenge+user).digest()[:8]
    return b"S=" + hashlib.sha1(digest+challenge+b"Pad to make it do more than one iteration").hexdigest().upper().encode()


class ReplayWindow:
    def __init__(self, size=128):
        self.size, self.high, self.bitmap = size, 0, 0

    def check(self, seq):
        need(0 < seq <= 0xffffffff, "invalid IPsec sequence")
        need(seq > self.high or (self.high-seq < self.size and not (self.bitmap >> (self.high-seq)) & 1),
             "IPsec replay or stale sequence")

    def commit(self, seq):
        self.check(seq)
        if seq > self.high:
            delta = seq-self.high
            self.bitmap = 0 if delta >= self.size else (self.bitmap << delta) & ((1 << self.size)-1)
            self.high = seq
            self.bitmap |= 1
        else:
            self.bitmap |= 1 << (self.high-seq)


@dataclass(repr=False)
class ESP:
    spi: bytes
    encryption_key: bytes
    authentication_key: bytes
    lifetime: float = 3600
    byte_limit: int = 1 << 30
    created: float = field(default_factory=time.monotonic)
    sequence: int = 0
    octets: int = 0
    replay: ReplayWindow = field(default_factory=ReplayWindow)

    def expired(self):
        return time.monotonic()-self.created >= self.lifetime or self.octets >= self.byte_limit or self.sequence >= 0xfffffffe

    def seal(self, payload, next_header=17):
        if self.expired():
            raise TunnelClosed("ESP SA reached hard lifetime/byte/sequence limit")
        self.sequence += 1
        pad = (-len(payload)-2) % 16
        plain = payload + bytes(range(1, pad+1)) + bytes([pad, next_header])
        iv = secrets.token_bytes(16)
        packet = self.spi + u32(self.sequence) + iv + encrypt(self.encryption_key, iv, plain)
        self.octets += len(payload)
        return packet + prf(self.authentication_key, packet)[:12]

    def open(self, packet):
        need(len(packet) >= 52 and packet[:4] == self.spi, "invalid ESP SPI/length")
        seq = int.from_bytes(packet[4:8], "big")
        self.replay.check(seq)
        if not hmac.compare_digest(prf(self.authentication_key, packet[:-12])[:12], packet[-12:]):
            raise AuthenticationError("ESP integrity check failed")
        need(not self.expired(), "inbound ESP SA expired")
        plain = decrypt(self.encryption_key, packet[8:24], packet[24:-12])
        pad, nh = plain[-2:]
        need(pad <= len(plain)-2 and plain[len(plain)-2-pad:-2] == bytes(range(1, pad+1)), "invalid ESP padding")
        self.replay.commit(seq)
        self.octets += len(packet)
        return nh, plain[:len(plain)-2-pad]


class AH:
    """RFC 4302 HMAC-SHA1-96 for IPv4 transport packets without IP options.

    Packet primitive only. AH cannot traverse NAT; the VPN transport negotiates ESP.
    """
    def __init__(self, spi, key):
        need(len(spi) == 4, "AH SPI must be 4 bytes")
        self.spi, self.key, self.sequence, self.replay = spi, key, 0, ReplayWindow()

    @staticmethod
    def _canonical(packet):
        need(len(packet) >= 20 and packet[0] == 0x45, "AH supports IPv4 without options only")
        p = bytearray(packet)
        p[1] = 0
        p[6:9] = b"\0"*3
        p[10:12] = b"\0\0"
        p[32:44] = b"\0"*12
        return bytes(p)

    def seal(self, ipv4):
        from .ip import checksum
        need(len(ipv4) >= 20 and ipv4[0] == 0x45, "invalid AH IPv4 input")
        need(int.from_bytes(ipv4[2:4], "big") == len(ipv4) and len(ipv4) <= 65511,
             "AH input length mismatch or packet too large")
        need(self.sequence < 0xffffffff, "AH sequence exhausted")
        self.sequence += 1
        ah = bytes([ipv4[9], 4, 0, 0]) + self.spi + u32(self.sequence) + b"\0"*12
        p = bytearray(ipv4[:20] + ah + ipv4[20:])
        p[9], p[2:4], p[10:12] = 51, struct.pack("!H", len(p)), b"\0\0"
        p[32:44] = prf(self.key, self._canonical(p))[:12]
        p[10:12] = struct.pack("!H", checksum(p[:20]))
        return bytes(p)

    def open(self, packet):
        from .ip import checksum
        need(len(packet) >= 44 and packet[9] == 51 and packet[21] == 4 and packet[24:28] == self.spi,
             "invalid AH packet")
        need(int.from_bytes(packet[2:4], "big") == len(packet) and packet[22:24] == b"\0\0",
             "invalid AH length/reserved field")
        seq = int.from_bytes(packet[28:32], "big")
        self.replay.check(seq)
        if not hmac.compare_digest(packet[32:44], prf(self.key, self._canonical(packet))[:12]):
            raise AuthenticationError("AH integrity failed")
        self.replay.commit(seq)
        p = bytearray(packet[:20] + packet[44:])
        p[9], p[2:4], p[10:12] = packet[20], struct.pack("!H", len(p)), b"\0\0"
        p[10:12] = struct.pack("!H", checksum(p[:20]))
        return bytes(p)
