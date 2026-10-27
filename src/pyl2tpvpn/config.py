from dataclasses import dataclass, field
import ipaddress
import math


@dataclass(frozen=True)
class VPNConfig:
    server: str
    username: str = field(default="", repr=False)
    password: str = field(default="", repr=False)
    psk: str = field(default="", repr=False)
    ike_version: int = 1
    data_mode: str = "auto"
    local_id: str | None = None
    remote_id: str | None = None
    request_remote_id: bool = False
    ikev2_renewal: str = "rekey"
    dh_groups: tuple[int, ...] = (14, 5, 2)
    aes_bits: tuple[int, ...] = (128, 256)
    pfs_group: int | None = None
    ike_lifetime: float = 28800
    child_lifetime: float = 3600
    rekey_margin: float = 0.2
    rekey_overlap: float = 30
    child_byte_limit: int = 1 << 30
    keepalive_interval: float = 20
    dpd_interval: float = 30
    connect_timeout: float = 90
    shutdown_timeout: float = 8
    retransmit_initial: float = 1
    retransmit_attempts: int = 5
    lcp_echo_interval: float = 30
    l2tp_hello_interval: float = 30
    mtu: int = 1360
    auth_methods: tuple[str, ...] = ("mschapv2",)
    local_address: str = "0.0.0.0"
    local_ike_port: int = 0
    local_natt_port: int = 0
    server_ike_port: int = 500
    server_natt_port: int = 4500
    l2tp_port: int = 1701
    dns_servers: tuple[str, ...] = ()
    force_natt: bool = True

    @property
    def uses_l2tp(self):
        return self.data_mode == "l2tp" or (self.data_mode == "auto" and self.ike_version == 1)

    def __post_init__(self):
        if not self.server or self.ike_version not in (1, 2):
            raise ValueError("server and ike_version (1 or 2) are required")
        if self.data_mode not in ("auto","l2tp","tunnel") or (self.ike_version == 1 and self.data_mode == "tunnel"):
            raise ValueError("data_mode must be auto/l2tp/tunnel; IKEv1 uses L2TP")
        if self.ikev2_renewal not in ("rekey", "reauthenticate"):
            raise ValueError("ikev2_renewal must be rekey or reauthenticate")
        if not self.dh_groups or any(g not in (2, 5, 14) for g in self.dh_groups):
            raise ValueError("DH groups supported: 2, 5, 14")
        if self.pfs_group is not None and self.pfs_group not in (2, 5, 14):
            raise ValueError("PFS group supported: 2, 5, 14")
        if not self.aes_bits or any(n not in (128, 192, 256) for n in self.aes_bits):
            raise ValueError("AES-CBC key size must be 128, 192 or 256")
        if not 576 <= self.mtu <= 1400:
            raise ValueError("mtu must be between 576 and 1400")
        if not 0.05 <= self.rekey_margin <= 0.5:
            raise ValueError("rekey_margin must be between 0.05 and 0.5")
        for name in ("ike_lifetime", "child_lifetime", "rekey_overlap", "keepalive_interval",
                     "dpd_interval", "connect_timeout", "retransmit_initial", "lcp_echo_interval",
                     "l2tp_hello_interval", "shutdown_timeout"):
            if not math.isfinite(getattr(self, name)) or getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")
        ipaddress.IPv4Address(self.local_address)
        for address in self.dns_servers:
            ipaddress.IPv4Address(address)
        if any(value is not None and len(value.encode()) > 1024 for value in (self.local_id,self.remote_id)):
            raise ValueError("IKE identities must not exceed 1024 encoded bytes")
        if self.retransmit_attempts < 1 or self.child_byte_limit < 1024:
            raise ValueError("invalid retransmission / byte limit")
        if not self.auth_methods or any(a not in ("mschapv2", "chap-md5", "pap") for a in self.auth_methods):
            raise ValueError("authentication methods: mschapv2, chap-md5, pap")
        for name in ("local_ike_port", "local_natt_port", "server_ike_port", "server_natt_port", "l2tp_port"):
            if not 0 <= getattr(self, name) <= 65535:
                raise ValueError(f"{name}: invalid port")
        if min(self.server_ike_port,self.server_natt_port,self.l2tp_port) == 0:
            raise ValueError("remote IKE/NAT-T and L2TP ports must be nonzero")
        if min(self.ike_lifetime,self.child_lifetime) < 1:
            raise ValueError("IKE/child lifetimes must be at least one second")
