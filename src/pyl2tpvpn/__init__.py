"""Isolated IPv4 sockets over L2TP/IPsec or native IKEv2 for Python 3.11+."""
__version__ = "0.3.0"
from .client import VPNClient
from .config import VPNConfig
from .errors import VPNError, VPNTimeout, AuthenticationError, NegotiationError, TunnelClosed

__all__ = ["VPNClient", "VPNConfig", "VPNError", "VPNTimeout", "AuthenticationError",
           "NegotiationError", "TunnelClosed"]
