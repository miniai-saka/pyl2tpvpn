class VPNError(Exception):
    """The tunnel failed; application traffic must not fall back to the host."""


class ProtocolError(VPNError):
    pass


class AuthenticationError(VPNError):
    pass


class NegotiationError(VPNError):
    pass


class VPNTimeout(VPNError, TimeoutError):
    pass


class TunnelClosed(VPNError, ConnectionError):
    pass
