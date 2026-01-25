"""Custom exceptions for Secure TCP Server."""


class SecureTCPServerError(Exception):
    """Base exception for all Secure TCP Server errors."""

    pass


class KeyManagementError(SecureTCPServerError):
    """Raised when key management operations fail."""

    pass


class HandshakeError(SecureTCPServerError):
    """Raised when handshake operations fail."""

    pass


class TransportError(SecureTCPServerError):
    """Raised when transport/socket operations fail."""

    pass


class CryptoError(SecureTCPServerError):
    """Raised when cryptographic operations fail."""

    pass
