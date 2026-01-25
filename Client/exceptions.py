"""Custom exceptions for Secure TCP Client."""


class SecureTCPClientError(Exception):
    """Base exception for all Secure TCP Client errors."""

    pass


class HandshakeError(SecureTCPClientError):
    """Raised when handshake operations fail."""

    pass


class TransportError(SecureTCPClientError):
    """Raised when transport/socket operations fail."""

    pass


class CryptoError(SecureTCPClientError):
    """Raised when cryptographic operations fail."""

    pass
