"""
Secure TCP Client Library

A production-ready secure TCP client implementation with:
- RSA for key exchange
- AES-GCM for encrypted communication
"""

from .client import SecureTCPClient
from .exceptions import (
    SecureTCPClientError,
    HandshakeError,
    TransportError,
    CryptoError,
)

__all__ = [
    "SecureTCPClient",
    "SecureTCPClientError",
    "HandshakeError",
    "TransportError",
    "CryptoError",
]

__version__ = "1.0.0"
