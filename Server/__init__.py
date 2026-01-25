"""
Secure TCP Server Library

A production-ready secure TCP server implementation with:
- RSA for key exchange
- AES-GCM for encrypted communication
"""

from .server import SecureTCPServer
from .exceptions import (
    SecureTCPServerError,
    KeyManagementError,
    HandshakeError,
    TransportError,
    CryptoError,
)

__all__ = [
    "SecureTCPServer",
    "SecureTCPServerError",
    "KeyManagementError",
    "HandshakeError",
    "TransportError",
    "CryptoError",
]

__version__ = "1.0.0"
