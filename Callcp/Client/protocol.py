"""Protocol handlers for Secure TCP Client."""

from typing import Optional, Callable

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from Client.crypto import AESGCMHandler, KeyExchange
from Client.transport import TCPClientTransport
from Client.exceptions import HandshakeError, CryptoError


class HandshakeHandler:
    """Handles the secure handshake protocol for client."""

    def __init__(
        self,
        transport: TCPClientTransport,
        logger: Optional[Callable[[str], None]] = None,
    ) -> None:
        """
        Initialize handshake handler.

        Args:
            transport: TCP client transport
            logger: Optional logging function
        """
        self._transport = transport
        self._log = logger or (lambda msg: None)

    def perform_handshake(self) -> AESGCMHandler:
        """
        Perform secure handshake with server.

        Returns:
            Initialized AESGCMHandler for encrypted communication

        Raises:
            HandshakeError: If handshake fails
        """
        try:
            self._log("Starting secure handshake")

            # Receive public key from server
            public_key = self._receive_public_key()

            # Generate AES key
            aes_key = KeyExchange.generate_aes_key()

            # Encrypt AES key with RSA public key
            encrypted_aes_key = KeyExchange.encrypt_aes_key_with_rsa(public_key, aes_key)

            # Send encrypted AES key to server
            self._send_encrypted_aes_key(encrypted_aes_key)

            # Initialize AES-GCM handler
            aes_handler = AESGCMHandler(aes_key)

            self._log("Secure AES session key established")
            return aes_handler

        except (CryptoError, TransportError) as e:
            raise HandshakeError(f"Handshake failed: {e}") from e

    def _receive_public_key(self) -> RSAPublicKey:
        """Receive and load public key from server."""
        try:
            # Receive public key (RSA public keys in PEM format are typically 400-600 bytes)
            # Use larger buffer to ensure we get the complete key in one recv
            public_key_bytes = self._transport.receive(4096)
            
            # Try to load the key
            try:
                return KeyExchange.load_public_key(public_key_bytes)
            except CryptoError:
                # If parsing fails, the key might be incomplete
                # Try receiving more data (shouldn't happen for typical RSA keys, but handle it)
                # Check if we have the PEM end marker
                if b"-----END PUBLIC KEY-----" not in public_key_bytes:
                    # Key might be incomplete, try one more recv
                    additional = self._transport.receive(4096)
                    public_key_bytes += additional
                    return KeyExchange.load_public_key(public_key_bytes)
                else:
                    # Has end marker but still failed to parse - invalid key
                    raise

        except TransportError as e:
            raise HandshakeError(f"Failed to receive public key: {e}") from e
        except CryptoError as e:
            raise HandshakeError(f"Failed to load public key: {e}") from e

    def _send_encrypted_aes_key(self, encrypted_key: bytes) -> None:
        """Send encrypted AES key to server."""
        try:
            self._transport.send(encrypted_key)
            self._log("Encrypted AES key sent to server")
        except TransportError as e:
            raise HandshakeError(f"Failed to send encrypted key: {e}") from e


class MessageHandler:
    """Handles encrypted message exchange for client."""

    def __init__(
        self,
        aes_handler: AESGCMHandler,
        transport: TCPClientTransport,
        message_callback: Optional[Callable[[bytes], bytes]] = None,
        logger: Optional[Callable[[str], None]] = None,
    ) -> None:
        """
        Initialize message handler.

        Args:
            aes_handler: AES-GCM handler for encryption/decryption
            transport: TCP client transport
            message_callback: Optional callback function(message) -> response
            logger: Optional logging function
        """
        self._aes_handler = aes_handler
        self._transport = transport
        self._message_callback = message_callback or self._default_callback
        self._log = logger or (lambda msg: None)

    def send_message(self, message: bytes) -> bytes:
        """
        Send encrypted message and receive response.

        Args:
            message: Message to send

        Returns:
            Decrypted response from server

        Raises:
            CryptoError: If encryption/decryption fails
            TransportError: If transport operations fail
        """
        try:
            # Encrypt and send message
            encrypted_message = self._aes_handler.encrypt(message)
            self._transport.send(encrypted_message)
            self._log(f"Sent: {message.decode('utf-8', errors='replace')}")

            # Receive and decrypt response
            encrypted_response = self._transport.receive(4096)
            plaintext = self._aes_handler.decrypt(encrypted_response)

            self._log(f"Received: {plaintext.decode('utf-8', errors='replace')}")
            return plaintext

        except CryptoError as e:
            self._log(f"Encryption/decryption error: {e}")
            raise
        except TransportError as e:
            self._log(f"Transport error: {e}")
            raise

    @staticmethod
    def _default_callback(message: bytes) -> bytes:
        """
        Default message callback (echo).

        Args:
            message: Received message

        Returns:
            Response message (echo)
        """
        return message
