"""Protocol handlers for Secure TCP Server."""

import socket
from typing import Optional, Callable

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from Server.crypto import AESGCMHandler
from Server.exceptions import HandshakeError, CryptoError


class HandshakeHandler:
    """Handles the secure handshake protocol."""

    def __init__(
        self,
        private_key: RSAPrivateKey,
        public_key_bytes: bytes,
        logger: Optional[Callable[[str], None]] = None,
    ) -> None:
        """
        Initialize handshake handler.

        Args:
            private_key: RSA private key for decryption
            public_key_bytes: RSA public key bytes to send to client
            logger: Optional logging function
        """
        self._private_key = private_key
        self._public_key_bytes = public_key_bytes
        self._log = logger or (lambda msg: None)

    def perform_handshake(self, conn: socket.socket) -> AESGCMHandler:
        """
        Perform secure handshake with client.

        Args:
            conn: Client socket connection

        Returns:
            Initialized AESGCMHandler for encrypted communication

        Raises:
            HandshakeError: If handshake fails
        """
        try:
            self._log("Starting secure handshake")

            # Send public key to client
            self._send_public_key(conn)

            # Receive and decrypt AES key
            aes_key = self._receive_aes_key(conn)

            # Initialize AES-GCM handler
            aes_handler = AESGCMHandler(aes_key)

            self._log("Secure AES session key established")
            return aes_handler

        except (CryptoError, OSError) as e:
            raise HandshakeError(f"Handshake failed: {e}") from e

    def _send_public_key(self, conn: socket.socket) -> None:
        """Send public key to client."""
        try:
            conn.sendall(self._public_key_bytes)
            self._log("Public key sent to client")
        except OSError as e:
            raise HandshakeError(f"Failed to send public key: {e}") from e

    def _receive_aes_key(self, conn: socket.socket) -> bytes:
        """Receive and decrypt AES key from client."""
        try:
            encrypted_aes_key = conn.recv(4096)
            if not encrypted_aes_key:
                raise HandshakeError("No encrypted key received from client")

            # Decrypt RSA-encrypted AES key
            return self._private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

        except OSError as e:
            raise HandshakeError(f"Failed to receive encrypted key: {e}") from e
        except Exception as e:
            raise HandshakeError(f"Failed to decrypt AES key: {e}") from e


class MessageHandler:
    """Handles encrypted message exchange."""

    def __init__(
        self,
        aes_handler: AESGCMHandler,
        message_callback: Optional[Callable[[bytes], bytes]] = None,
        logger: Optional[Callable[[str], None]] = None,
    ) -> None:
        """
        Initialize message handler.

        Args:
            aes_handler: AES-GCM handler for encryption/decryption
            message_callback: Optional callback function(message) -> response
            logger: Optional logging function
        """
        self._aes_handler = aes_handler
        self._message_callback = message_callback or self._default_callback
        self._log = logger or (lambda msg: None)

    def handle_connection(self, conn: socket.socket) -> None:
        """
        Handle encrypted message exchange with client.

        Args:
            conn: Client socket connection

        Raises:
            CryptoError: If encryption/decryption fails
            OSError: If socket operations fail
        """
        self._log("Encrypted channel active")

        while True:
            try:
                packet = conn.recv(4096)
                if not packet:
                    self._log("Client disconnected")
                    break

                # Decrypt message
                plaintext = self._aes_handler.decrypt(packet)

                self._log(f"Received: {plaintext.decode('utf-8', errors='replace')}")

                # Process message and get response
                response = self._message_callback(plaintext)

                # Encrypt and send response
                encrypted_response = self._aes_handler.encrypt(response)
                conn.sendall(encrypted_response)

            except CryptoError as e:
                self._log(f"Decryption error: {e}")
                raise
            except OSError as e:
                self._log(f"Socket error: {e}")
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
