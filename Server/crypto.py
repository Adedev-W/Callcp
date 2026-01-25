"""Cryptographic operations for Secure TCP Server."""

import os
from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from Server.exceptions import KeyManagementError, CryptoError


class KeyManager:
    """Manages RSA key pair generation, loading, and serialization."""

    def __init__(
        self,
        private_key_path: str = "server_private.pem",
        public_key_path: str = "server_public.pem",
        key_size: int = 2048,
        public_exponent: int = 65537,
    ) -> None:
        """
        Initialize KeyManager.

        Args:
            private_key_path: Path to private key file
            public_key_path: Path to public key file
            key_size: RSA key size in bits
            public_exponent: RSA public exponent
        """
        self.private_key_path = Path(private_key_path)
        self.public_key_path = Path(public_key_path)
        self.key_size = key_size
        self.public_exponent = public_exponent
        self._private_key: Optional[RSAPrivateKey] = None
        self._public_key_bytes: Optional[bytes] = None

    def load_or_generate_keys(self) -> Tuple[RSAPrivateKey, bytes]:
        """
        Load existing keys or generate new ones.

        Returns:
            Tuple of (private_key, public_key_bytes)

        Raises:
            KeyManagementError: If key operations fail
        """
        try:
            if not self.private_key_path.exists():
                self._generate_keys()
            else:
                self._load_keys()

            if self._private_key is None or self._public_key_bytes is None:
                raise KeyManagementError("Failed to initialize keys")

            return self._private_key, self._public_key_bytes

        except Exception as e:
            raise KeyManagementError(f"Key management failed: {e}") from e

    def _generate_keys(self) -> None:
        """Generate new RSA key pair and save to files."""
        try:
            self._private_key = rsa.generate_private_key(
                public_exponent=self.public_exponent,
                key_size=self.key_size,
            )

            # Save private key
            with open(self.private_key_path, "wb") as f:
                f.write(
                    self._private_key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    )
                )

            # Save public key
            with open(self.public_key_path, "wb") as f:
                f.write(
                    self._private_key.public_key().public_bytes(
                        serialization.Encoding.PEM,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                )

            # Load public key bytes
            with open(self.public_key_path, "rb") as f:
                self._public_key_bytes = f.read()

        except Exception as e:
            raise KeyManagementError(f"Key generation failed: {e}") from e

    def _load_keys(self) -> None:
        """Load existing RSA keys from files."""
        try:
            if not self.private_key_path.exists():
                raise KeyManagementError(f"Private key file not found: {self.private_key_path}")

            with open(self.private_key_path, "rb") as f:
                self._private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                )

            if not self.public_key_path.exists():
                raise KeyManagementError(f"Public key file not found: {self.public_key_path}")

            with open(self.public_key_path, "rb") as f:
                self._public_key_bytes = f.read()

        except Exception as e:
            raise KeyManagementError(f"Key loading failed: {e}") from e

    def get_private_key(self) -> RSAPrivateKey:
        """
        Get the private key.

        Returns:
            RSAPrivateKey instance

        Raises:
            KeyManagementError: If keys are not loaded
        """
        if self._private_key is None:
            raise KeyManagementError("Keys not loaded. Call load_or_generate_keys() first.")
        return self._private_key

    def get_public_key_bytes(self) -> bytes:
        """
        Get the public key as bytes.

        Returns:
            Public key bytes

        Raises:
            KeyManagementError: If keys are not loaded
        """
        if self._public_key_bytes is None:
            raise KeyManagementError("Keys not loaded. Call load_or_generate_keys() first.")
        return self._public_key_bytes


class AESGCMHandler:
    """Handles AES-GCM encryption and decryption operations."""

    def __init__(self, key: bytes) -> None:
        """
        Initialize AES-GCM handler.

        Args:
            key: AES key (must be 16, 24, or 32 bytes)

        Raises:
            CryptoError: If key is invalid
        """
        if len(key) not in (16, 24, 32):
            raise CryptoError(f"Invalid AES key length: {len(key)}. Must be 16, 24, or 32 bytes.")
        self._aesgcm = AESGCM(key)
        self._nonce_size = 12

    def encrypt(self, plaintext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Encrypt plaintext using AES-GCM.

        Args:
            plaintext: Data to encrypt
            associated_data: Optional associated data for authentication

        Returns:
            Encrypted data with nonce prepended (nonce + ciphertext)

        Raises:
            CryptoError: If encryption fails
        """
        try:
            nonce = os.urandom(self._nonce_size)
            ciphertext = self._aesgcm.encrypt(nonce, plaintext, associated_data)
            return nonce + ciphertext
        except Exception as e:
            raise CryptoError(f"Encryption failed: {e}") from e

    def decrypt(self, encrypted_data: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt ciphertext using AES-GCM.

        Args:
            encrypted_data: Encrypted data with nonce prepended (nonce + ciphertext)
            associated_data: Optional associated data for authentication

        Returns:
            Decrypted plaintext

        Raises:
            CryptoError: If decryption fails
        """
        try:
            if len(encrypted_data) < self._nonce_size:
                raise CryptoError("Encrypted data too short to contain nonce")

            nonce = encrypted_data[:self._nonce_size]
            ciphertext = encrypted_data[self._nonce_size:]

            return self._aesgcm.decrypt(nonce, ciphertext, associated_data)
        except Exception as e:
            raise CryptoError(f"Decryption failed: {e}") from e

