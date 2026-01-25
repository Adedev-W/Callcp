"""Cryptographic operations for Secure TCP Client."""

import os
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from Client.exceptions import CryptoError


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
            raise CryptoError(
                f"Invalid AES key length: {len(key)}. Must be 16, 24, or 32 bytes."
            )
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


class KeyExchange:
    """Handles key exchange operations for client."""

    @staticmethod
    def generate_aes_key(key_size: int = 32) -> bytes:
        """
        Generate a random AES key.

        Args:
            key_size: Key size in bytes (16, 24, or 32)

        Returns:
            Random AES key

        Raises:
            CryptoError: If key size is invalid
        """
        if key_size not in (16, 24, 32):
            raise CryptoError(f"Invalid AES key size: {key_size}. Must be 16, 24, or 32 bytes.")
        return os.urandom(key_size)

    @staticmethod
    def load_public_key(public_key_bytes: bytes) -> RSAPublicKey:
        """
        Load RSA public key from bytes.

        Args:
            public_key_bytes: Public key in PEM format

        Returns:
            RSAPublicKey instance

        Raises:
            CryptoError: If key loading fails
        """
        try:
            return serialization.load_pem_public_key(public_key_bytes)
        except Exception as e:
            raise CryptoError(f"Failed to load public key: {e}") from e

    @staticmethod
    def encrypt_aes_key_with_rsa(public_key: RSAPublicKey, aes_key: bytes) -> bytes:
        """
        Encrypt AES key with RSA public key.

        Args:
            public_key: RSA public key
            aes_key: AES key to encrypt

        Returns:
            Encrypted AES key

        Raises:
            CryptoError: If encryption fails
        """
        try:
            return public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as e:
            raise CryptoError(f"RSA encryption failed: {e}") from e
