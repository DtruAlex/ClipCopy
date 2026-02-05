"""
Security utilities for encrypting and decrypting clipboard data.

This module provides AES-256-GCM encryption for clipboard synchronization.
Each room has a password that is used to derive an encryption key.
"""

import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SecurityEngine:
    """
    Handles encryption and decryption for clipboard data.

    Uses AES-256-GCM (Advanced Encryption Standard with Galois/Counter Mode):
    - 256-bit key strength (derived from password)
    - Built-in authentication tag (prevents tampering)
    - Random nonce for each encryption (prevents replay attacks)
    """

    # Size constants for clarity
    NONCE_SIZE = 12  # 96 bits as recommended for GCM
    KEY_SIZE = 32    # 256 bits for AES-256

    @staticmethod
    def derive_key(passphrase: str) -> bytes:
        """
        Convert a room password into a cryptographic key.

        Uses SHA-256 hash to derive a deterministic 256-bit key from the password.
        Same password always produces the same key.

        Args:
            passphrase: The room password (string)

        Returns:
            32-byte encryption key
        """
        return hashlib.sha256(passphrase.encode()).digest()

    @staticmethod
    def encrypt(data: str, passphrase: str) -> bytes:
        """
        Encrypt text data (for simple string messages).

        Args:
            data: String to encrypt
            passphrase: Room password

        Returns:
            Encrypted data as: [nonce (12 bytes)][encrypted data + auth tag]
        """
        key = SecurityEngine.derive_key(passphrase)
        aesgcm = AESGCM(key)
        nonce = os.urandom(SecurityEngine.NONCE_SIZE)

        # Encrypt and add authentication tag
        ciphertext = aesgcm.encrypt(nonce, data.encode('utf-8'), None)

        # Return nonce + ciphertext (nonce is needed for decryption)
        return nonce + ciphertext

    @staticmethod
    def decrypt(encrypted_payload: bytes, passphrase: str) -> str:
        """
        Decrypt text data.

        Args:
            encrypted_payload: Encrypted bytes (nonce + ciphertext + tag)
            passphrase: Room password (must match encryption password)

        Returns:
            Decrypted string

        Raises:
            cryptography.exceptions.InvalidTag: If password is wrong or data was tampered with
        """
        key = SecurityEngine.derive_key(passphrase)
        aesgcm = AESGCM(key)

        # Split nonce and ciphertext
        nonce = encrypted_payload[:SecurityEngine.NONCE_SIZE]
        ciphertext = encrypted_payload[SecurityEngine.NONCE_SIZE:]

        # Decrypt and verify authentication tag
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_bytes.decode('utf-8')

    @staticmethod
    def encrypt_binary(data: bytes, passphrase: str) -> bytes:
        """
        Encrypt binary data (for clipboard content with images, etc.).

        Args:
            data: Raw binary data to encrypt
            passphrase: Room password

        Returns:
            Encrypted data as: [nonce (12 bytes)][encrypted data + auth tag (16 bytes)]
        """
        key = SecurityEngine.derive_key(passphrase)
        aesgcm = AESGCM(key)
        nonce = os.urandom(SecurityEngine.NONCE_SIZE)

        # Encrypt the binary data
        ciphertext = aesgcm.encrypt(nonce, data, None)

        return nonce + ciphertext

    @staticmethod
    def decrypt_binary(encrypted_payload: bytes, passphrase: str) -> bytes:
        """
        Decrypt binary data.

        Args:
            encrypted_payload: Encrypted bytes (nonce + ciphertext + tag)
            passphrase: Room password (must match encryption password)

        Returns:
            Decrypted binary data

        Raises:
            cryptography.exceptions.InvalidTag: If password is wrong or data was tampered with
        """
        key = SecurityEngine.derive_key(passphrase)
        aesgcm = AESGCM(key)

        # Extract nonce and ciphertext
        nonce = encrypted_payload[:SecurityEngine.NONCE_SIZE]
        ciphertext = encrypted_payload[SecurityEngine.NONCE_SIZE:]

        # Decrypt and verify authentication
        return aesgcm.decrypt(nonce, ciphertext, None)
