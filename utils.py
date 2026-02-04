import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class SecurityEngine:
    @staticmethod
    def derive_key(passphrase: str) -> bytes:
        """Derives a deterministic 256-bit key from a room password."""
        return hashlib.sha256(passphrase.encode()).digest()

    @staticmethod
    def encrypt(data: str, passphrase: str) -> bytes:
        """Encrypt string data (legacy compatibility)"""
        key = SecurityEngine.derive_key(passphrase)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # 96-bit unique nonce
        # Encrypts and adds a 16-byte authentication tag
        ciphertext = aesgcm.encrypt(nonce, data.encode('utf-8'), None)
        return nonce + ciphertext

    @staticmethod
    def decrypt(raw_payload: bytes, passphrase: str) -> str:
        """Decrypt to string (legacy compatibility)"""
        key = SecurityEngine.derive_key(passphrase)
        aesgcm = AESGCM(key)
        nonce = raw_payload[:12]
        ciphertext = raw_payload[12:]
        # Decrypts and verifies the authentication tag
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_bytes.decode('utf-8')

    @staticmethod
    def encrypt_binary(data: bytes, passphrase: str) -> bytes:
        """
        Encrypt raw binary data with AES-256-GCM.

        Args:
            data: Raw bytes (already binary, no encoding needed)
            passphrase: Room password (will be hashed to 256-bit key)

        Returns:
            nonce (12B) + ciphertext (variable) + auth_tag (16B)
        """
        key = SecurityEngine.derive_key(passphrase)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # Random 96-bit nonce
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext

    @staticmethod
    def decrypt_binary(raw_payload: bytes, passphrase: str) -> bytes:
        """
        Decrypt raw binary data with AES-256-GCM.

        Args:
            raw_payload: nonce (12B) + ciphertext + auth_tag (16B)
            passphrase: Room password (must match encryption key)

        Returns:
            Decrypted raw bytes

        Raises:
            cryptography.exceptions.InvalidTag: If authentication fails
                (data was tampered with or wrong password)
        """
        key = SecurityEngine.derive_key(passphrase)
        aesgcm = AESGCM(key)
        nonce = raw_payload[:12]
        ciphertext = raw_payload[12:]
        # Will raise InvalidTag exception if auth fails
        return aesgcm.decrypt(nonce, ciphertext, None)
