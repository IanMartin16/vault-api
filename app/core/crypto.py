import os
import base64
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.exceptions import EncryptionError


class CryptoService:
    """
    Encryption service for secrets using AES-256-GCM.

    Design:
    - Master key: 32 bytes, base64 encoded in environment variable.
    - Project DEK: derived from master key using HKDF-SHA256.
    - Secret encryption: AES-256-GCM with 96-bit nonce.
    - AAD: binds ciphertext to project_id, secret_key and version.
    """

    FORMAT_VERSION = 1
    KEY_VERSION = 1
    ALG = "AES-256-GCM"
    KDF = "HKDF-SHA256"
    NONCE_SIZE = 12
    SALT_SIZE = 16

    def __init__(self, master_key: str):
        """Initialize with base64-encoded 256-bit master key."""
        try:
            self.master_key = base64.b64decode(master_key, validate=True)

            if len(self.master_key) != 32:
                raise ValueError()

        except Exception:
            raise EncryptionError("Invalid encryption configuration")

    def derive_dek(
        self,
        project_id: str,
        salt: Optional[bytes] = None
    ) -> Tuple[bytes, bytes]:
        """
        Derive a project-specific Data Encryption Key using HKDF-SHA256.
        """
        if salt is None:
            salt = os.urandom(self.SALT_SIZE)

        try:
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                info=f"vsecrets:project:{project_id}".encode("utf-8"),
            )

            dek = hkdf.derive(self.master_key)
            return dek, salt

        except Exception:
            raise EncryptionError("DEK derivation failed")

    @staticmethod
    def build_aad(project_id: str, secret_key: str, version: int) -> bytes:
        """
        Build Additional Authenticated Data for AES-GCM.

        Keep this stable. Do not include mutable fields like description,
        tags or updated_at.
        """
        normalized_key = secret_key.upper()
        return f"vsecrets:v1:{project_id}:{normalized_key}:{version}".encode("utf-8")

    def encrypt_secret(
        self,
        plaintext: str,
        dek: bytes,
        *,
        project_id: str,
        secret_key: str,
        version: int
    ) -> dict:
        """
        Encrypt a secret using AES-256-GCM.
        """
        try:
            aesgcm = AESGCM(dek)
            nonce = os.urandom(self.NONCE_SIZE)
            aad = self.build_aad(project_id, secret_key, version)

            ciphertext = aesgcm.encrypt(
                nonce,
                plaintext.encode("utf-8"),
                aad
            )

            return {
                "v": self.FORMAT_VERSION,
                "alg": self.ALG,
                "kdf": self.KDF,
                "key_version": self.KEY_VERSION,
                "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
                "nonce": base64.b64encode(nonce).decode("utf-8"),
            }

        except Exception:
            raise EncryptionError("Encryption failed")

    def decrypt_secret(
        self,
        encrypted_data: dict,
        dek: bytes,
        *,
        project_id: str,
        secret_key: str,
        version: int
    ) -> str:
        """
        Decrypt a secret using AES-256-GCM.
        """
        try:
            if encrypted_data.get("v") != self.FORMAT_VERSION:
                raise EncryptionError("Unsupported encrypted payload version")

            if encrypted_data.get("alg") != self.ALG:
                raise EncryptionError("Unsupported encryption algorithm")

            aesgcm = AESGCM(dek)

            ciphertext = base64.b64decode(
                encrypted_data["ciphertext"],
                validate=True
            )
            nonce = base64.b64decode(
                encrypted_data["nonce"],
                validate=True
            )

            aad = self.build_aad(project_id, secret_key, version)

            plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
            return plaintext.decode("utf-8")

        except EncryptionError:
            raise
        except Exception:
            raise EncryptionError("Decryption failed")

    @staticmethod
    def generate_master_key() -> str:
        """
        Generate a new base64-encoded 256-bit master key.
        """
        key = os.urandom(32)
        return base64.b64encode(key).decode("utf-8")

    def generate_new_dek(self, project_id: str) -> Tuple[bytes, bytes]:
        """
        Generate a new project DEK by creating a new salt.

        Note:
        This does not rotate existing secrets by itself.
        Full DEK rotation requires decrypting and re-encrypting existing secrets.
        """
        return self.derive_dek(project_id)