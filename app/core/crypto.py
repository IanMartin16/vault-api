from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # ← CAMBIO AQUÍ
import os
import base64
from typing import Tuple

from app.core.exceptions import EncryptionError

class CryptoService:
    """
    Encryption service for secrets using AES-256-GCM.
    """
    
    def __init__(self, master_key: str):
        """Initialize with base64-encoded master key."""
        try:
            self.master_key = base64.b64decode(master_key)
            if len(self.master_key) != 32:
                raise ValueError("Master key must be 256 bits (32 bytes)")
        except Exception as e:
            raise EncryptionError(f"Invalid master key: {str(e)}")
    
    def derive_dek(self, project_id: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """Derive a Data Encryption Key (DEK) for a project using PBKDF2."""
        if salt is None:
            salt = os.urandom(16)
        
        try:
            kdf = PBKDF2HMAC(  # ← CAMBIO AQUÍ
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            dek = kdf.derive(self.master_key + project_id.encode())
            return dek, salt
        except Exception as e:
            raise EncryptionError(f"DEK derivation failed: {str(e)}")
    
    def encrypt_secret(self, plaintext: str, dek: bytes) -> dict:
        """Encrypt a secret using AES-256-GCM."""
        try:
            aesgcm = AESGCM(dek)
            nonce = os.urandom(12)  # 96 bits for GCM
            
            ciphertext = aesgcm.encrypt(
                nonce,
                plaintext.encode('utf-8'),
                None  # No additional authenticated data
            )
            
            return {
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                'nonce': base64.b64encode(nonce).decode('utf-8'),
            }
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {str(e)}")
    
    def decrypt_secret(self, encrypted_data: dict, dek: bytes) -> str:
        """Decrypt a secret."""
        try:
            aesgcm = AESGCM(dek)
            
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            nonce = base64.b64decode(encrypted_data['nonce'])
            
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode('utf-8')
        except Exception as e:
            raise EncryptionError(f"Decryption failed: {str(e)}")
    
    @staticmethod
    def generate_master_key() -> str:
        """Generate a new 256-bit master key."""
        key = os.urandom(32)
        return base64.b64encode(key).decode('utf-8')
    
    def rotate_dek(self, project_id: str, old_salt: bytes) -> Tuple[bytes, bytes]:
        """Rotate project DEK by generating new salt."""
        return self.derive_dek(project_id)