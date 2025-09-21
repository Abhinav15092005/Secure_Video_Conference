import os
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import secrets
import logging
from typing import Tuple, Optional

logger = logging.getLogger(__name__)

class EncryptionManager:
    def __init__(self):
        self.backend = default_backend()
        self.salt_length = 16
        self.iv_length = 12
        self.tag_length = 16
        self.iterations = 100000
        self.key_length = 32
        
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.key_length,
                salt=salt,
                iterations=self.iterations,
                backend=self.backend
            )
            return kdf.derive(password.encode())
        except Exception as e:
            logger.error(f"Key derivation error: {e}")
            raise
    
    def encrypt(self, plaintext: str, key: bytes) -> Optional[Tuple[bytes, bytes, bytes]]:
        """Encrypt data using AES-GCM"""
        try:
            if not plaintext or not key:
                logger.error("Invalid input for encryption")
                return None
                
            # Generate random IV
            iv = secrets.token_bytes(self.iv_length)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv),
                backend=self.backend
            )
            
            # Encrypt
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
            
            return ciphertext, iv, encryptor.tag
            
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            return None
    
    def decrypt(self, ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> Optional[str]:
        """Decrypt data using AES-GCM"""
        try:
            if not ciphertext or not key or not iv or not tag:
                logger.error("Invalid input for decryption")
                return None
                
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag),
                backend=self.backend
            )
            
            # Decrypt
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            return plaintext.decode()
            
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return None
    
    def encrypt_with_password(self, plaintext: str, password: str) -> Optional[str]:
        """Encrypt data with password (returns base64 encoded string)"""
        try:
            if not plaintext or not password:
                logger.error("Invalid input for encryption")
                return None
                
            # Generate random salt
            salt = secrets.token_bytes(self.salt_length)
            
            # Derive key
            key = self.derive_key(password, salt)
            
            # Encrypt
            result = self.encrypt(plaintext, key)
            if not result:
                return None
                
            ciphertext, iv, tag = result
            
            # Combine salt + iv + tag + ciphertext
            combined = salt + iv + tag + ciphertext
            
            # Base64 encode
            return base64.urlsafe_b64encode(combined).decode()
            
        except Exception as e:
            logger.error(f"Password encryption error: {e}")
            return None
    
    def decrypt_with_password(self, encrypted_data: str, password: str) -> Optional[str]:
        """Decrypt data with password"""
        try:
            if not encrypted_data or not password:
                logger.error("Invalid input for decryption")
                return None
                
            # Base64 decode
            combined = base64.urlsafe_b64decode(encrypted_data.encode())
            
            # Extract components
            salt = combined[:self.salt_length]
            iv = combined[self.salt_length:self.salt_length + self.iv_length]
            tag = combined[self.salt_length + self.iv_length:self.salt_length + self.iv_length + self.tag_length]
            ciphertext = combined[self.salt_length + self.iv_length + self.tag_length:]
            
            # Derive key
            key = self.derive_key(password, salt)
            
            # Decrypt
            return self.decrypt(ciphertext, key, iv, tag)
            
        except Exception as e:
            logger.error(f"Password decryption error: {e}")
            return None
    
    def generate_secure_key(self) -> bytes:
        """Generate a secure random key"""
        return secrets.token_bytes(self.key_length)
    
    def key_to_string(self, key: bytes) -> str:
        """Convert key bytes to string representation"""
        return base64.urlsafe_b64encode(key).decode()
    
    def string_to_key(self, key_str: str) -> Optional[bytes]:
        """Convert string representation back to key bytes"""
        try:
            return base64.urlsafe_b64decode(key_str.encode())
        except:
            return None

# Global instance
encryption_manager = EncryptionManager()