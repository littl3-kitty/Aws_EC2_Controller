"""
암호화 유틸리티
"""
import hashlib
import uuid
import base64
from cryptography.fernet import Fernet


class CryptoManager:
    """PC 고유 키 기반 암호화"""
    
    def __init__(self):
        self.cipher = self._create_cipher()
    
    def _create_cipher(self) -> Fernet:
        """PC UUID 기반 암호화 키 생성"""
        pc_id = str(uuid.getnode())
        key_bytes = hashlib.sha256(pc_id.encode()).digest()
        return Fernet(base64.urlsafe_b64encode(key_bytes))
    
    def encrypt(self, plaintext: str) -> str:
        """문자열 암호화"""
        return self.cipher.encrypt(plaintext.encode()).decode()
    
    def decrypt(self, ciphertext: str) -> str:
        """문자열 복호화"""
        return self.cipher.decrypt(ciphertext.encode()).decode()
