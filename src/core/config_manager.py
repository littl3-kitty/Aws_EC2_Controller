"""
설정 파일 관리
"""
import os
import json
from pathlib import Path
from typing import Optional

from src.utils.crypto import CryptoManager


class ConfigManager:
    """애플리케이션 설정 관리"""
    
    DEFAULT_CONFIG_DIR = Path.home() / '.aws_ctrl'
    DEFAULT_CREDENTIAL_FILE = 'credentials.enc'
    
    def __init__(self, config_dir: Optional[Path] = None):
        self.config_dir = config_dir or self.DEFAULT_CONFIG_DIR
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self.credential_file = self.config_dir / self.DEFAULT_CREDENTIAL_FILE
        self.crypto = CryptoManager()
    
    def save_credentials(self, access_key: str, secret_key: str):
        """자격증명 암호화 저장"""
        data = {
            'access_key': self.crypto.encrypt(access_key),
            'secret_key': self.crypto.encrypt(secret_key)
        }
        
        with open(self.credential_file, 'w') as f:
            json.dump(data, f)
    
    def load_credentials(self) -> Optional[tuple]:
        """자격증명 로드"""
        if not self.credential_file.exists():
            return None
        
        try:
            with open(self.credential_file, 'r') as f:
                data = json.load(f)
            
            access_key = self.crypto.decrypt(data['access_key'])
            secret_key = self.crypto.decrypt(data['secret_key'])
            
            return access_key, secret_key
        except Exception:
            return None
    
    def has_saved_credentials(self) -> bool:
        """저장된 자격증명이 있는지 확인"""
        return self.credential_file.exists()
