"""
HTTP Basic Authentication handler
"""
import base64
import hashlib
import secrets
from typing import Optional, Tuple
from config import config


class AuthManager:
    def __init__(self):
        self.enabled = config.AUTH_ENABLED
        self.users = config.USERS  # {username: password_hash}
    
    def hash_password(self, password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """Hash password with salt"""
        if salt is None:
            salt = secrets.token_hex(16)
        pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode(), 
                                      salt.encode(), 100000)
        return pwdhash.hex(), salt
    
    def verify_password(self, username: str, password: str) -> bool:
        """Verify user credentials"""
        if username not in self.users:
            return False
        
        stored_hash = self.users[username]
        # For simple config, assume plaintext or pre-hashed
        # In production, use proper password hashing
        return stored_hash == password
    
    def parse_auth_header(self, header: str) -> Optional[Tuple[str, str]]:
        """Parse Basic Auth header"""
        try:
            scheme, credentials = header.split(' ', 1)
            if scheme.lower() != 'basic':
                return None
            
            decoded = base64.b64decode(credentials).decode('utf-8')
            username, password = decoded.split(':', 1)
            return username, password
        except Exception:
            return None
    
    def authenticate(self, headers: dict) -> bool:
        """Check if request is authenticated"""
        if not self.enabled:
            return True
        
        auth_header = headers.get('Proxy-Authorization') or headers.get('Authorization')
        if not auth_header:
            return False
        
        credentials = self.parse_auth_header(auth_header)
        if not credentials:
            return False
        
        username, password = credentials
        return self.verify_password(username, password)
    
    def get_auth_challenge(self) -> str:
        """Get 407 Proxy Authentication Required response"""
        return (
            "HTTP/1.1 407 Proxy Authentication Required\r\n"
            "Proxy-Authenticate: Basic realm=\"Proxy Server\"\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n\r\n"
        )