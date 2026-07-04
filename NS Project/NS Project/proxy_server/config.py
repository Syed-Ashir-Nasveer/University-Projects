"""
Proxy Server Configuration
"""
import os
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class ProxyConfig:
    # Server Settings
    HOST: str = "0.0.0.0"
    PORT: int = 8888
    BACKLOG: int = 100
    
    # Buffer sizes
    BUFFER_SIZE: int = 8192
    MAX_REQUEST_SIZE: int = 1024 * 1024  # 1MB
    
    # Timeouts (seconds)
    CONNECTION_TIMEOUT: int = 30
    KEEP_ALIVE_TIMEOUT: int = 5
    
    # Caching
    CACHE_ENABLED: bool = True
    CACHE_DIR: str = "./cache"
    CACHE_MAX_SIZE: int = 100 * 1024 * 1024  # 100MB
    CACHE_TTL: int = 3600  # 1 hour
    
    # Authentication
    AUTH_ENABLED: bool = False
    USERS: dict = None
    
    # Filtering
    BLOCKED_DOMAINS: List[str] = None
    BLOCKED_KEYWORDS: List[str] = None
    
    # Logging
    LOG_FILE: str = "proxy.log"
    LOG_LEVEL: str = "INFO"
    
    # SSL/TLS
    SSL_CERT: Optional[str] = None
    SSL_KEY: Optional[str] = None
    
    def __post_init__(self):
        if self.USERS is None:
            self.USERS = {}
        if self.BLOCKED_DOMAINS is None:
            self.BLOCKED_DOMAINS = []
        if self.BLOCKED_KEYWORDS is None:
            self.BLOCKED_KEYWORDS = []


# Default configuration instance
config = ProxyConfig()