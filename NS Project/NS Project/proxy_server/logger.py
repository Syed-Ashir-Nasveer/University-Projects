"""
Advanced logging system for proxy server
"""
import logging
import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, Any
from config import config


class ProxyLogger:
    def __init__(self):
        self.logger = logging.getLogger("ProxyServer")
        self.logger.setLevel(getattr(logging, config.LOG_LEVEL))
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_format = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(console_format)
        self.logger.addHandler(console_handler)
        
        # File handler
        if config.LOG_FILE:
            file_handler = logging.FileHandler(config.LOG_FILE)
            file_handler.setLevel(logging.DEBUG)
            file_format = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(file_format)
            self.logger.addHandler(file_handler)
        
        # Request stats
        self.stats_lock = threading.Lock()
        self.request_count = 0
        self.bytes_transferred = 0
        self.blocked_requests = 0
    
    def log_request(self, client_addr: str, method: str, url: str, 
                   status_code: int, size: int, cached: bool = False):
        """Log HTTP request"""
        with self.stats_lock:
            self.request_count += 1
            self.bytes_transferred += size
        
        cache_status = "HIT" if cached else "MISS"
        self.logger.info(f"{client_addr} - {method} {url} - {status_code} - {size}b - Cache:{cache_status}")
    
    def log_https_tunnel(self, client_addr: str, host: str, port: int):
        """Log HTTPS CONNECT tunnel"""
        self.logger.info(f"{client_addr} - CONNECT {host}:{port} - Tunnel Established")
    
    def log_blocked(self, client_addr: str, url: str, reason: str):
        """Log blocked request"""
        with self.stats_lock:
            self.blocked_requests += 1
        self.logger.warning(f"{client_addr} - BLOCKED {url} - Reason: {reason}")
    
    def log_error(self, message: str, exc_info: bool = False):
        """Log error"""
        self.logger.error(message, exc_info=exc_info)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics"""
        with self.stats_lock:
            return {
                "total_requests": self.request_count,
                "bytes_transferred": self.bytes_transferred,
                "blocked_requests": self.blocked_requests,
                "uptime": datetime.now().isoformat()
            }


# Global logger instance
logger = ProxyLogger()