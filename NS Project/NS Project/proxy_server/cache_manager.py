"""
LRU Cache implementation for HTTP responses
"""
import os
import hashlib
import pickle
import time
import threading
from pathlib import Path
from typing import Optional, Dict, Any
from config import config


class CacheEntry:
    def __init__(self, data: bytes, headers: Dict[str, str], timestamp: float):
        self.data = data
        self.headers = headers
        self.timestamp = timestamp
        self.size = len(data)


class CacheManager:
    def __init__(self):
        self.cache_dir = Path(config.CACHE_DIR)
        self.cache_dir.mkdir(exist_ok=True)
        self.memory_cache: Dict[str, CacheEntry] = {}
        self.lock = threading.Lock()
        self.current_size = 0
        self.max_size = config.CACHE_MAX_SIZE
        self.ttl = config.CACHE_TTL
        
        # Load existing cache index
        self.index_file = self.cache_dir / "cache.index"
        self._load_index()
    
    def _get_cache_key(self, method: str, url: str) -> str:
        """Generate cache key from request"""
        key_string = f"{method}:{url}"
        return hashlib.sha256(key_string.encode()).hexdigest()
    
    def _load_index(self):
        """Load cache index from disk"""
        if self.index_file.exists():
            try:
                with open(self.index_file, 'rb') as f:
                    self.memory_cache = pickle.load(f)
                    self.current_size = sum(entry.size for entry in self.memory_cache.values())
            except Exception:
                self.memory_cache = {}
    
    def _save_index(self):
        """Save cache index to disk"""
        with open(self.index_file, 'wb') as f:
            pickle.dump(self.memory_cache, f)
    
    def get(self, method: str, url: str) -> Optional[CacheEntry]:
        """Retrieve cached response"""
        if not config.CACHE_ENABLED:
            return None
            
        key = self._get_cache_key(method, url)
        
        with self.lock:
            entry = self.memory_cache.get(key)
            if entry:
                # Check TTL
                if time.time() - entry.timestamp > self.ttl:
                    self._evict(key)
                    return None
                return entry
            return None
    
    def put(self, method: str, url: str, data: bytes, headers: Dict[str, str]):
        """Store response in cache"""
        if not config.CACHE_ENABLED or method != "GET":
            return
            
        # Don't cache if too large
        if len(data) > self.max_size // 10:
            return
            
        key = self._get_cache_key(method, url)
        entry = CacheEntry(data, headers, time.time())
        
        with self.lock:
            # Evict old entries if necessary
            while self.current_size + entry.size > self.max_size and self.memory_cache:
                self._evict_oldest()
            
            self.memory_cache[key] = entry
            self.current_size += entry.size
            self._save_index()
    
    def _evict(self, key: str):
        """Remove specific entry"""
        if key in self.memory_cache:
            self.current_size -= self.memory_cache[key].size
            del self.memory_cache[key]
    
    def _evict_oldest(self):
        """Remove oldest entry (LRU)"""
        if not self.memory_cache:
            return
        oldest_key = min(self.memory_cache.keys(), 
                        key=lambda k: self.memory_cache[k].timestamp)
        self._evict(oldest_key)
    
    def clear(self):
        """Clear all cache"""
        with self.lock:
            self.memory_cache.clear()
            self.current_size = 0
            self._save_index()