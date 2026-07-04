"""
Content filtering and access control
"""
import re
from urllib.parse import urlparse
from typing import Optional
from config import config
from logger import logger


class FilterEngine:
    def __init__(self):
        self.blocked_domains = set(config.BLOCKED_DOMAINS)
        self.blocked_keywords = config.BLOCKED_KEYWORDS
        self.domain_patterns = [re.compile(rf'.*{re.escape(domain)}.*', re.I) 
                               for domain in self.blocked_domains]
    
    def is_blocked(self, url: str, client_addr: str) -> Optional[str]:
        """
        Check if URL should be blocked
        Returns reason if blocked, None if allowed
        """
        parsed = urlparse(url)
        host = parsed.hostname or ""
        
        # Check blocked domains
        for pattern in self.domain_patterns:
            if pattern.match(host):
                logger.log_blocked(client_addr, url, f"Blocked domain: {host}")
                return f"Domain {host} is blocked"
        
        # Check blocked keywords in URL
        for keyword in self.blocked_keywords:
            if keyword.lower() in url.lower():
                logger.log_blocked(client_addr, url, f"Blocked keyword: {keyword}")
                return f"URL contains blocked keyword: {keyword}"
        
        return None
    
    def filter_content(self, content: bytes, content_type: str) -> bytes:
        """
        Filter content based on type (placeholder for content modification)
        """
        # Implement content filtering logic here
        # Example: Remove ads, block scripts, etc.
        return content