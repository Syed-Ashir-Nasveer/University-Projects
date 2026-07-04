#!/usr/bin/env python3
"""
Advanced HTTP/HTTPS Proxy Server
Features:
- HTTP/HTTPS support with CONNECT tunneling
- Caching with TTL and LRU eviction
- Authentication (Basic Auth)
- Content filtering
- Request/Response logging
- Connection pooling
- Multi-threading
"""

import socket
import threading
import select
import ssl
import gzip
import zlib
from urllib.parse import urlparse
from typing import Optional, Tuple
from datetime import datetime

from config import config, ProxyConfig
from cache_manager import CacheManager
from logger import logger
from auth_manager import AuthManager
from filter_engine import FilterEngine
from utils import (
    create_socket, parse_request, build_response, 
    tunnel_data, is_valid_host
)


class ProxyHandler(threading.Thread):
    def __init__(self, client_socket: socket.socket, client_addr: Tuple[str, int],
                 cache: CacheManager, auth: AuthManager, filter_engine: FilterEngine):
        super().__init__(daemon=True)
        self.client = client_socket
        self.client_addr = client_addr
        self.cache = cache
        self.auth = auth
        self.filter = filter_engine
        
        self.server: Optional[socket.socket] = None
        self.is_https = False
        self.target_host = ""
        self.target_port = 80
    
    def run(self):
        """Main handler loop"""
        try:
            self.client.settimeout(config.CONNECTION_TIMEOUT)
            
            # Receive initial request
            data = self.client.recv(config.BUFFER_SIZE)
            if not data:
                return
            
            method, url, headers, body = parse_request(data)
            
            # Check authentication
            if not self.auth.authenticate(headers):
                self.client.sendall(self.auth.get_auth_challenge().encode())
                return
            
            # Handle CONNECT method (HTTPS)
            if method == "CONNECT":
                self.handle_connect(url, headers)
            else:
                # Handle HTTP request
                self.handle_http(method, url, headers, body)
                
        except Exception as e:
            logger.log_error(f"Error handling request from {self.client_addr}: {e}")
        finally:
            self.cleanup()
    
    def handle_connect(self, url: str, headers: dict):
        """Handle HTTPS CONNECT method"""
        try:
            # Parse target host:port
            if ':' in url:
                host, port = url.rsplit(':', 1)
                port = int(port)
            else:
                host, port = url, 443
            
            self.target_host = host
            self.target_port = port
            self.is_https = True
            
            # Check filter
            block_reason = self.filter.is_blocked(f"https://{host}", self.client_addr[0])
            if block_reason:
                self.send_error(403, "Forbidden", block_reason)
                return
            
            # Connect to target server
            self.server = create_socket()
            self.server.settimeout(config.CONNECTION_TIMEOUT)
            self.server.connect((host, port))
            
            # Send 200 Connection established to client
            self.client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            
            logger.log_https_tunnel(self.client_addr[0], host, port)
            
            # Start bidirectional tunnel
            tunnel_data(self.client, self.server)
            
        except Exception as e:
            logger.log_error(f"CONNECT error: {e}")
            self.send_error(502, "Bad Gateway", str(e))
    
    def handle_http(self, method: str, url: str, headers: dict, body: bytes):
        """Handle HTTP request"""
        try:
            # Parse URL
            if url.startswith('http://'):
                parsed = urlparse(url)
                host = parsed.hostname
                port = parsed.port or 80
                path = parsed.path or '/'
                if parsed.query:
                    path += '?' + parsed.query
            else:
                # Relative URL (shouldn't happen with proper proxy config)
                host = headers.get('Host', '').split(':')[0]
                port = 80
                path = url
            
            self.target_host = host
            self.target_port = port
            
            # Check filter
            full_url = f"http://{host}{path}"
            block_reason = self.filter.is_blocked(full_url, self.client_addr[0])
            if block_reason:
                self.send_error(403, "Forbidden", block_reason)
                return
            
            # Check cache for GET requests
            if method == "GET":
                cached = self.cache.get(method, full_url)
                if cached:
                    # Serve from cache
                    response = self.build_cached_response(cached)
                    self.client.sendall(response)
                    logger.log_request(self.client_addr[0], method, full_url, 
                                     200, len(cached.data), cached=True)
                    return
            
            # Modify headers for proxy
            headers['Connection'] = 'close'
            headers.pop('Proxy-Connection', None)
            if 'Proxy-Authorization' in headers:
                del headers['Proxy-Authorization']
            
            # Build request
            request_line = f"{method} {path} HTTP/1.1\r\n"
            header_lines = ''.join(f"{k}: {v}\r\n" for k, v in headers.items())
            request_data = f"{request_line}{header_lines}\r\n".encode() + body
            
            # Connect to target server
            self.server = create_socket()
            self.server.settimeout(config.CONNECTION_TIMEOUT)
            self.server.connect((host, port))
            
            # Send request
            self.server.sendall(request_data)
            
            # Receive and forward response
            response_data = self.receive_full_response()
            
            # Parse response for caching
            if method == "GET":
                self.cache_response(method, full_url, response_data)
            
            # Send to client
            self.client.sendall(response_data)
            
            # Log request
            status_code = self.parse_status_code(response_data)
            logger.log_request(self.client_addr[0], method, full_url, 
                             status_code, len(response_data))
            
        except Exception as e:
            logger.log_error(f"HTTP error: {e}")
            self.send_error(502, "Bad Gateway", str(e))
    
    def receive_full_response(self) -> bytes:
        """Receive complete HTTP response"""
        chunks = []
        while True:
            chunk = self.server.recv(config.BUFFER_SIZE)
            if not chunk:
                break
            chunks.append(chunk)
            
            # Check if we received all data (simple check)
            if len(chunk) < config.BUFFER_SIZE:
                # Try to peek if there's more data
                self.server.setblocking(0)
                try:
                    extra = self.server.recv(config.BUFFER_SIZE)
                    if extra:
                        chunks.append(extra)
                except:
                    pass
                self.server.setblocking(1)
                break
        
        return b''.join(chunks)
    
    def cache_response(self, method: str, url: str, response_data: bytes):
        """Cache response if cacheable"""
        try:
            # Parse response headers
            header_end = response_data.index(b'\r\n\r\n')
            header_section = response_data[:header_end].decode('utf-8', errors='ignore')
            
            headers = {}
            for line in header_section.split('\r\n')[1:]:
                if ':' in line:
                    k, v = line.split(':', 1)
                    headers[k.strip().lower()] = v.strip()
            
            # Check if cacheable
            if 'no-store' in headers.get('cache-control', ''):
                return
            
            # Cache the response
            body = response_data[header_end + 4:]
            self.cache.put(method, url, body, headers)
            
        except Exception:
            pass
    
    def build_cached_response(self, entry) -> bytes:
        """Build HTTP response from cache entry"""
        headers = {
            'HTTP/1.1 200 OK': '',
            'Content-Length': str(len(entry.data)),
        }   
        header_lines = ''.join(f"{k}: {v}\r\n" for k, v in headers.items())
        return f"{header_lines}\r\n".encode() + entry.data      