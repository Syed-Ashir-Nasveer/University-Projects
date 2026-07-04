"""
Utility functions for proxy server
"""
import socket
import ssl
import select
from typing import Tuple, Optional
from config import config


def create_socket() -> socket.socket:
    """Create a new socket with optimal settings"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock


def parse_request(data: bytes) -> Tuple[str, str, dict, bytes]:
    """
    Parse HTTP request
    Returns: (method, url, headers, body)
    """
    try:
        header_end = data.index(b'\r\n\r\n')
        header_data = data[:header_end].decode('utf-8', errors='ignore')
        body = data[header_end + 4:]
        
        lines = header_data.split('\r\n')
        request_line = lines[0]
        method, url, version = request_line.split(' ', 2)
        
        headers = {}
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        return method, url, headers, body
    except Exception as e:
        raise ValueError(f"Invalid HTTP request: {e}")


def build_response(status_code: int, status_text: str, 
                  headers: dict, body: bytes = b'') -> bytes:
    """Build HTTP response"""
    response_line = f"HTTP/1.1 {status_code} {status_text}\r\n"
    header_lines = ''.join(f"{k}: {v}\r\n" for k, v in headers.items())
    return f"{response_line}{header_lines}\r\n".encode() + body


def tunnel_data(src: socket.socket, dst: socket.socket, timeout: int = 60):
    """Bidirectional data tunneling for HTTPS"""
    try:
        while True:
            readable, _, _ = select.select([src, dst], [], [], timeout)
            if not readable:
                break
            
            for sock in readable:
                data = sock.recv(config.BUFFER_SIZE)
                if not data:
                    return
                
                other = dst if sock is src else src
                other.sendall(data)
    except Exception:
        pass
    finally:
        src.close()
        dst.close()


def is_valid_host(host: str) -> bool:
    """Validate hostname"""
    try:
        socket.getaddrinfo(host, None)
        return True
    except socket.gaierror:
        return False