import socket
import time

print("Testing network operations...")

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    
    print("Attempting to connect to google.com:80...")
    sock.connect(("google.com", 80))
    print("✓ Connection successful")
    
    sock.send(b"GET / HTTP/1.1\r\nHost: google.com\r\n\r\n")
    print("✓ Data sent")
    
    response = sock.recv(1024)
    print(f"✓ Received {len(response)} bytes")
    
    sock.close()
    print("✓ Connection closed")
    
except Exception as e:
    print(f"✗ Network operation failed: {e}")