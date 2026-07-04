"""
Network Scanner Module
Provides port scanning and network discovery functionality
"""

import socket
import threading
import time
from datetime import datetime
import ipaddress


class PortScanner:
    """Port scanner with multiple scan types"""
    
    def __init__(self, target, start_port, end_port, scan_type="TCP"):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.scan_type = scan_type
        self.results = []
        self.lock = threading.Lock()
        
        # Common service ports
        self.services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Proxy",
            27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch"
        }
    
    def scan(self):
        """Perform port scan"""
        print(f"[*] Starting {self.scan_type} scan on {self.target}")
        print(f"[*] Scanning ports {self.start_port}-{self.end_port}")
        
        start_time = time.time()
        
        # Resolve hostname to IP
        try:
            ip = socket.gethostbyname(self.target)
            print(f"[+] Resolved {self.target} to {ip}")
        except socket.gaierror:
            print(f"[-] Could not resolve hostname: {self.target}")
            return []
        
        # Scan ports
        threads = []
        for port in range(self.start_port, self.end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(ip, port))
            thread.daemon = True
            thread.start()
            threads.append(thread)
            
            # Limit concurrent threads
            if len(threads) >= 100:
                for t in threads:
                    t.join()
                threads = []
        
        # Wait for remaining threads
        for thread in threads:
            thread.join()
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\n[+] Scan completed in {duration:.2f} seconds")
        print(f"[+] Found {len(self.results)} open ports")
        
        return sorted(self.results, key=lambda x: x['port'])
    
    def scan_port(self, ip, port):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                service = self.services.get(port, "Unknown")
                banner = self.grab_banner(sock)
                
                with self.lock:
                    self.results.append({
                        'port': port,
                        'state': 'Open',
                        'service': service,
                        'banner': banner
                    })
                    print(f"[+] Port {port} ({service}) is open - {banner}")
            
            sock.close()
        except socket.error:
            pass
        except Exception as e:
            pass
    
    def grab_banner(self, sock):
        """Attempt to grab service banner"""
        try:
            sock.send(b"Hello\r\n")
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:50] if banner else "No banner"
        except:
            return "No banner"


class NetworkDiscovery:
    """Network discovery and host enumeration"""
    
    def __init__(self, network_range, method="Ping Sweep"):
        self.network_range = network_range
        self.method = method
        self.hosts = []
        self.lock = threading.Lock()
    
    def discover(self):
        """Discover hosts on network"""
        print(f"[*] Discovering hosts in {self.network_range}")
        print(f"[*] Using method: {self.method}")
        
        try:
            network = ipaddress.ip_network(self.network_range, strict=False)
        except ValueError as e:
            print(f"[-] Invalid network range: {e}")
            return []
        
        start_time = time.time()
        threads = []
        
        for ip in network.hosts():
            thread = threading.Thread(target=self.check_host, args=(str(ip),))
            thread.daemon = True
            thread.start()
            threads.append(thread)
            
            # Limit concurrent threads
            if len(threads) >= 50:
                for t in threads:
                    t.join()
                threads = []
        
        # Wait for remaining threads
        for thread in threads:
            thread.join()
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\n[+] Discovery completed in {duration:.2f} seconds")
        print(f"[+] Found {len(self.hosts)} active hosts")
        
        return self.hosts
    
    def check_host(self, ip):
        """Check if host is alive"""
        try:
            # Try to connect to port 80 (HTTP) as a quick check
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, 80))
            sock.close()
            
            if result == 0 or self.ping_host(ip):
                hostname = self.get_hostname(ip)
                mac = self.get_mac_address(ip)
                os_guess = self.guess_os(ip)
                open_ports = self.quick_port_scan(ip)
                
                with self.lock:
                    self.hosts.append({
                        'ip': ip,
                        'mac': mac,
                        'hostname': hostname,
                        'os': os_guess,
                        'status': 'Up',
                        'ports': open_ports
                    })
                    print(f"[+] Found host: {ip} ({hostname})")
        except Exception as e:
            pass
    
    def ping_host(self, ip):
        """Ping a host (simplified check)"""
        import platform
        import subprocess
        
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', '-W', '1', ip]
        
        try:
            result = subprocess.run(command, stdout=subprocess.DEVNULL, 
                                  stderr=subprocess.DEVNULL, timeout=2)
            return result.returncode == 0
        except:
            return False
    
    def get_hostname(self, ip):
        """Get hostname for IP"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Unknown"
    
    def get_mac_address(self, ip):
        """Get MAC address (simplified)"""
        # This would use ARP tables in real implementation
        return "00:00:00:00:00:00"
    
    def guess_os(self, ip):
        """Guess operating system based on TTL and ports"""
        # Simplified OS detection
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, 445))  # SMB port
            sock.close()
            
            if result == 0:
                return "Windows"
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, 22))  # SSH port
            sock.close()
            
            if result == 0:
                return "Linux/Unix"
        except:
            pass
        
        return "Unknown"
    
    def quick_port_scan(self, ip):
        """Quick scan of common ports"""
        common_ports = [21, 22, 23, 25, 80, 443, 445, 3389]
        open_ports = []
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
            except:
                pass
        
        return open_ports


class PacketSniffer:
    """Packet sniffer for network traffic analysis"""
    
    def __init__(self, interface="eth0", packet_filter=""):
        self.interface = interface
        self.filter = packet_filter
        self.packets = []
        self.running = False
    
    def start(self):
        """Start packet sniffing"""
        print(f"[*] Starting packet capture on {self.interface}")
        print(f"[*] Filter: {self.filter}")
        self.running = True
        
        # Note: Actual packet sniffing requires scapy library and root privileges
        # This is a placeholder implementation
        print("[!] Packet sniffing requires scapy library and root privileges")
        print("[!] Install: pip install scapy")
        print("[!] Run with: sudo python3 main.py")
    
    def stop(self):
        """Stop packet sniffing"""
        self.running = False
        print(f"\n[+] Captured {len(self.packets)} packets")
    
    def packet_callback(self, packet):
        """Callback for captured packets"""
        self.packets.append(packet)
        # Process and display packet info


# Testing functions
def test_port_scanner():
    """Test port scanner"""
    print("\n" + "="*60)
    print("TESTING PORT SCANNER")
    print("="*60)
    
    scanner = PortScanner("127.0.0.1", 1, 1000, "TCP")
    results = scanner.scan()
    
    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    for result in results:
        print(f"Port {result['port']}: {result['state']} - "
              f"{result['service']} - {result['banner']}")


def test_network_discovery():
    """Test network discovery"""
    print("\n" + "="*60)
    print("TESTING NETWORK DISCOVERY")
    print("="*60)
    
    discovery = NetworkDiscovery("192.168.1.0/28", "Ping Sweep")
    hosts = discovery.discover()
    
    print("\n" + "="*60)
    print("DISCOVERED HOSTS")
    print("="*60)
    for host in hosts:
        print(f"IP: {host['ip']}")
        print(f"  Hostname: {host['hostname']}")
        print(f"  OS: {host['os']}")
        print(f"  Ports: {host['ports']}")
        print()


if __name__ == "__main__":
    print("🛡️ Network Security Tool - Scanner Module")
    print("This module provides network scanning functionality")
    print("\nAvailable tests:")
    print("1. Port Scanner Test")
    print("2. Network Discovery Test")
    
    choice = input("\nSelect test (1 or 2): ")
    
    if choice == "1":
        test_port_scanner()
    elif choice == "2":
        test_network_discovery()
    else:
        print("Invalid choice")
