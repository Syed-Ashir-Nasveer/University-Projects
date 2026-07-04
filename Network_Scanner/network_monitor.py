"""
network_monitor.py
==================
Live Network Traffic Monitoring & Intrusion Prevention System (IPS)
Captures and analyzes network packets in real-time

Author: [Your Name]
Date: December 2024
"""

import time
import json
import sqlite3
from datetime import datetime
from collections import defaultdict
from threading import Thread, Lock
import re

# Network packet capture
try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw, ARP
    from scapy.layers.http import HTTPRequest
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Scapy not installed. Install with: pip install scapy")

# For IP geolocation
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class NetworkMonitor:
    """Real-time network traffic monitor and IPS"""
    
    def __init__(self, interface=None):
        """
        Initialize Network Monitor
        
        Args:
            interface (str): Network interface to monitor (None = all interfaces)
        """
        self.interface = interface
        self.db_path = 'network_monitor.db'
        self.is_monitoring = False
        self.packet_count = 0
        self.suspicious_ips = set()
        
        # Traffic statistics
        self.stats = {
            'total_packets': 0,
            'http_requests': 0,
            'dns_queries': 0,
            'suspicious_activities': 0,
            'blocked_ips': 0
        }
        
        # Rate limiting
        self.ip_request_count = defaultdict(int)
        self.ip_last_seen = {}
        self.lock = Lock()
        
        # Suspicious patterns
        self.suspicious_patterns = {
            'sql_injection': [
                r"(\bunion\b.*\bselect\b)",
                r"(\bor\b.*=.*)",
                r"('|\").*(\bor\b|\band\b).*('|\")",
                r"(;|\|\||&&).*(\bdrop\b|\bdelete\b|\binsert\b)"
            ],
            'xss': [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"onerror\s*=",
                r"<iframe[^>]*>"
            ],
            'path_traversal': [
                r"\.\./",
                r"\.\.\\"
            ],
            'command_injection': [
                r"[;&|].*\b(cat|ls|pwd|whoami|wget|curl)\b",
                r"`.*`",
                r"\$\(.*\)"
            ]
        }
        
        # Blocked IPs list
        self.blocked_ips = set()
        
        self.init_database()
        print("[+] Network Monitor initialized")
    
    def init_database(self):
        """Initialize database for storing traffic logs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Traffic logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                payload TEXT,
                is_suspicious BOOLEAN,
                threat_type TEXT,
                action_taken TEXT
            )
        ''')
        
        # Suspicious activities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS suspicious_activities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                attack_type TEXT,
                details TEXT,
                severity TEXT,
                blocked BOOLEAN
            )
        ''')
        
        # Blocked IPs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE,
                reason TEXT,
                blocked_at TEXT,
                unblock_at TEXT
            )
        ''')
        
        # Network statistics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                total_packets INTEGER,
                http_requests INTEGER,
                dns_queries INTEGER,
                suspicious_count INTEGER,
                top_talkers TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        print("[+] Network monitoring database initialized")
    
    def start_monitoring(self, duration=None):
        """
        Start monitoring network traffic
        
        Args:
            duration (int): Duration in seconds (None = continuous)
        """
        if not SCAPY_AVAILABLE:
            print("[!] Cannot start monitoring: Scapy not available")
            return
        
        self.is_monitoring = True
        print(f"\n[*] Starting network monitoring...")
        print(f"[*] Interface: {self.interface or 'All interfaces'}")
        print(f"[*] Duration: {duration or 'Continuous'} seconds")
        print("[*] Press Ctrl+C to stop\n")
        
        try:
            # Start packet capture
            sniff(
                iface=self.interface,
                prn=self.process_packet,
                store=False,
                timeout=duration
            )
        except KeyboardInterrupt:
            print("\n[*] Monitoring stopped by user")
        except Exception as e:
            print(f"[!] Monitoring error: {str(e)}")
        finally:
            self.stop_monitoring()
    
    def process_packet(self, packet):
        """Process each captured packet"""
        try:
            self.packet_count += 1
            self.stats['total_packets'] += 1
            
            # Extract packet information
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = packet[IP].proto
                
                # Check if IP is blocked
                if src_ip in self.blocked_ips:
                    self.log_suspicious_activity(
                        src_ip, 
                        'Blocked IP attempting connection',
                        'Blocked IP',
                        'HIGH'
                    )
                    return
                
                # Rate limiting check
                if self.check_rate_limit(src_ip):
                    self.log_suspicious_activity(
                        src_ip,
                        'Rate limit exceeded - Possible DDoS',
                        'Rate Limit Violation',
                        'HIGH'
                    )
                    self.block_ip(src_ip, 'Rate limit exceeded')
                
                # Analyze TCP packets
                if TCP in packet:
                    self.analyze_tcp_packet(packet, src_ip, dst_ip)
                
                # Analyze UDP packets
                elif UDP in packet:
                    self.analyze_udp_packet(packet, src_ip, dst_ip)
                
                # Analyze HTTP requests
                if packet.haslayer(HTTPRequest):
                    self.analyze_http_request(packet, src_ip)
                
                # Analyze DNS queries
                if packet.haslayer(DNSQR):
                    self.analyze_dns_query(packet, src_ip)
                
                # Analyze ARP packets (ARP spoofing detection)
                if ARP in packet:
                    self.analyze_arp_packet(packet)
            
            # Display progress every 100 packets
            if self.packet_count % 100 == 0:
                self.print_stats()
        
        except Exception as e:
            print(f"[!] Packet processing error: {str(e)}")
    
    def analyze_tcp_packet(self, packet, src_ip, dst_ip):
        """Analyze TCP packets for suspicious activity"""
        try:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            
            # Check for port scanning (SYN scan)
            if flags == 'S':  # SYN flag only
                with self.lock:
                    if not hasattr(self, 'syn_packets'):
                        self.syn_packets = defaultdict(set)
                    
                    self.syn_packets[src_ip].add(dst_port)
                    
                    # If same IP scanned more than 20 ports
                    if len(self.syn_packets[src_ip]) > 20:
                        self.log_suspicious_activity(
                            src_ip,
                            f'Port scanning detected - {len(self.syn_packets[src_ip])} ports',
                            'Port Scan',
                            'HIGH'
                        )
                        self.block_ip(src_ip, 'Port scanning detected')
            
            # Check for common attack ports
            suspicious_ports = [
                22,    # SSH brute force
                23,    # Telnet
                3389,  # RDP
                445,   # SMB
                1433,  # SQL Server
                3306,  # MySQL
                5432   # PostgreSQL
            ]
            
            if dst_port in suspicious_ports:
                self.log_traffic(
                    src_ip, dst_ip, 'TCP', src_port, dst_port,
                    f'Connection to suspicious port {dst_port}',
                    is_suspicious=True,
                    threat_type='Suspicious Port Access'
                )
            
            # Analyze payload for attacks
            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                self.analyze_payload(payload, src_ip, 'TCP')
        
        except Exception as e:
            pass  # Silent fail for malformed packets
    
    def analyze_udp_packet(self, packet, src_ip, dst_ip):
        """Analyze UDP packets"""
        try:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            
            # Log UDP traffic
            self.log_traffic(
                src_ip, dst_ip, 'UDP', src_port, dst_port,
                'UDP packet',
                is_suspicious=False
            )
        
        except Exception as e:
            pass
    
    def analyze_http_request(self, packet, src_ip):
        """Analyze HTTP requests for attacks"""
        try:
            http_layer = packet[HTTPRequest]
            url = http_layer.Host.decode() + http_layer.Path.decode()
            method = http_layer.Method.decode()
            
            self.stats['http_requests'] += 1
            
            # Check for SQL injection in URL
            for pattern in self.suspicious_patterns['sql_injection']:
                if re.search(pattern, url, re.IGNORECASE):
                    self.log_suspicious_activity(
                        src_ip,
                        f'SQL Injection attempt in URL: {url}',
                        'SQL Injection',
                        'CRITICAL'
                    )
                    self.block_ip(src_ip, 'SQL Injection attempt')
                    return
            
            # Check for XSS
            for pattern in self.suspicious_patterns['xss']:
                if re.search(pattern, url, re.IGNORECASE):
                    self.log_suspicious_activity(
                        src_ip,
                        f'XSS attempt in URL: {url}',
                        'Cross-Site Scripting',
                        'HIGH'
                    )
                    return
            
            # Check for path traversal
            for pattern in self.suspicious_patterns['path_traversal']:
                if re.search(pattern, url):
                    self.log_suspicious_activity(
                        src_ip,
                        f'Path traversal attempt: {url}',
                        'Path Traversal',
                        'HIGH'
                    )
                    return
        
        except Exception as e:
            pass
    
    def analyze_dns_query(self, packet, src_ip):
        """Analyze DNS queries for suspicious domains"""
        try:
            query = packet[DNSQR].qname.decode('utf-8')
            self.stats['dns_queries'] += 1
            
            # Suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.onion']
            
            if any(query.endswith(tld) for tld in suspicious_tlds):
                self.log_suspicious_activity(
                    src_ip,
                    f'DNS query to suspicious domain: {query}',
                    'Suspicious DNS',
                    'MEDIUM'
                )
        
        except Exception as e:
            pass
    
    def analyze_arp_packet(self, packet):
        """Detect ARP spoofing attacks"""
        try:
            if packet[ARP].op == 2:  # ARP reply
                arp_src_ip = packet[ARP].psrc
                arp_src_mac = packet[ARP].hwsrc
                
                # Check for duplicate IPs with different MACs
                if not hasattr(self, 'arp_table'):
                    self.arp_table = {}
                
                if arp_src_ip in self.arp_table:
                    if self.arp_table[arp_src_ip] != arp_src_mac:
                        self.log_suspicious_activity(
                            arp_src_ip,
                            f'Possible ARP spoofing: IP {arp_src_ip} has multiple MACs',
                            'ARP Spoofing',
                            'CRITICAL'
                        )
                else:
                    self.arp_table[arp_src_ip] = arp_src_mac
        
        except Exception as e:
            pass
    
    def analyze_payload(self, payload, src_ip, protocol):
        """Analyze packet payload for malicious content"""
        try:
            # Check all attack patterns
            for attack_type, patterns in self.suspicious_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, payload, re.IGNORECASE):
                        self.log_suspicious_activity(
                            src_ip,
                            f'{attack_type.upper()} pattern detected in {protocol} payload',
                            attack_type,
                            'HIGH'
                        )
                        return True
            
            return False
        
        except Exception as e:
            return False
    
    def check_rate_limit(self, ip):
        """Check if IP exceeded rate limit (simple DDoS detection)"""
        with self.lock:
            current_time = time.time()
            
            # Reset counter every 10 seconds
            if ip in self.ip_last_seen:
                if current_time - self.ip_last_seen[ip] > 10:
                    self.ip_request_count[ip] = 0
            
            self.ip_request_count[ip] += 1
            self.ip_last_seen[ip] = current_time
            
            # If more than 100 packets in 10 seconds
            if self.ip_request_count[ip] > 100:
                return True
            
            return False
    
    def block_ip(self, ip, reason):
        """Block an IP address"""
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            self.stats['blocked_ips'] += 1
            
            # Save to database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR IGNORE INTO blocked_ips (ip_address, reason, blocked_at)
                VALUES (?, ?, ?)
            ''', (ip, reason, datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            
            print(f"\n[!] BLOCKED IP: {ip} - Reason: {reason}")
    
    def log_traffic(self, src_ip, dst_ip, protocol, src_port, dst_port, 
                   payload, is_suspicious=False, threat_type=None):
        """Log network traffic to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO traffic_logs 
                (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, 
                 payload, is_suspicious, threat_type, action_taken)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                src_ip, dst_ip, protocol, src_port, dst_port,
                payload[:500],  # Limit payload size
                is_suspicious,
                threat_type,
                'BLOCKED' if src_ip in self.blocked_ips else 'ALLOWED'
            ))
            
            conn.commit()
            conn.close()
        
        except Exception as e:
            print(f"[!] Logging error: {str(e)}")
    
    def log_suspicious_activity(self, src_ip, details, attack_type, severity):
        """Log suspicious activity"""
        self.stats['suspicious_activities'] += 1
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO suspicious_activities 
                (timestamp, src_ip, attack_type, details, severity, blocked)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                src_ip, attack_type, details, severity,
                src_ip in self.blocked_ips
            ))
            
            conn.commit()
            conn.close()
            
            print(f"\n[!] SUSPICIOUS: {attack_type} from {src_ip}")
            print(f"    Details: {details}")
            print(f"    Severity: {severity}")
        
        except Exception as e:
            print(f"[!] Logging error: {str(e)}")
    
    def print_stats(self):
        """Print current statistics"""
        print(f"\r[*] Packets: {self.stats['total_packets']} | "
              f"HTTP: {self.stats['http_requests']} | "
              f"DNS: {self.stats['dns_queries']} | "
              f"Suspicious: {self.stats['suspicious_activities']} | "
              f"Blocked IPs: {self.stats['blocked_ips']}", end='', flush=True)
    
    def stop_monitoring(self):
        """Stop monitoring and save statistics"""
        self.is_monitoring = False
        
        # Save final statistics
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO network_stats 
            (timestamp, total_packets, http_requests, dns_queries, suspicious_count)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            self.stats['total_packets'],
            self.stats['http_requests'],
            self.stats['dns_queries'],
            self.stats['suspicious_activities']
        ))
        
        conn.commit()
        conn.close()
        
        print("\n\n" + "="*60)
        print("MONITORING SESSION SUMMARY")
        print("="*60)
        print(f"Total Packets Captured: {self.stats['total_packets']}")
        print(f"HTTP Requests: {self.stats['http_requests']}")
        print(f"DNS Queries: {self.stats['dns_queries']}")
        print(f"Suspicious Activities: {self.stats['suspicious_activities']}")
        print(f"Blocked IPs: {self.stats['blocked_ips']}")
        print("="*60 + "\n")
    
    def get_suspicious_activities(self, limit=50):
        """Get recent suspicious activities"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM suspicious_activities 
            ORDER BY id DESC LIMIT ?
        ''', (limit,))
        
        activities = cursor.fetchall()
        conn.close()
        
        return activities
    
    def get_blocked_ips(self):
        """Get list of blocked IPs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM blocked_ips ORDER BY blocked_at DESC')
        blocked = cursor.fetchall()
        
        conn.close()
        return blocked
    
    def unblock_ip(self, ip):
        """Unblock an IP address"""
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE blocked_ips 
                SET unblock_at = ? 
                WHERE ip_address = ?
            ''', (datetime.now().isoformat(), ip))
            
            conn.commit()
            conn.close()
            
            print(f"[+] IP {ip} unblocked")


# Main execution
if __name__ == "__main__":
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║     Network Traffic Monitor & IPS System v1.0            ║
    ║          Real-time Intrusion Prevention                  ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    if not SCAPY_AVAILABLE:
        print("\n[!] Scapy is required for packet capture")
        print("[!] Install with: pip install scapy")
        print("[!] On Windows, also install Npcap from: https://npcap.com/")
        exit(1)
    
    # Check for admin/root privileges
    import os
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except:
            is_admin = False
    else:  # Linux/Mac
        is_admin = os.geteuid() == 0
    
    if not is_admin:
        print("\n[!] WARNING: This program requires administrator/root privileges")
        print("[!] Run as: sudo python network_monitor.py (Linux/Mac)")
        print("[!] Run as: Administrator (Windows)")
        print("\n[*] Continuing with limited functionality...\n")
    
    # Initialize monitor
    monitor = NetworkMonitor()
    
    print("\nOptions:")
    print("1. Start monitoring (duration)")
    print("2. Start continuous monitoring")
    print("3. View suspicious activities")
    print("4. View blocked IPs")
    print("5. Unblock IP")
    
    choice = input("\nYour choice: ").strip()
    
    if choice == '1':
        duration = int(input("Duration (seconds): "))
        monitor.start_monitoring(duration=duration)
    
    elif choice == '2':
        monitor.start_monitoring()
    
    elif choice == '3':
        activities = monitor.get_suspicious_activities()
        print("\nRecent Suspicious Activities:")
        print("="*80)
        for act in activities:
            print(f"Time: {act[1]} | IP: {act[2]} | Type: {act[3]}")
            print(f"Details: {act[4]} | Severity: {act[5]}")
            print("-"*80)
    
    elif choice == '4':
        blocked = monitor.get_blocked_ips()
        print("\nBlocked IPs:")
        print("="*80)
        for ip in blocked:
            print(f"IP: {ip[1]} | Reason: {ip[2]} | Blocked: {ip[3]}")
        print("="*80)
    
    elif choice == '5':
        ip = input("Enter IP to unblock: ").strip()
        monitor.unblock_ip(ip)
    
    else:
        print("[!] Invalid choice")
