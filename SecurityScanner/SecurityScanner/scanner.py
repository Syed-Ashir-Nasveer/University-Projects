# scanner.py 
"""
scanner.py
===========
Web Application Security Scanner Backend
Using OWASP ZAP for automated vulnerability detection

Author: [Your Name]
Date: December 2024
"""

import time
import sqlite3
from datetime import datetime
from zapv2 import ZAPv2


class SecurityScanner:
    """Main scanner class for security testing"""
    
    def __init__(self, zap_api_key='ndke8q5tkgsrp4mh1sf00l8nv0', zap_proxy='http://127.0.0.1:8080'):
        """
        Initialize ZAP connection and database
        
        Args:
            zap_api_key (str): ZAP API key
            zap_proxy (str): ZAP proxy URL
        """
        print("[*] Initializing Security Scanner...")
        self.zap = ZAPv2(apikey=zap_api_key, proxies={'http': zap_proxy, 'https': zap_proxy})
        self.db_path = 'scan_results.db'
        self.init_database()
        print("[+] Scanner initialized successfully")
    
    def init_database(self):
        """Create SQLite database for storing scan results"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT,
                total_alerts INTEGER DEFAULT 0,
                high_risk INTEGER DEFAULT 0,
                medium_risk INTEGER DEFAULT 0,
                low_risk INTEGER DEFAULT 0,
                status TEXT DEFAULT 'running'
            )
        ''')
        
        # Create vulnerabilities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                alert_name TEXT,
                risk_level TEXT,
                confidence TEXT,
                url TEXT,
                description TEXT,
                solution TEXT,
                reference TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        ''')
        
        conn.commit()
        conn.close()
        print("[+] Database initialized successfully")
    
    def start_scan(self, target_url, scan_type='quick'):
        """
        Start a new security scan
        
        Args:
            target_url (str): Target website URL
            scan_type (str): Type of scan (quick, standard, deep)
            
        Returns:
            int: Scan ID if successful, None otherwise
        """
        print(f"\n{'='*60}")
        print(f"[+] Starting {scan_type.upper()} scan for: {target_url}")
        print(f"{'='*60}\n")
        
        # Save scan info to database
        scan_id = self.save_scan_info(target_url, scan_type)
        
        try:
            # Step 1: Access the target
            print("[1/4] Accessing target URL...")
            self.zap.urlopen(target_url)
            time.sleep(2)
            print("      ✓ Target accessed successfully")
            
            # Step 2: Spider the target
            print("\n[2/4] Spidering the target (crawling pages)...")
            spider_id = self.zap.spider.scan(target_url)
            
            while int(self.zap.spider.status(spider_id)) < 100:
                progress = self.zap.spider.status(spider_id)
                print(f"      Spider progress: {progress}%", end='\r')
                time.sleep(2)
            
            print("\n      ✓ Spider completed")
            
            # Step 3: Passive scan (runs automatically)
            print("\n[3/4] Running passive scan...")
            time.sleep(5)
            print("      ✓ Passive scan completed")
            
            # Step 4: Active scan (if not quick scan)
            if scan_type != 'quick':
                print("\n[4/4] Starting active scan (this may take time)...")
                active_scan_id = self.zap.ascan.scan(target_url)
                
                while int(self.zap.ascan.status(active_scan_id)) < 100:
                    progress = self.zap.ascan.status(active_scan_id)
                    print(f"      Active scan progress: {progress}%", end='\r')
                    time.sleep(5)
                
                print("\n      ✓ Active scan completed")
            else:
                print("\n[4/4] Skipping active scan (quick mode)")
            
            # Step 5: Collect results
            print("\n[*] Collecting vulnerability results...")
            alerts = self.zap.core.alerts(baseurl=target_url)
            
            # Process and save results
            self.process_results(scan_id, alerts)
            
            print(f"\n{'='*60}")
            print(f"[+] Scan completed successfully!")
            print(f"[+] Found {len(alerts)} vulnerabilities")
            print(f"{'='*60}\n")
            
            return scan_id
            
        except Exception as e:
            print(f"\n[!] Error during scan: {str(e)}")
            self.update_scan_status(scan_id, 'failed')
            return None
    
    def save_scan_info(self, target_url, scan_type):
        """Save initial scan information to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO scans (target_url, scan_type, start_time, status)
            VALUES (?, ?, ?, 'running')
        ''', (target_url, scan_type, datetime.now().isoformat()))
        
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return scan_id
    
    def process_results(self, scan_id, alerts):
        """Process and save vulnerability results to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        high_count = 0
        medium_count = 0
        low_count = 0
        
        # Count vulnerabilities by severity
        for alert in alerts:
            risk = alert.get('risk', 'Informational')
            
            if risk == 'High':
                high_count += 1
            elif risk == 'Medium':
                medium_count += 1
            elif risk == 'Low':
                low_count += 1
            
            # Save vulnerability to database
            cursor.execute('''
                INSERT INTO vulnerabilities 
                (scan_id, alert_name, risk_level, confidence, url, description, solution, reference)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id,
                alert.get('alert', 'Unknown'),
                alert.get('risk', 'Informational'),
                alert.get('confidence', 'Unknown'),
                alert.get('url', ''),
                alert.get('description', ''),
                alert.get('solution', ''),
                alert.get('reference', '')
            ))
        
        # Update scan summary
        cursor.execute('''
            UPDATE scans 
            SET end_time = ?, total_alerts = ?, high_risk = ?, 
                medium_risk = ?, low_risk = ?, status = 'completed'
            WHERE id = ?
        ''', (datetime.now().isoformat(), len(alerts), high_count, 
              medium_count, low_count, scan_id))
        
        conn.commit()
        conn.close()
    
    def update_scan_status(self, scan_id, status):
        """Update scan status in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('UPDATE scans SET status = ? WHERE id = ?', (status, scan_id))
        conn.commit()
        conn.close()
    
    def get_scan_history(self, limit=10):
        """Get scan history from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM scans ORDER BY id DESC LIMIT ?', (limit,))
        scans = cursor.fetchall()
        conn.close()
        return scans
    
    def print_summary(self, scan_id):
        """Print scan summary to console"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
        scan = cursor.fetchone()
        
        if scan:
            print("\n" + "="*60)
            print("SCAN SUMMARY")
            print("="*60)
            print(f"Scan ID:       {scan[0]}")
            print(f"Target URL:    {scan[1]}")
            print(f"Scan Type:     {scan[2]}")
            print(f"Start Time:    {scan[3]}")
            print(f"End Time:      {scan[4]}")
            print(f"Status:        {scan[9]}")
            print("-"*60)
            print(f"Total Issues:  {scan[5]}")
            print(f"High Risk:     {scan[6]}")
            print(f"Medium Risk:   {scan[7]}")
            print(f"Low Risk:      {scan[8]}")
            print("="*60 + "\n")
        
        conn.close()


# Main execution
if __name__ == "__main__":
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║        Web Application Security Scanner v1.0             ║
    ║              Powered by OWASP ZAP                        ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    # Check if ZAP is running
    print("[*] Make sure OWASP ZAP is running on localhost:8080")
    print("[*] Default API Key: ndke8q5tkgsrp4mh1sf00l8nv0\n")
    
    # Initialize scanner
    try:
        scanner = SecurityScanner()
    except Exception as e:
        print(f"[!] Failed to connect to ZAP: {str(e)}")
        print("[!] Please make sure ZAP is running")
        exit(1)
    
    # Get user input
    target_url = input("Enter target URL (e.g., http://testphp.vulnweb.com): ").strip()
    
    if not target_url:
        target_url = "http://testphp.vulnweb.com"
        print(f"[*] Using default test site: {target_url}")
    
    print("\nScan Types:")
    print("1. Quick Scan (Spider + Passive) - 5-10 min")
    print("2. Standard Scan (Spider + Passive + Active) - 15-30 min")
    print("3. Deep Scan (Full scan) - 1-2 hours")
    
    choice = input("\nSelect scan type (1-3): ").strip()
    
    scan_types = {'1': 'quick', '2': 'standard', '3': 'deep'}
    scan_type = scan_types.get(choice, 'quick')
    
    # Start scan
    scan_id = scanner.start_scan(target_url, scan_type)
    
    if scan_id:
        # Print summary
        scanner.print_summary(scan_id)
        print(f"[+] Scan ID {scan_id} completed successfully")
        print(f"[+] Use this scan ID to generate reports")
    else:
        print("[!] Scan failed. Please check ZAP connection and try again.")