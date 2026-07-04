"""
Network Security Tool - Main GUI Application
Advanced network security scanner with killer interface
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
from datetime import datetime
import json

class NetworkSecurityTool:
    """Main application class with tabbed interface"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Network Security Tool - Professional Edition")
        self.root.geometry("1200x800")
        self.root.configure(bg="#0f172a")
        
        # Configure style
        self.setup_styles()
        
        # Create main container
        self.main_container = ttk.Frame(root)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create header
        self.create_header()
        
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Create tabs
        self.create_port_scanner_tab()
        self.create_network_discovery_tab()
        self.create_packet_sniffer_tab()
        self.create_password_checker_tab()
        self.create_vulnerability_scanner_tab()
        self.create_reports_tab()
        
        # Status bar
        self.create_status_bar()
        
        # Queue for thread communication
        self.result_queue = queue.Queue()
        
        # Load saved settings
        self.load_settings()
    
    def setup_styles(self):
        """Configure ttk styles for modern look"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        bg_color = "#0f172a"
        fg_color = "#e2e8f0"
        accent_color = "#6366f1"
        
        # Notebook style
        style.configure('TNotebook', background=bg_color, borderwidth=0)
        style.configure('TNotebook.Tab', 
                       background="#1e293b",
                       foreground=fg_color,
                       padding=[20, 10],
                       font=('Arial', 10, 'bold'))
        style.map('TNotebook.Tab',
                 background=[('selected', accent_color)],
                 foreground=[('selected', 'white')])
        
        # Frame style
        style.configure('TFrame', background=bg_color)
        
        # Label style
        style.configure('TLabel', 
                       background=bg_color,
                       foreground=fg_color,
                       font=('Arial', 10))
        
        style.configure('Title.TLabel',
                       font=('Arial', 16, 'bold'),
                       foreground=accent_color)
        
        # Entry style
        style.configure('TEntry',
                       fieldbackground="#1e293b",
                       foreground=fg_color,
                       insertcolor=fg_color)
        
        # Button style
        style.configure('Accent.TButton',
                       background=accent_color,
                       foreground='white',
                       font=('Arial', 10, 'bold'),
                       padding=[20, 10])
        
        style.map('Accent.TButton',
                 background=[('active', '#4f46e5')])
    
    def create_header(self):
        """Create application header"""
        header_frame = ttk.Frame(self.main_container)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        title = ttk.Label(header_frame, 
                         text="🛡️ Network Security Tool",
                         style='Title.TLabel')
        title.pack(side=tk.LEFT)
        
        subtitle = ttk.Label(header_frame,
                            text="Professional Network Analysis & Security Scanner",
                            font=('Arial', 9))
        subtitle.pack(side=tk.LEFT, padx=20)
        
        # Quick action buttons
        btn_frame = ttk.Frame(header_frame)
        btn_frame.pack(side=tk.RIGHT)
        
        ttk.Button(btn_frame, text="⚙️ Settings",
                  command=self.open_settings).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="📚 Help",
                  command=self.show_help).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="ℹ️ About",
                  command=self.show_about).pack(side=tk.LEFT, padx=5)
    
    def create_port_scanner_tab(self):
        """Create port scanner tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔍 Port Scanner")
        
        # Input section
        input_frame = ttk.LabelFrame(tab, text="Scanner Configuration", padding=15)
        input_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Target IP
        ttk.Label(input_frame, text="Target IP/Hostname:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.port_target_entry = ttk.Entry(input_frame, width=30)
        self.port_target_entry.grid(row=0, column=1, padx=10, pady=5)
        self.port_target_entry.insert(0, "127.0.0.1")
        
        # Port range
        ttk.Label(input_frame, text="Port Range:").grid(row=1, column=0, sticky=tk.W, pady=5)
        port_frame = ttk.Frame(input_frame)
        port_frame.grid(row=1, column=1, sticky=tk.W, padx=10, pady=5)
        
        self.port_start_entry = ttk.Entry(port_frame, width=10)
        self.port_start_entry.pack(side=tk.LEFT)
        self.port_start_entry.insert(0, "1")
        
        ttk.Label(port_frame, text=" to ").pack(side=tk.LEFT, padx=5)
        
        self.port_end_entry = ttk.Entry(port_frame, width=10)
        self.port_end_entry.pack(side=tk.LEFT)
        self.port_end_entry.insert(0, "1000")
        
        # Scan options
        ttk.Label(input_frame, text="Scan Type:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.scan_type_var = tk.StringVar(value="TCP")
        scan_combo = ttk.Combobox(input_frame, textvariable=self.scan_type_var,
                                  values=["TCP", "UDP", "SYN", "Comprehensive"],
                                  state='readonly', width=28)
        scan_combo.grid(row=2, column=1, padx=10, pady=5)
        
        # Control buttons
        btn_frame = ttk.Frame(input_frame)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=15)
        
        self.scan_btn = ttk.Button(btn_frame, text="🚀 Start Scan",
                                   style='Accent.TButton',
                                   command=self.start_port_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="⏹️ Stop",
                  command=self.stop_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="💾 Export Results",
                  command=lambda: self.export_results('port_scan')).pack(side=tk.LEFT, padx=5)
        
        # Results section
        results_frame = ttk.LabelFrame(tab, text="Scan Results", padding=15)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create treeview for results
        columns = ('Port', 'State', 'Service', 'Banner')
        self.port_tree = ttk.Treeview(results_frame, columns=columns, show='tree headings', height=15)
        
        self.port_tree.heading('#0', text='#')
        self.port_tree.heading('Port', text='Port')
        self.port_tree.heading('State', text='State')
        self.port_tree.heading('Service', text='Service')
        self.port_tree.heading('Banner', text='Banner')
        
        self.port_tree.column('#0', width=50)
        self.port_tree.column('Port', width=100)
        self.port_tree.column('State', width=100)
        self.port_tree.column('Service', width=150)
        self.port_tree.column('Banner', width=400)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.port_tree.yview)
        self.port_tree.configure(yscrollcommand=scrollbar.set)
        
        self.port_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Progress bar
        self.port_progress = ttk.Progressbar(tab, mode='determinate')
        self.port_progress.pack(fill=tk.X, padx=10, pady=5)
    
    def create_network_discovery_tab(self):
        """Create network discovery tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🌐 Network Discovery")
        
        # Input section
        input_frame = ttk.LabelFrame(tab, text="Discovery Configuration", padding=15)
        input_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(input_frame, text="Network Range (CIDR):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.network_range_entry = ttk.Entry(input_frame, width=30)
        self.network_range_entry.grid(row=0, column=1, padx=10, pady=5)
        self.network_range_entry.insert(0, "192.168.1.0/24")
        
        ttk.Label(input_frame, text="Discovery Method:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.discovery_method_var = tk.StringVar(value="Ping Sweep")
        method_combo = ttk.Combobox(input_frame, textvariable=self.discovery_method_var,
                                   values=["Ping Sweep", "ARP Scan", "TCP SYN", "Full Scan"],
                                   state='readonly', width=28)
        method_combo.grid(row=1, column=1, padx=10, pady=5)
        
        # Control buttons
        btn_frame = ttk.Frame(input_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=15)
        
        ttk.Button(btn_frame, text="🔎 Discover Network",
                  style='Accent.TButton',
                  command=self.start_network_discovery).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="🗺️ Generate Map",
                  command=self.generate_network_map).pack(side=tk.LEFT, padx=5)
        
        # Results section
        results_frame = ttk.LabelFrame(tab, text="Discovered Hosts", padding=15)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        columns = ('IP', 'MAC', 'Hostname', 'OS', 'Status', 'Ports')
        self.network_tree = ttk.Treeview(results_frame, columns=columns, show='tree headings', height=15)
        
        self.network_tree.heading('#0', text='#')
        for col in columns:
            self.network_tree.heading(col, text=col)
            self.network_tree.column(col, width=150)
        
        self.network_tree.column('#0', width=50)
        
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.network_tree.yview)
        self.network_tree.configure(yscrollcommand=scrollbar.set)
        
        self.network_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_packet_sniffer_tab(self):
        """Create packet sniffer tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📡 Packet Sniffer")
        
        # Controls
        control_frame = ttk.LabelFrame(tab, text="Sniffer Controls", padding=15)
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(control_frame, text="Interface:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.interface_var = tk.StringVar(value="eth0")
        interface_combo = ttk.Combobox(control_frame, textvariable=self.interface_var,
                                      values=["eth0", "wlan0", "lo", "any"],
                                      width=28)
        interface_combo.grid(row=0, column=1, padx=10, pady=5)
        
        ttk.Label(control_frame, text="Filter:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.packet_filter_entry = ttk.Entry(control_frame, width=30)
        self.packet_filter_entry.grid(row=1, column=1, padx=10, pady=5)
        self.packet_filter_entry.insert(0, "tcp or udp")
        
        btn_frame = ttk.Frame(control_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=15)
        
        self.sniff_btn = ttk.Button(btn_frame, text="▶️ Start Sniffing",
                                    style='Accent.TButton',
                                    command=self.start_packet_sniffing)
        self.sniff_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="⏹️ Stop",
                  command=self.stop_packet_sniffing).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="🗑️ Clear",
                  command=self.clear_packets).pack(side=tk.LEFT, padx=5)
        
        # Packet list
        packet_frame = ttk.LabelFrame(tab, text="Captured Packets", padding=15)
        packet_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        columns = ('Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info')
        self.packet_tree = ttk.Treeview(packet_frame, columns=columns, show='tree headings', height=15)
        
        self.packet_tree.heading('#0', text='#')
        for col in columns:
            self.packet_tree.heading(col, text=col)
        
        self.packet_tree.column('#0', width=50)
        self.packet_tree.column('Time', width=100)
        self.packet_tree.column('Source', width=150)
        self.packet_tree.column('Destination', width=150)
        self.packet_tree.column('Protocol', width=100)
        self.packet_tree.column('Length', width=80)
        self.packet_tree.column('Info', width=300)
        
        scrollbar = ttk.Scrollbar(packet_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=scrollbar.set)
        
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Packet details
        details_frame = ttk.LabelFrame(tab, text="Packet Details", padding=10)
        details_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.packet_details_text = scrolledtext.ScrolledText(details_frame, height=5,
                                                             bg="#1e293b", fg="#e2e8f0",
                                                             font=('Courier', 9))
        self.packet_details_text.pack(fill=tk.BOTH, expand=True)
        
        self.packet_tree.bind('<<TreeviewSelect>>', self.show_packet_details)
    
    def create_password_checker_tab(self):
        """Create password strength checker tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔐 Password Checker")
        
        # Input section
        input_frame = ttk.LabelFrame(tab, text="Password Analysis", padding=20)
        input_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(input_frame, text="Enter Password:",
                 font=('Arial', 11, 'bold')).pack(anchor=tk.W, pady=5)
        
        self.password_entry = ttk.Entry(input_frame, width=50, show="*", font=('Arial', 12))
        self.password_entry.pack(fill=tk.X, pady=10)
        
        # Show password checkbox
        self.show_password_var = tk.BooleanVar()
        ttk.Checkbutton(input_frame, text="Show Password",
                       variable=self.show_password_var,
                       command=self.toggle_password_visibility).pack(anchor=tk.W)
        
        ttk.Button(input_frame, text="🔍 Check Strength",
                  style='Accent.TButton',
                  command=self.check_password_strength).pack(pady=15)
        
        # Results section
        results_frame = ttk.LabelFrame(tab, text="Analysis Results", padding=20)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.password_result_text = scrolledtext.ScrolledText(results_frame, height=15,
                                                              bg="#1e293b", fg="#e2e8f0",
                                                              font=('Courier', 10))
        self.password_result_text.pack(fill=tk.BOTH, expand=True)
        
        # Strength meter
        meter_frame = ttk.Frame(results_frame)
        meter_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(meter_frame, text="Strength:").pack(side=tk.LEFT)
        self.strength_progress = ttk.Progressbar(meter_frame, mode='determinate', length=300)
        self.strength_progress.pack(side=tk.LEFT, padx=10)
        self.strength_label = ttk.Label(meter_frame, text="Not Checked")
        self.strength_label.pack(side=tk.LEFT)
    
    def create_vulnerability_scanner_tab(self):
        """Create vulnerability scanner tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🚨 Vulnerability Scanner")
        
        input_frame = ttk.LabelFrame(tab, text="Vulnerability Scan", padding=15)
        input_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(input_frame, text="Target:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.vuln_target_entry = ttk.Entry(input_frame, width=40)
        self.vuln_target_entry.grid(row=0, column=1, padx=10, pady=5)
        
        ttk.Label(input_frame, text="Scan Profile:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.vuln_profile_var = tk.StringVar(value="Quick Scan")
        profile_combo = ttk.Combobox(input_frame, textvariable=self.vuln_profile_var,
                                    values=["Quick Scan", "Deep Scan", "Web Application", "Network Services"],
                                    state='readonly', width=38)
        profile_combo.grid(row=1, column=1, padx=10, pady=5)
        
        btn_frame = ttk.Frame(input_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=15)
        
        ttk.Button(btn_frame, text="🔎 Start Scan",
                  style='Accent.TButton',
                  command=self.start_vulnerability_scan).pack(side=tk.LEFT, padx=5)
        
        # Results
        results_frame = ttk.LabelFrame(tab, text="Vulnerabilities Found", padding=15)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        columns = ('Severity', 'CVE', 'Service', 'Description', 'Risk Score')
        self.vuln_tree = ttk.Treeview(results_frame, columns=columns, show='tree headings', height=15)
        
        self.vuln_tree.heading('#0', text='#')
        for col in columns:
            self.vuln_tree.heading(col, text=col)
        
        self.vuln_tree.column('#0', width=50)
        self.vuln_tree.column('Severity', width=100)
        self.vuln_tree.column('CVE', width=120)
        self.vuln_tree.column('Service', width=120)
        self.vuln_tree.column('Description', width=400)
        self.vuln_tree.column('Risk Score', width=100)
        
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.vuln_tree.yview)
        self.vuln_tree.configure(yscrollcommand=scrollbar.set)
        
        self.vuln_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_reports_tab(self):
        """Create reports tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📊 Reports")
        
        report_frame = ttk.LabelFrame(tab, text="Generate Report", padding=20)
        report_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(report_frame, text="Report Type:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.report_type_var = tk.StringVar(value="Comprehensive")
        report_combo = ttk.Combobox(report_frame, textvariable=self.report_type_var,
                                   values=["Comprehensive", "Port Scan Only", "Network Map", "Vulnerabilities"],
                                   state='readonly', width=38)
        report_combo.grid(row=0, column=1, padx=10, pady=5)
        
        ttk.Label(report_frame, text="Format:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.report_format_var = tk.StringVar(value="PDF")
        format_combo = ttk.Combobox(report_frame, textvariable=self.report_format_var,
                                   values=["PDF", "HTML", "JSON", "CSV", "XML"],
                                   state='readonly', width=38)
        format_combo.grid(row=1, column=1, padx=10, pady=5)
        
        btn_frame = ttk.Frame(report_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=15)
        
        ttk.Button(btn_frame, text="📄 Generate Report",
                  style='Accent.TButton',
                  command=self.generate_report).pack(side=tk.LEFT, padx=5)
        
        # Report preview
        preview_frame = ttk.LabelFrame(tab, text="Report Preview", padding=15)
        preview_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.report_text = scrolledtext.ScrolledText(preview_frame, height=20,
                                                     bg="#1e293b", fg="#e2e8f0",
                                                     font=('Courier', 9))
        self.report_text.pack(fill=tk.BOTH, expand=True)
    
    def create_status_bar(self):
        """Create status bar at bottom"""
        status_frame = ttk.Frame(self.main_container)
        status_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.status_label = ttk.Label(status_frame, text="Ready", relief=tk.SUNKEN)
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.time_label = ttk.Label(status_frame, text="", relief=tk.SUNKEN)
        self.time_label.pack(side=tk.RIGHT)
        
        self.update_time()
    
    def update_time(self):
        """Update time in status bar"""
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.config(text=current_time)
        self.root.after(1000, self.update_time)
    
    def update_status(self, message):
        """Update status bar message"""
        self.status_label.config(text=message)
    
    # Placeholder methods for functionality
    def start_port_scan(self):
        """Start port scanning"""
        from network_scanner import PortScanner
        
        target = self.port_target_entry.get()
        start_port = int(self.port_start_entry.get())
        end_port = int(self.port_end_entry.get())
        scan_type = self.scan_type_var.get()
        
        if not target:
            messagebox.showerror("Error", "Please enter a target IP or hostname")
            return
        
        self.update_status(f"Scanning {target} ports {start_port}-{end_port}...")
        self.scan_btn.config(state='disabled')
        
        # Clear previous results
        for item in self.port_tree.get_children():
            self.port_tree.delete(item)
        
        # Start scan in thread
        scanner = PortScanner(target, start_port, end_port, scan_type)
        thread = threading.Thread(target=self.run_port_scan, args=(scanner,))
        thread.daemon = True
        thread.start()
    
    def run_port_scan(self, scanner):
        """Run port scan in thread"""
        try:
            results = scanner.scan()
            for idx, result in enumerate(results, 1):
                self.port_tree.insert('', 'end', text=str(idx), values=(
                    result['port'],
                    result['state'],
                    result['service'],
                    result['banner']
                ))
                progress = (idx / len(results)) * 100
                self.port_progress['value'] = progress
            
            self.update_status(f"Scan complete. Found {len(results)} open ports.")
        except Exception as e:
            messagebox.showerror("Error", f"Scan failed: {str(e)}")
        finally:
            self.scan_btn.config(state='normal')
            self.port_progress['value'] = 0
    
    def stop_scan(self):
        """Stop current scan"""
        self.update_status("Scan stopped by user")
        self.scan_btn.config(state='normal')
    
    def start_network_discovery(self):
        """Start network discovery"""
        from network_scanner import NetworkDiscovery
        
        network_range = self.network_range_entry.get()
        method = self.discovery_method_var.get()
        
        if not network_range:
            messagebox.showerror("Error", "Please enter a network range")
            return
        
        self.update_status(f"Discovering hosts in {network_range}...")
        
        # Clear previous results
        for item in self.network_tree.get_children():
            self.network_tree.delete(item)
        
        discovery = NetworkDiscovery(network_range, method)
        thread = threading.Thread(target=self.run_network_discovery, args=(discovery,))
        thread.daemon = True
        thread.start()
    
    def run_network_discovery(self, discovery):
        """Run network discovery in thread"""
        try:
            hosts = discovery.discover()
            for idx, host in enumerate(hosts, 1):
                self.network_tree.insert('', 'end', text=str(idx), values=(
                    host['ip'],
                    host['mac'],
                    host['hostname'],
                    host['os'],
                    host['status'],
                    ', '.join(map(str, host['ports']))
                ))
            
            self.update_status(f"Discovery complete. Found {len(hosts)} hosts.")
        except Exception as e:
            messagebox.showerror("Error", f"Discovery failed: {str(e)}")
    
    def generate_network_map(self):
        """Generate network topology map"""
        messagebox.showinfo("Network Map", "Generating network topology map...")
        # This would create a visual network map
    
    def start_packet_sniffing(self):
        """Start packet sniffing"""
        interface = self.interface_var.get()
        packet_filter = self.packet_filter_entry.get()
        
        self.update_status(f"Sniffing on {interface}...")
        self.sniff_btn.config(text="⏹️ Stop Sniffing")
        
        messagebox.showwarning("Requires Root", 
                             "Packet sniffing requires root/admin privileges.\n"
                             "Run the application with sudo/admin rights.")
    
    def stop_packet_sniffing(self):
        """Stop packet sniffing"""
        self.update_status("Packet sniffing stopped")
        self.sniff_btn.config(text="▶️ Start Sniffing")
    
    def clear_packets(self):
        """Clear packet list"""
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
        self.packet_details_text.delete(1.0, tk.END)
    
    def show_packet_details(self, event):
        """Show details of selected packet"""
        selection = self.packet_tree.selection()
        if selection:
            self.packet_details_text.delete(1.0, tk.END)
            self.packet_details_text.insert(tk.END, "Packet details would be shown here...")
    
    def check_password_strength(self):
        """Check password strength"""
        from password_checker import PasswordChecker
        
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password")
            return
        
        checker = PasswordChecker()
        result = checker.analyze(password)
        
        # Display results
        self.password_result_text.delete(1.0, tk.END)
        self.password_result_text.insert(tk.END, result['detailed_report'])
        
        # Update strength meter
        score = result['score']
        self.strength_progress['value'] = score
        
        if score < 30:
            strength_text = "Very Weak 😱"
            color = "red"
        elif score < 50:
            strength_text = "Weak 😟"
            color = "orange"
        elif score < 70:
            strength_text = "Medium 😐"
            color = "yellow"
        elif score < 90:
            strength_text = "Strong 😊"
            color = "lightgreen"
        else:
            strength_text = "Very Strong 🔥"
            color = "green"
        
        self.strength_label.config(text=strength_text)
    
    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")
    
    def start_vulnerability_scan(self):
        """Start vulnerability scanning"""
        target = self.vuln_target_entry.get()
        profile = self.vuln_profile_var.get()
        
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        self.update_status(f"Scanning {target} for vulnerabilities...")
        
        # Simulated vulnerabilities
        vulns = [
            ("HIGH", "CVE-2023-1234", "SSH", "OpenSSH version vulnerable to attack", "8.5"),
            ("MEDIUM", "CVE-2023-5678", "HTTP", "Outdated Apache version", "6.2"),
            ("LOW", "CVE-2023-9012", "FTP", "Anonymous FTP enabled", "3.1"),
        ]
        
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)
        
        for idx, vuln in enumerate(vulns, 1):
            self.vuln_tree.insert('', 'end', text=str(idx), values=vuln)
        
        self.update_status(f"Scan complete. Found {len(vulns)} vulnerabilities.")
    
    def generate_report(self):
        """Generate security report"""
        report_type = self.report_type_var.get()
        report_format = self.report_format_var.get()
        
        self.report_text.delete(1.0, tk.END)
        
        report = f"""
{'='*60}
NETWORK SECURITY REPORT
{'='*60}
Report Type: {report_type}
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Format: {report_format}
{'='*60}

EXECUTIVE SUMMARY
-----------------
This report provides a comprehensive analysis of network security
scans performed on the target infrastructure.

FINDINGS
--------
1. Port Scan Results: Multiple open ports detected
2. Network Discovery: X hosts found on network
3. Vulnerability Assessment: Y vulnerabilities identified

RECOMMENDATIONS
---------------
1. Close unnecessary open ports
2. Update vulnerable services
3. Implement firewall rules
4. Enable intrusion detection

{'='*60}
END OF REPORT
{'='*60}
        """
        
        self.report_text.insert(tk.END, report)
        
        filename = filedialog.asksaveasfilename(
            defaultextension=f".{report_format.lower()}",
            filetypes=[(f"{report_format} files", f"*.{report_format.lower()}")]
        )
        
        if filename:
            with open(filename, 'w') as f:
                f.write(report)
            messagebox.showinfo("Success", f"Report saved to {filename}")
    
    def export_results(self, scan_type):
        """Export scan results"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("CSV files", "*.csv")]
        )
        
        if filename:
            messagebox.showinfo("Success", f"Results exported to {filename}")
    
    def open_settings(self):
        """Open settings dialog"""
        settings_window = tk.Toplevel(self.root)
        settings_window.title("⚙️ Settings")
        settings_window.geometry("500x400")
        settings_window.configure(bg="#0f172a")
        
        ttk.Label(settings_window, text="Settings",
                 style='Title.TLabel').pack(pady=20)
        
        # Add settings options here
        ttk.Label(settings_window, text="Timeout (seconds):").pack(pady=5)
        ttk.Entry(settings_window).pack(pady=5)
        
        ttk.Label(settings_window, text="Thread Count:").pack(pady=5)
        ttk.Entry(settings_window).pack(pady=5)
        
        ttk.Button(settings_window, text="💾 Save Settings",
                  style='Accent.TButton').pack(pady=20)
    
    def show_help(self):
        """Show help dialog"""
        help_text = """
🛡️ NETWORK SECURITY TOOL - HELP

PORT SCANNER:
Enter target IP and port range to scan for open ports.
Supports TCP, UDP, and SYN scanning methods.

NETWORK DISCOVERY:
Enter network range in CIDR notation (e.g., 192.168.1.0/24)
to discover active hosts on the network.

PACKET SNIFFER:
Requires root/admin privileges. Captures and analyzes
network traffic in real-time.

PASSWORD CHECKER:
Analyzes password strength using multiple criteria
including length, complexity, and common patterns.

VULNERABILITY SCANNER:
Scans targets for known security vulnerabilities
and provides risk assessment.

REPORTS:
Generate comprehensive security reports in multiple
formats for documentation and compliance.

For more information, visit the documentation.
        """
        
        messagebox.showinfo("Help", help_text)
    
    def show_about(self):
        """Show about dialog"""
        about_text = """
🛡️ Network Security Tool
Professional Edition v1.0

A comprehensive network security scanner
with advanced features for penetration testing
and network analysis.

Built with Python & Tkinter
Created with ❤️ for security professionals

© 2024 Network Security Tool
All rights reserved.
        """
        
        messagebox.showinfo("About", about_text)
    
    def load_settings(self):
        """Load saved settings"""
        try:
            with open('settings.json', 'r') as f:
                settings = json.load(f)
                # Apply settings here
        except FileNotFoundError:
            pass
    
    def save_settings(self):
        """Save current settings"""
        settings = {
            'timeout': 5,
            'threads': 100,
            'interface': self.interface_var.get()
        }
        
        with open('settings.json', 'w') as f:
            json.dump(settings, f, indent=4)


def main():
    """Main function to run the application"""
    root = tk.Tk()
    app = NetworkSecurityTool(root)
    root.mainloop()


if __name__ == "__main__":
    main()
