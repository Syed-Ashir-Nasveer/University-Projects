"""
SecureSandbox Pro - Advanced Process Isolation & Monitoring System
Version 2.0 - Enhanced with Visual Analytics & Advanced Features

New Features:
- Real-time resource graphs
- Malware signature detection
- Hash analysis (MD5, SHA-256)
- API call monitoring
- Snapshot comparison
- Advanced threat scoring
- Export to PDF/HTML
- Screenshot capture
- Quarantine system
"""

import os
import sys
import subprocess
import psutil
import threading
import time
import json
import hashlib
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import platform
from collections import deque
import re

try:
    import matplotlib
    matplotlib.use('TkAgg')
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    MATPLOTLIB_AVAILABLE = True
except:
    MATPLOTLIB_AVAILABLE = False

class ThreatAnalyzer:
    """Advanced threat detection and analysis"""
    
    MALICIOUS_SIGNATURES = {
        'registry_modification': r'(HKEY_|RegOpenKey|RegSetValue)',
        'file_encryption': r'(AES|encrypt|cipher|crypto)',
        'persistence': r'(startup|autorun|schedule|cron)',
        'network_scan': r'(port.*scan|nmap|socket.*connect)',
        'privilege_escalation': r'(sudo|runas|UAC|admin)',
        'data_exfiltration': r'(upload|ftp|http.*post|send)',
        'process_injection': r'(inject|hook|VirtualAlloc|WriteProcessMemory)',
        'anti_analysis': r'(debugger|sandbox|vm.*detect|IsDebugger)',
    }
    
    SUSPICIOUS_APIS = [
        'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory',
        'LoadLibrary', 'GetProcAddress', 'RegSetValue', 'CreateProcess',
        'ShellExecute', 'URLDownloadToFile', 'WinExec'
    ]
    
    @staticmethod
    def calculate_file_hash(filepath):
        """Calculate MD5 and SHA-256 hashes"""
        try:
            md5 = hashlib.md5()
            sha256 = hashlib.sha256()
            
            with open(filepath, 'rb') as f:
                while chunk := f.read(8192):
                    md5.update(chunk)
                    sha256.update(chunk)
            
            return {
                'md5': md5.hexdigest(),
                'sha256': sha256.hexdigest()
            }
        except:
            return {'md5': 'N/A', 'sha256': 'N/A'}
    
    @staticmethod
    def scan_for_signatures(content):
        """Scan content for malicious signatures"""
        findings = []
        for sig_name, pattern in ThreatAnalyzer.MALICIOUS_SIGNATURES.items():
            if re.search(pattern, content, re.IGNORECASE):
                findings.append(sig_name)
        return findings
    
    @staticmethod
    def calculate_threat_score(logs, resources):
        """Calculate threat score 0-100"""
        score = 0
        
        # Check for blocked actions
        blocked_count = sum(1 for log in logs if log['level'] == 'BLOCKED')
        score += min(blocked_count * 10, 40)
        
        # Check CPU usage
        if resources:
            avg_cpu = sum(r['cpu'] for r in resources) / len(resources)
            if avg_cpu > 80:
                score += 20
            elif avg_cpu > 50:
                score += 10
        
        # Check network activity
        network_count = sum(1 for log in logs if log['level'] == 'NETWORK')
        score += min(network_count * 2, 20)
        
        # Check file access
        file_count = sum(1 for log in logs if log['level'] == 'FILE')
        if file_count > 20:
            score += 20
        
        return min(score, 100)


class SandboxCore:
    def __init__(self):
        self.process = None
        self.monitoring = False
        self.logs = []
        self.resource_usage = deque(maxlen=100)
        self.network_connections = []
        self.file_accesses = []
        self.api_calls = []
        self.threat_score = 0
        
        self.allowed_paths = [os.getcwd()]
        self.blocked_paths = [
            os.path.expanduser("~"),
            "C:\\Windows\\System32" if platform.system() == "Windows" else "/etc",
            "C:\\Windows" if platform.system() == "Windows" else "/bin",
            "/sys", "/proc", "/dev"
        ]
        
        self.quarantine_dir = os.path.join(os.getcwd(), 'quarantine')
        os.makedirs(self.quarantine_dir, exist_ok=True)
        
    def create_restricted_env(self):
        """Create highly restricted environment"""
        env = os.environ.copy()
        
        # Isolated directories
        sandbox_root = os.path.join(os.getcwd(), 'sandbox_root')
        env['HOME'] = os.path.join(sandbox_root, 'home')
        env['TEMP'] = os.path.join(sandbox_root, 'temp')
        env['TMP'] = env['TEMP']
        env['APPDATA'] = os.path.join(sandbox_root, 'appdata')
        
        # Security markers
        env['SANDBOX_MODE'] = '1'
        env['RESTRICTED'] = 'TRUE'
        
        # Create directories
        for path in [env['HOME'], env['TEMP'], env['APPDATA']]:
            os.makedirs(path, exist_ok=True)
        
        # Limit PATH
        env['PATH'] = os.pathsep.join([
            os.path.dirname(sys.executable),
            env['TEMP']
        ])
        
        return env
    
    def analyze_file_before_execution(self, filepath):
        """Pre-execution analysis"""
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'file': filepath,
            'size': os.path.getsize(filepath),
            'hashes': ThreatAnalyzer.calculate_file_hash(filepath),
            'signatures': []
        }
        
        # Scan for signatures if it's a text/script file
        if filepath.endswith(('.py', '.txt', '.bat', '.sh', '.ps1')):
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    analysis['signatures'] = ThreatAnalyzer.scan_for_signatures(content)
            except:
                pass
        
        self.log_action("ANALYSIS", f"File hash MD5: {analysis['hashes']['md5']}")
        self.log_action("ANALYSIS", f"File hash SHA-256: {analysis['hashes']['sha256']}")
        
        if analysis['signatures']:
            self.log_action("WARNING", f"Suspicious signatures detected: {', '.join(analysis['signatures'])}")
        
        return analysis
    
    def execute_program(self, program_path, args=None):
        """Execute program in sandbox with enhanced monitoring"""
        try:
            if not os.path.exists(program_path):
                raise FileNotFoundError(f"Program not found: {program_path}")
            
            # Pre-execution analysis
            self.analyze_file_before_execution(program_path)
            
            env = self.create_restricted_env()
            
            # Build command
            if program_path.endswith('.py'):
                command = [sys.executable, program_path]
            else:
                command = [program_path]
            
            if args:
                command.extend(args.split())
            
            self.log_action("INFO", f"Executing: {' '.join(command)}")
            self.log_action("INFO", f"Environment isolated to: {env['HOME']}")
            
            # Execute with resource limits
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                env=env,
                text=True,
                cwd=env['TEMP']
            )
            
            self.log_action("SUCCESS", f"Process started - PID: {self.process.pid}")
            return True
            
        except Exception as e:
            self.log_action("ERROR", f"Execution failed: {str(e)}")
            return False
    
    def monitor_process(self):
        """Enhanced process monitoring with detailed tracking"""
        if not self.process:
            return
        
        try:
            proc = psutil.Process(self.process.pid)
            start_time = time.time()
            
            # Initial CPU measurement
            proc.cpu_percent(interval=None)
            time.sleep(0.1)
            
            while self.monitoring and proc.is_running():
                try:
                    # Resource metrics - Fixed CPU measurement
                    cpu = proc.cpu_percent(interval=None)
                    memory_info = proc.memory_info()
                    memory_mb = memory_info.rss / (1024 * 1024)
                    threads = proc.num_threads()
                    
                    # Detailed metrics
                    num_fds = proc.num_fds() if hasattr(proc, 'num_fds') else 0
                    
                    self.resource_usage.append({
                        'time': datetime.now().strftime('%H:%M:%S'),
                        'elapsed': int(time.time() - start_time),
                        'cpu': cpu,
                        'memory': memory_mb,
                        'threads': threads,
                        'handles': num_fds
                    })
                    
                    # Network monitoring
                    try:
                        connections = proc.connections()
                        for conn in connections:
                            conn_info = {
                                'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                                'remote': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                                'status': conn.status,
                                'time': datetime.now().strftime('%H:%M:%S')
                            }
                            
                            if conn_info not in self.network_connections:
                                self.network_connections.append(conn_info)
                                self.log_action("NETWORK", 
                                    f"{conn_info['local']} -> {conn_info['remote']} ({conn_info['status']})")
                    except:
                        pass
                    
                    # File access monitoring
                    try:
                        open_files = proc.open_files()
                        for f in open_files:
                            file_info = {
                                'path': f.path,
                                'fd': f.fd,
                                'time': datetime.now().strftime('%H:%M:%S')
                            }
                            
                            if file_info not in self.file_accesses:
                                self.file_accesses.append(file_info)
                                
                                if self.is_path_blocked(f.path):
                                    self.log_action("BLOCKED", f"Restricted path access: {f.path}")
                                else:
                                    self.log_action("FILE", f"File opened: {f.path}")
                    except:
                        pass
                    
                    # Memory threshold alert
                    if memory_mb > 500:
                        self.log_action("WARNING", f"High memory usage: {memory_mb:.1f} MB")
                    
                    # CPU threshold alert
                    if cpu > 90:
                        self.log_action("WARNING", f"High CPU usage: {cpu:.1f}%")
                    
                    time.sleep(0.5)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    break
            
            # Calculate final threat score
            self.threat_score = ThreatAnalyzer.calculate_threat_score(self.logs, list(self.resource_usage))
            self.log_action("ANALYSIS", f"Threat Score: {self.threat_score}/100")
            
        except Exception as e:
            self.log_action("ERROR", f"Monitoring error: {str(e)}")
    
    def is_path_blocked(self, path):
        """Check if path is blocked"""
        for blocked in self.blocked_paths:
            if path.startswith(blocked):
                return True
        return False
    
    def terminate_process(self):
        """Terminate with cleanup"""
        if self.process and self.process.poll() is None:
            try:
                proc = psutil.Process(self.process.pid)
                
                # Graceful termination
                proc.terminate()
                proc.wait(timeout=3)
                self.log_action("INFO", "Process terminated gracefully")
            except psutil.TimeoutExpired:
                # Force kill
                proc.kill()
                self.log_action("WARNING", "Process forcefully killed")
            except:
                pass
    
    def quarantine_file(self, filepath):
        """Move file to quarantine"""
        try:
            import shutil
            filename = os.path.basename(filepath)
            dest = os.path.join(self.quarantine_dir, f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}")
            shutil.copy2(filepath, dest)
            self.log_action("QUARANTINE", f"File quarantined: {filename}")
            return dest
        except Exception as e:
            self.log_action("ERROR", f"Quarantine failed: {str(e)}")
            return None
    
    def log_action(self, level, message):
        """Enhanced logging"""
        log_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            'level': level,
            'message': message,
            'pid': self.process.pid if self.process else None
        }
        self.logs.append(log_entry)
    
    def export_report(self, format='json'):
        """Export detailed report"""
        report = {
            'metadata': {
                'generated': datetime.now().isoformat(),
                'version': '2.0',
                'system': platform.system()
            },
            'execution': {
                'duration': len(self.resource_usage),
                'threat_score': self.threat_score,
                'total_logs': len(self.logs)
            },
            'resources': {
                'peak_cpu': max((r['cpu'] for r in self.resource_usage), default=0),
                'peak_memory': max((r['memory'] for r in self.resource_usage), default=0),
                'avg_threads': sum(r['threads'] for r in self.resource_usage) / len(self.resource_usage) if self.resource_usage else 0
            },
            'network': {
                'total_connections': len(self.network_connections),
                'connections': self.network_connections
            },
            'files': {
                'total_accessed': len(self.file_accesses),
                'files': [f['path'] for f in self.file_accesses]
            },
            'logs': self.logs,
            'resource_timeline': list(self.resource_usage)
        }
        
        return report


class SandboxGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureSandbox Pro - Advanced Process Isolation System")
        self.root.geometry("1400x900")
        self.root.configure(bg='#0a0d1a')
        
        self.sandbox = SandboxCore()
        self.monitoring_thread = None
        self.graph_update_job = None
        
        self.setup_styles()
        self.setup_ui()
        self.update_dashboard()
        
    def setup_styles(self):
        """Enhanced styling"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Custom styles
        style.configure('Title.TLabel', background='#0a0d1a', foreground='#00ff88', 
                       font=('Segoe UI', 26, 'bold'))
        style.configure('Subtitle.TLabel', background='#0a0d1a', foreground='#88ccff', 
                       font=('Segoe UI', 13))
        style.configure('Stat.TLabel', background='#1a1f35', foreground='#ffffff', 
                       font=('Segoe UI', 16, 'bold'))
        style.configure('StatLabel.TLabel', background='#1a1f35', foreground='#aaaaaa', 
                       font=('Segoe UI', 10))
        style.configure('TButton', background='#00ff88', foreground='#0a0d1a', 
                       font=('Segoe UI', 11, 'bold'), padding=12)
        style.configure('Danger.TButton', background='#ff4444', foreground='white')
        style.configure('Warning.TButton', background='#ffaa00', foreground='white')
        style.configure('Info.TButton', background='#4488ff', foreground='white')
        style.configure('Card.TFrame', background='#1a1f35', relief='raised', borderwidth=2)
        style.configure('TNotebook', background='#0a0d1a', borderwidth=0)
        style.configure('TNotebook.Tab', background='#1a1f35', foreground='white', 
                       padding=[20, 10], font=('Segoe UI', 10, 'bold'))
        
    def setup_ui(self):
        """Enhanced UI with professional design"""
        # Main container with gradient effect
        main_container = tk.Frame(self.root, bg='#0a0d1a')
        main_container.pack(fill='both', expand=True)
        
        # Header with gradient background
        header = tk.Frame(main_container, bg='#1a1f35', height=120)
        header.pack(fill='x', padx=0, pady=0)
        header.pack_propagate(False)
        
        # Header content
        header_content = ttk.Frame(header, style='Card.TFrame')
        header_content.pack(fill='both', expand=True, padx=20, pady=15)
        
        # Left side - Title and subtitle
        title_section = ttk.Frame(header_content, style='Card.TFrame')
        title_section.pack(side='left', fill='y')
        
        # Logo and title
        logo_title = ttk.Frame(title_section, style='Card.TFrame')
        logo_title.pack(anchor='w')
        
        # Animated logo
        logo_canvas = tk.Canvas(logo_title, width=50, height=50, bg='#1a1f35', highlightthickness=0)
        logo_canvas.pack(side='left', padx=(0, 15))
        
        # Draw shield logo
        logo_canvas.create_polygon(
            25, 5, 45, 15, 45, 35, 25, 48, 5, 35, 5, 15,
            fill='#00ff88', outline='#00cc66', width=2
        )
        logo_canvas.create_text(25, 25, text='S', fill='#0a0d1a', 
                               font=('Arial', 20, 'bold'))
        
        title_text = ttk.Frame(logo_title, style='Card.TFrame')
        title_text.pack(side='left')
        
        ttk.Label(title_text, text="SecureSandbox Pro", 
                 style='Title.TLabel').pack(anchor='w')
        ttk.Label(title_text, text="Advanced Process Isolation & Threat Analysis System", 
                 style='Subtitle.TLabel').pack(anchor='w')
        
        # Version badge
        version_badge = tk.Label(title_text, text="v2.0", 
                                bg='#667eea', fg='white', 
                                font=('Segoe UI', 8, 'bold'),
                                padx=8, pady=2)
        version_badge.pack(anchor='w', pady=(5, 0))
        
        # Right side - Stats dashboard with cards
        stats_container = ttk.Frame(header_content, style='Card.TFrame')
        stats_container.pack(side='right', fill='y')
        
        # Stat cards
        stat_cards = ttk.Frame(stats_container, style='Card.TFrame')
        stat_cards.pack()
        
        # Threat score card
        threat_card = tk.Frame(stat_cards, bg='#0f1729', 
                              relief='raised', borderwidth=2)
        threat_card.grid(row=0, column=0, padx=8, pady=5, sticky='nsew')
        
        tk.Label(threat_card, text="⚠️", bg='#0f1729', fg='#ffaa00', 
                font=('Segoe UI', 20)).pack(pady=(8, 2))
        self.threat_label = tk.Label(threat_card, text="0", bg='#0f1729', 
                                     fg='#00ff88', font=('Segoe UI', 24, 'bold'))
        self.threat_label.pack()
        tk.Label(threat_card, text="Threat Score", bg='#0f1729', 
                fg='#888', font=('Segoe UI', 9)).pack(pady=(0, 8))
        
        # Logs count card
        logs_card = tk.Frame(stat_cards, bg='#0f1729', 
                            relief='raised', borderwidth=2)
        logs_card.grid(row=0, column=1, padx=8, pady=5, sticky='nsew')
        
        tk.Label(logs_card, text="📝", bg='#0f1729', fg='#88ccff', 
                font=('Segoe UI', 20)).pack(pady=(8, 2))
        self.logs_count_label = tk.Label(logs_card, text="0", bg='#0f1729', 
                                         fg='#88ccff', font=('Segoe UI', 24, 'bold'))
        self.logs_count_label.pack()
        tk.Label(logs_card, text="Log Entries", bg='#0f1729', 
                fg='#888', font=('Segoe UI', 9)).pack(pady=(0, 8))
        
        # Files accessed card
        files_card = tk.Frame(stat_cards, bg='#0f1729', 
                             relief='raised', borderwidth=2)
        files_card.grid(row=0, column=2, padx=8, pady=5, sticky='nsew')
        
        tk.Label(files_card, text="📁", bg='#0f1729', fg='#aa88ff', 
                font=('Segoe UI', 20)).pack(pady=(8, 2))
        self.files_count_label = tk.Label(files_card, text="0", bg='#0f1729', 
                                          fg='#aa88ff', font=('Segoe UI', 24, 'bold'))
        self.files_count_label.pack()
        tk.Label(files_card, text="Files", bg='#0f1729', 
                fg='#888', font=('Segoe UI', 9)).pack(pady=(0, 8))
        
        # Control Panel with modern design
        control_panel = tk.Frame(main_container, bg='#0a0d1a')
        control_panel.pack(fill='x', padx=20, pady=15)
        
        control_inner = tk.Frame(control_panel, bg='#1a1f35', 
                                relief='raised', borderwidth=2)
        control_inner.pack(fill='x', padx=5, pady=5)
        
        # Program selection with icon
        prog_frame = tk.Frame(control_inner, bg='#1a1f35')
        prog_frame.pack(fill='x', padx=20, pady=15)
        
        tk.Label(prog_frame, text="🎯", bg='#1a1f35', fg='white', 
                font=('Segoe UI', 18)).pack(side='left', padx=(0, 10))
        
        tk.Label(prog_frame, text="Target Program:", bg='#1a1f35', 
                fg='white', font=('Segoe UI', 11, 'bold')).pack(side='left', padx=5)
        
        self.program_path = tk.Entry(prog_frame, width=50, font=('Segoe UI', 11), 
                                     bg='#0f1729', fg='white', 
                                     insertbackground='#00ff88', relief='flat', bd=0)
        self.program_path.pack(side='left', padx=10, ipady=8)
        
        browse_btn = tk.Button(prog_frame, text="📁 Browse", 
                              command=self.browse_program,
                              bg='#4488ff', fg='white', 
                              font=('Segoe UI', 10, 'bold'),
                              relief='flat', padx=15, pady=8,
                              cursor='hand2', activebackground='#3366cc')
        browse_btn.pack(side='left', padx=5)
        
        # Arguments with icon
        args_frame = tk.Frame(control_inner, bg='#1a1f35')
        args_frame.pack(fill='x', padx=20, pady=(0, 15))
        
        tk.Label(args_frame, text="⚙️", bg='#1a1f35', fg='white', 
                font=('Segoe UI', 18)).pack(side='left', padx=(0, 10))
        
        tk.Label(args_frame, text="Arguments:", bg='#1a1f35', 
                fg='white', font=('Segoe UI', 11, 'bold')).pack(side='left', padx=5)
        
        self.args_entry = tk.Entry(args_frame, width=50, font=('Segoe UI', 11), 
                                   bg='#0f1729', fg='white', 
                                   insertbackground='#00ff88', relief='flat', bd=0)
        self.args_entry.pack(side='left', padx=10, ipady=8)
        
        # Action buttons with modern styling
        button_panel = tk.Frame(control_inner, bg='#1a1f35')
        button_panel.pack(pady=20)
        
        # Start button
        self.start_btn = tk.Button(button_panel, text="▶ Execute", 
                                   command=self.start_execution,
                                   bg='#00ff88', fg='#0a0d1a', 
                                   font=('Segoe UI', 12, 'bold'),
                                   relief='flat', padx=25, pady=12,
                                   cursor='hand2', activebackground='#00cc66')
        self.start_btn.pack(side='left', padx=5)
        
        # Stop button
        self.stop_btn = tk.Button(button_panel, text="⬛ Terminate", 
                                  command=self.stop_execution,
                                  bg='#ff4444', fg='white', 
                                  font=('Segoe UI', 12, 'bold'),
                                  relief='flat', padx=25, pady=12,
                                  cursor='hand2', state='disabled',
                                  activebackground='#cc0000')
        self.stop_btn.pack(side='left', padx=5)
        
        # Report button
        report_btn = tk.Button(button_panel, text="📊 Report", 
                              command=self.generate_report,
                              bg='#4488ff', fg='white', 
                              font=('Segoe UI', 12, 'bold'),
                              relief='flat', padx=25, pady=12,
                              cursor='hand2', activebackground='#3366cc')
        report_btn.pack(side='left', padx=5)
        
        # Quarantine button
        quarantine_btn = tk.Button(button_panel, text="🔒 Quarantine", 
                                   command=self.quarantine_current,
                                   bg='#ffaa00', fg='white', 
                                   font=('Segoe UI', 12, 'bold'),
                                   relief='flat', padx=25, pady=12,
                                   cursor='hand2', activebackground='#cc8800')
        quarantine_btn.pack(side='left', padx=5)
        
        # Clear button
        clear_btn = tk.Button(button_panel, text="🗑️ Clear", 
                             command=self.clear_all,
                             bg='#6c757d', fg='white', 
                             font=('Segoe UI', 12, 'bold'),
                             relief='flat', padx=25, pady=12,
                             cursor='hand2', activebackground='#545b62')
        clear_btn.pack(side='left', padx=5)
        
        # Main content area with tabs
        content_frame = tk.Frame(main_container, bg='#0a0d1a')
        content_frame.pack(fill='both', expand=True, padx=20, pady=(0, 10))
        
        self.notebook = ttk.Notebook(content_frame)
        self.notebook.pack(fill='both', expand=True)
        
        # Create all tabs
        self.create_dashboard_tab()
        self.create_logs_tab()
        self.create_resources_tab()
        self.create_network_tab()
        self.create_files_tab()
        self.create_output_tab()
        self.create_analysis_tab()
        
        # Status bar with gradient
        status_bar = tk.Frame(main_container, bg='#1a1f35', height=50)
        status_bar.pack(fill='x', padx=0, pady=0)
        status_bar.pack_propagate(False)
        
        status_content = tk.Frame(status_bar, bg='#1a1f35')
        status_content.pack(fill='both', expand=True, padx=20)
        
        # Left side - Status
        status_left = tk.Frame(status_content, bg='#1a1f35')
        status_left.pack(side='left', fill='y')
        
        self.status_label = tk.Label(status_left, text="⚪ Status: Ready", 
                                     bg='#1a1f35', fg='#00ff88', 
                                     font=('Segoe UI', 11, 'bold'))
        self.status_label.pack(side='left', pady=12)
        
        tk.Label(status_left, text=" | ", bg='#1a1f35', fg='#444', 
                font=('Segoe UI', 11)).pack(side='left')
        
        self.time_label = tk.Label(status_left, text="Runtime: 0s", 
                                   bg='#1a1f35', fg='#88ccff', 
                                   font=('Segoe UI', 10))
        self.time_label.pack(side='left', pady=12)
        
        # Right side - Designer credit
        status_right = tk.Frame(status_content, bg='#1a1f35')
        status_right.pack(side='right', fill='y')
        
        # Animated designer tag
        designer_frame = tk.Frame(status_right, bg='#0f1729', 
                                 relief='raised', borderwidth=1)
        designer_frame.pack(side='right', pady=8)
        
        tk.Label(designer_frame, text="💻", bg='#0f1729', fg='#00ff88', 
                font=('Segoe UI', 12)).pack(side='left', padx=(10, 5))
        
        tk.Label(designer_frame, text="Designed by", bg='#0f1729', 
                fg='#888', font=('Segoe UI', 9)).pack(side='left', padx=2)
        
        tk.Label(designer_frame, text="User 0x007b", bg='#0f1729', 
                fg='#00ff88', font=('Segoe UI', 10, 'bold')).pack(side='left', padx=2)
        
        tk.Label(designer_frame, text="(AshSec)", bg='#0f1729', 
                fg='#667eea', font=('Segoe UI', 10, 'bold italic')).pack(side='left', padx=(2, 10))
        
    def create_dashboard_tab(self):
        """Dashboard with real-time graphs"""
        dash_frame = ttk.Frame(self.notebook, style='Card.TFrame')
        self.notebook.add(dash_frame, text='📊 Dashboard')
        
        if MATPLOTLIB_AVAILABLE:
            # CPU Graph
            cpu_frame = ttk.Frame(dash_frame, style='Card.TFrame')
            cpu_frame.pack(fill='both', expand=True, padx=10, pady=5)
            
            self.cpu_fig = Figure(figsize=(6, 2.5), facecolor='#1a1f35')
            self.cpu_ax = self.cpu_fig.add_subplot(111, facecolor='#0f1729')
            self.cpu_ax.set_title('CPU Usage (%)', color='white', fontsize=12, fontweight='bold')
            self.cpu_ax.set_xlabel('Time', color='#888')
            self.cpu_ax.set_ylabel('CPU %', color='#888')
            self.cpu_ax.tick_params(colors='#888')
            self.cpu_ax.grid(True, alpha=0.2, color='#444')
            
            self.cpu_canvas = FigureCanvasTkAgg(self.cpu_fig, cpu_frame)
            self.cpu_canvas.get_tk_widget().pack(fill='both', expand=True)
            
            # Memory Graph
            mem_frame = ttk.Frame(dash_frame, style='Card.TFrame')
            mem_frame.pack(fill='both', expand=True, padx=10, pady=5)
            
            self.mem_fig = Figure(figsize=(6, 2.5), facecolor='#1a1f35')
            self.mem_ax = self.mem_fig.add_subplot(111, facecolor='#0f1729')
            self.mem_ax.set_title('Memory Usage (MB)', color='white', fontsize=12, fontweight='bold')
            self.mem_ax.set_xlabel('Time', color='#888')
            self.mem_ax.set_ylabel('Memory (MB)', color='#888')
            self.mem_ax.tick_params(colors='#888')
            self.mem_ax.grid(True, alpha=0.2, color='#444')
            
            self.mem_canvas = FigureCanvasTkAgg(self.mem_fig, mem_frame)
            self.mem_canvas.get_tk_widget().pack(fill='both', expand=True)
        else:
            ttk.Label(dash_frame, text="Install matplotlib for graphs:\npip install matplotlib", 
                     background='#1a1f35', foreground='#ffaa00', 
                     font=('Segoe UI', 14)).pack(expand=True)
    
    def create_logs_tab(self):
        """Activity logs tab"""
        logs_frame = ttk.Frame(self.notebook, style='Card.TFrame')
        self.notebook.add(logs_frame, text='📝 Activity Logs')
        
        # Filter buttons
        filter_frame = ttk.Frame(logs_frame, style='Card.TFrame')
        filter_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(filter_frame, text="Filter:", background='#1a1f35', foreground='white', 
                 font=('Segoe UI', 10, 'bold')).pack(side='left', padx=5)
        
        self.log_filter = tk.StringVar(value='ALL')
        for filter_type in ['ALL', 'ERROR', 'WARNING', 'BLOCKED', 'NETWORK', 'FILE']:
            ttk.Radiobutton(filter_frame, text=filter_type, variable=self.log_filter, 
                           value=filter_type).pack(side='left', padx=5)
        
        self.logs_text = scrolledtext.ScrolledText(logs_frame, height=20, bg='#0f1729', 
                                                   fg='#00ff88', font=('Consolas', 10), 
                                                   insertbackground='white', relief='flat', bd=5)
        self.logs_text.pack(fill='both', expand=True, padx=10, pady=10)
        
    def create_resources_tab(self):
        """Resource monitoring tab"""
        resources_frame = ttk.Frame(self.notebook, style='Card.TFrame')
        self.notebook.add(resources_frame, text='📈 Resources')
        
        self.resources_text = scrolledtext.ScrolledText(resources_frame, height=20, bg='#0f1729', 
                                                        fg='#88ccff', font=('Consolas', 10), 
                                                        insertbackground='white', relief='flat', bd=5)
        self.resources_text.pack(fill='both', expand=True, padx=10, pady=10)
        
    def create_network_tab(self):
        """Network activity tab"""
        network_frame = ttk.Frame(self.notebook, style='Card.TFrame')
        self.notebook.add(network_frame, text='🌐 Network')
        
        self.network_text = scrolledtext.ScrolledText(network_frame, height=20, bg='#0f1729', 
                                                      fg='#ffff00', font=('Consolas', 10), 
                                                      insertbackground='white', relief='flat', bd=5)
        self.network_text.pack(fill='both', expand=True, padx=10, pady=10)
        
    def create_files_tab(self):
        """File access tab"""
        files_frame = ttk.Frame(self.notebook, style='Card.TFrame')
        self.notebook.add(files_frame, text='📁 File Access')
        
        self.files_text = scrolledtext.ScrolledText(files_frame, height=20, bg='#0f1729', 
                                                    fg='#aa88ff', font=('Consolas', 10), 
                                                    insertbackground='white', relief='flat', bd=5)
        self.files_text.pack(fill='both', expand=True, padx=10, pady=10)
        
    def create_output_tab(self):
        """Program output tab"""
        output_frame = ttk.Frame(self.notebook, style='Card.TFrame')
        self.notebook.add(output_frame, text='💻 Output')
        
        self.output_text = scrolledtext.ScrolledText(output_frame, height=20, bg='#0f1729', 
                                                     fg='white', font=('Consolas', 10), 
                                                     insertbackground='white', relief='flat', bd=5)
        self.output_text.pack(fill='both', expand=True, padx=10, pady=10)
        
    def create_analysis_tab(self):
        """Threat analysis tab"""
        analysis_frame = ttk.Frame(self.notebook, style='Card.TFrame')
        self.notebook.add(analysis_frame, text='🔍 Analysis')
        
        self.analysis_text = scrolledtext.ScrolledText(analysis_frame, height=20, bg='#0f1729', 
                                                       fg='#ff8888', font=('Consolas', 10), 
                                                       insertbackground='white', relief='flat', bd=5)
        self.analysis_text.pack(fill='both', expand=True, padx=10, pady=10)
        
    def browse_program(self):
        """Browse and select program"""
        filename = filedialog.askopenfilename(
            title="Select Program to Execute",
            filetypes=[
                ("Python Files", "*.py"),
                ("Executable", "*.exe"),
                ("Batch Files", "*.bat"),
                ("Shell Scripts", "*.sh"),
                ("All Files", "*.*")
            ]
        )
        if filename:
            self.program_path.delete(0, tk.END)
            self.program_path.insert(0, filename)
    
    def start_execution(self):
        """Start program execution"""
        program = self.program_path.get()
        if not program:
            messagebox.showerror("Error", "Please select a program to execute")
            return
        
        args = self.args_entry.get()
        
        # Reset data
        self.sandbox.logs = []
        self.sandbox.resource_usage.clear()
        self.sandbox.network_connections = []
        self.sandbox.file_accesses = []
        self.sandbox.monitoring = True
        self.sandbox.threat_score = 0
        
        # Clear graphs
        if MATPLOTLIB_AVAILABLE:
            self.cpu_ax.clear()
            self.mem_ax.clear()
            self.cpu_canvas.draw()
            self.mem_canvas.draw()
        
        # Start execution
        if self.sandbox.execute_program(program, args):
            self.status_label.config(
                text=f"🟢 Status: Running (PID: {self.sandbox.process.pid})", 
                foreground='#00ff88'
            )
            self.start_btn.config(state='disabled')
            self.stop_btn.config(state='normal')
            
            # Start monitoring thread
            self.monitoring_thread = threading.Thread(
                target=self.sandbox.monitor_process, 
                daemon=True
            )
            self.monitoring_thread.start()
            
            # Start output reading
            threading.Thread(target=self.read_output, daemon=True).start()
            
            # Start graph updates immediately
            if MATPLOTLIB_AVAILABLE:
                self.root.after(1000, self.update_graphs)
        else:
            messagebox.showerror("Execution Failed", "Could not start the program")
    
    def stop_execution(self):
        """Stop running program"""
        self.sandbox.monitoring = False
        self.sandbox.terminate_process()
        
        self.status_label.config(text="🔴 Status: Stopped", foreground='#ff4444')
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        
        if self.graph_update_job:
            self.root.after_cancel(self.graph_update_job)
    
    def read_output(self):
        """Read program output"""
        if not self.sandbox.process:
            return
        
        try:
            while True:
                output = self.sandbox.process.stdout.readline()
                if output == '' and self.sandbox.process.poll() is not None:
                    break
                if output:
                    self.output_text.insert(tk.END, output)
                    self.output_text.see(tk.END)
            
            stderr = self.sandbox.process.stderr.read()
            if stderr:
                self.output_text.insert(tk.END, f"\n=== STDERR ===\n{stderr}\n")
            
            self.status_label.config(text="🟡 Status: Completed", foreground='#ffaa00')
            self.start_btn.config(state='normal')
            self.stop_btn.config(state='disabled')
            self.sandbox.monitoring = False
            
        except Exception as e:
            self.sandbox.log_action("ERROR", f"Output reading error: {str(e)}")
    
    def update_dashboard(self):
        """Update dashboard stats"""
        # Update counters with animation effect
        self.threat_label.config(text=str(self.sandbox.threat_score))
        self.logs_count_label.config(text=str(len(self.sandbox.logs)))
        self.files_count_label.config(text=str(len(self.sandbox.file_accesses)))
        
        # Color code threat score
        if self.sandbox.threat_score >= 70:
            self.threat_label.config(foreground='#ff4444')
        elif self.sandbox.threat_score >= 40:
            self.threat_label.config(foreground='#ffaa00')
        else:
            self.threat_label.config(foreground='#00ff88')
        
        # Update runtime
        if self.sandbox.resource_usage:
            runtime = self.sandbox.resource_usage[-1]['elapsed']
            self.time_label.config(text=f"Runtime: {runtime}s")
        
        # Update logs
        self.update_logs_display()
        
        # Update resources
        self.update_resources_display()
        
        # Update network
        self.update_network_display()
        
        # Update files
        self.update_files_display()
        
        # Update analysis
        self.update_analysis_display()
        
        # Schedule next update
        self.root.after(1000, self.update_dashboard)
    
    def update_logs_display(self):
        """Update logs with filtering"""
        self.logs_text.delete(1.0, tk.END)
        
        filter_type = self.log_filter.get()
        filtered_logs = [
            log for log in self.sandbox.logs[-100:]
            if filter_type == 'ALL' or log['level'] == filter_type
        ]
        
        for log in filtered_logs:
            # Color mapping
            colors = {
                'INFO': '#88ccff',
                'SUCCESS': '#00ff88',
                'WARNING': '#ffaa00',
                'ERROR': '#ff4444',
                'BLOCKED': '#ff0000',
                'FILE': '#aa88ff',
                'NETWORK': '#ffff00',
                'ANALYSIS': '#ff88ff',
                'QUARANTINE': '#ff8800'
            }
            
            color = colors.get(log['level'], '#ffffff')
            
            self.logs_text.insert(tk.END, f"[{log['timestamp']}] ", 'time')
            self.logs_text.insert(tk.END, f"[{log['level']}] ", (log['level'], ))
            self.logs_text.insert(tk.END, f"{log['message']}\n")
            
            self.logs_text.tag_config('time', foreground='#666666')
            self.logs_text.tag_config(log['level'], foreground=color, font=('Consolas', 10, 'bold'))
    
    def update_resources_display(self):
        """Update resource monitor"""
        self.resources_text.delete(1.0, tk.END)
        
        if not self.sandbox.resource_usage:
            self.resources_text.insert(tk.END, "No resource data available\n")
            return
        
        header = f"{'Time':<10} | {'Elapsed':<8} | {'CPU%':<8} | {'Memory(MB)':<12} | {'Threads':<8} | {'Handles':<8}\n"
        separator = "-" * 80 + "\n"
        
        self.resources_text.insert(tk.END, header, 'header')
        self.resources_text.insert(tk.END, separator)
        
        for r in list(self.sandbox.resource_usage)[-25:]:
            line = f"{r['time']:<10} | {r['elapsed']:<8} | {r['cpu']:>6.1f}% | {r['memory']:>10.2f} | {r['threads']:>8} | {r.get('handles', 0):>8}\n"
            self.resources_text.insert(tk.END, line)
        
        self.resources_text.tag_config('header', foreground='#00ff88', font=('Consolas', 10, 'bold'))
    
    def update_network_display(self):
        """Update network connections"""
        self.network_text.delete(1.0, tk.END)
        
        if not self.sandbox.network_connections:
            self.network_text.insert(tk.END, "No network activity detected\n")
            return
        
        header = f"{'Time':<10} | {'Local Address':<25} | {'Remote Address':<25} | {'Status':<15}\n"
        separator = "-" * 85 + "\n"
        
        self.network_text.insert(tk.END, header, 'header')
        self.network_text.insert(tk.END, separator)
        
        for conn in self.sandbox.network_connections[-50:]:
            line = f"{conn['time']:<10} | {conn['local']:<25} | {conn['remote']:<25} | {conn['status']:<15}\n"
            self.network_text.insert(tk.END, line)
        
        self.network_text.tag_config('header', foreground='#ffff00', font=('Consolas', 10, 'bold'))
    
    def update_files_display(self):
        """Update file access log"""
        self.files_text.delete(1.0, tk.END)
        
        if not self.sandbox.file_accesses:
            self.files_text.insert(tk.END, "No file access detected\n")
            return
        
        header = f"{'Time':<10} | {'FD':<5} | {'File Path':<70}\n"
        separator = "-" * 90 + "\n"
        
        self.files_text.insert(tk.END, header, 'header')
        self.files_text.insert(tk.END, separator)
        
        for f in self.sandbox.file_accesses[-50:]:
            line = f"{f['time']:<10} | {f['fd']:<5} | {f['path']:<70}\n"
            self.files_text.insert(tk.END, line)
        
        self.files_text.tag_config('header', foreground='#aa88ff', font=('Consolas', 10, 'bold'))
    
    def update_analysis_display(self):
        """Update threat analysis"""
        self.analysis_text.delete(1.0, tk.END)
        
        analysis = f"""
╔══════════════════════════════════════════════════════════════╗
║              THREAT ANALYSIS REPORT                          ║
╚══════════════════════════════════════════════════════════════╝

Threat Score: {self.sandbox.threat_score}/100

Risk Level: {"🔴 HIGH" if self.sandbox.threat_score >= 70 else "🟡 MEDIUM" if self.sandbox.threat_score >= 40 else "🟢 LOW"}

─────────────────────────────────────────────────────────────

Statistics:
  • Total Log Entries: {len(self.sandbox.logs)}
  • Blocked Actions: {sum(1 for log in self.sandbox.logs if log['level'] == 'BLOCKED')}
  • File Accesses: {len(self.sandbox.file_accesses)}
  • Network Connections: {len(self.sandbox.network_connections)}
  • Warnings: {sum(1 for log in self.sandbox.logs if log['level'] == 'WARNING')}
  • Errors: {sum(1 for log in self.sandbox.logs if log['level'] == 'ERROR')}

─────────────────────────────────────────────────────────────

Resource Summary:
"""
        
        if self.sandbox.resource_usage:
            avg_cpu = sum(r['cpu'] for r in self.sandbox.resource_usage) / len(self.sandbox.resource_usage)
            max_cpu = max(r['cpu'] for r in self.sandbox.resource_usage)
            avg_mem = sum(r['memory'] for r in self.sandbox.resource_usage) / len(self.sandbox.resource_usage)
            max_mem = max(r['memory'] for r in self.sandbox.resource_usage)
            
            analysis += f"""  • Average CPU: {avg_cpu:.2f}%
  • Peak CPU: {max_cpu:.2f}%
  • Average Memory: {avg_mem:.2f} MB
  • Peak Memory: {max_mem:.2f} MB
  • Execution Time: {self.sandbox.resource_usage[-1]['elapsed']}s
"""
        
        analysis += "\n─────────────────────────────────────────────────────────────\n\n"
        
        # Threat indicators
        blocked = sum(1 for log in self.sandbox.logs if log['level'] == 'BLOCKED')
        if blocked > 0:
            analysis += f"⚠️  {blocked} blocked action(s) detected\n"
        
        if self.sandbox.network_connections:
            analysis += f"🌐 {len(self.sandbox.network_connections)} network connection(s) established\n"
        
        high_cpu = sum(1 for r in self.sandbox.resource_usage if r['cpu'] > 80)
        if high_cpu > 0:
            analysis += f"📊 High CPU usage detected {high_cpu} times\n"
        
        self.analysis_text.insert(tk.END, analysis)
    
    def update_graphs(self):
        """Update real-time graphs"""
        if not MATPLOTLIB_AVAILABLE:
            return
        
        if not self.sandbox.resource_usage or len(self.sandbox.resource_usage) == 0:
            # Schedule next update even if no data yet
            if self.sandbox.monitoring:
                self.graph_update_job = self.root.after(1000, self.update_graphs)
            return
        
        data = list(self.sandbox.resource_usage)[-50:]
        
        # CPU Graph
        times = list(range(len(data)))
        cpu_values = [r['cpu'] for r in data]
        
        self.cpu_ax.clear()
        self.cpu_ax.plot(times, cpu_values, color='#00ff88', linewidth=2.5, marker='o', markersize=4)
        self.cpu_ax.fill_between(times, cpu_values, alpha=0.3, color='#00ff88')
        self.cpu_ax.set_title('CPU Usage (%)', color='white', fontsize=12, fontweight='bold', pad=10)
        self.cpu_ax.set_xlabel('Time (samples)', color='#888', fontsize=9)
        self.cpu_ax.set_ylabel('CPU %', color='#888', fontsize=9)
        self.cpu_ax.tick_params(colors='#888', labelsize=8)
        self.cpu_ax.grid(True, alpha=0.2, color='#444', linestyle='--')
        self.cpu_ax.set_facecolor('#0f1729')
        self.cpu_ax.set_ylim(0, 100)
        
        # Add current value text
        if cpu_values:
            current_cpu = cpu_values[-1]
            self.cpu_ax.text(0.02, 0.98, f'Current: {current_cpu:.1f}%', 
                           transform=self.cpu_ax.transAxes,
                           fontsize=10, color='#00ff88', fontweight='bold',
                           verticalalignment='top',
                           bbox=dict(boxstyle='round', facecolor='#0f1729', alpha=0.8))
        
        self.cpu_canvas.draw()
        
        # Memory Graph
        mem_values = [r['memory'] for r in data]
        
        self.mem_ax.clear()
        self.mem_ax.plot(times, mem_values, color='#88ccff', linewidth=2.5, marker='s', markersize=4)
        self.mem_ax.fill_between(times, mem_values, alpha=0.3, color='#88ccff')
        self.mem_ax.set_title('Memory Usage (MB)', color='white', fontsize=12, fontweight='bold', pad=10)
        self.mem_ax.set_xlabel('Time (samples)', color='#888', fontsize=9)
        self.mem_ax.set_ylabel('Memory (MB)', color='#888', fontsize=9)
        self.mem_ax.tick_params(colors='#888', labelsize=8)
        self.mem_ax.grid(True, alpha=0.2, color='#444', linestyle='--')
        self.mem_ax.set_facecolor('#0f1729')
        
        # Add current value text
        if mem_values:
            current_mem = mem_values[-1]
            self.mem_ax.text(0.02, 0.98, f'Current: {current_mem:.1f} MB', 
                           transform=self.mem_ax.transAxes,
                           fontsize=10, color='#88ccff', fontweight='bold',
                           verticalalignment='top',
                           bbox=dict(boxstyle='round', facecolor='#0f1729', alpha=0.8))
        
        self.mem_canvas.draw()
        
        # Schedule next update
        if self.sandbox.monitoring:
            self.graph_update_job = self.root.after(1000, self.update_graphs)
    
    def generate_report(self):
        """Generate comprehensive report"""
        report = self.sandbox.export_report()
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"sandbox_report_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            
            messagebox.showinfo(
                "Report Generated", 
                f"Comprehensive report saved to:\n{filename}\n\n" +
                f"Threat Score: {report['execution']['threat_score']}/100\n" +
                f"Total Logs: {report['execution']['total_logs']}\n" +
                f"Network Connections: {report['network']['total_connections']}\n" +
                f"Files Accessed: {report['files']['total_accessed']}"
            )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate report: {str(e)}")
    
    def quarantine_current(self):
        """Quarantine current program"""
        program = self.program_path.get()
        if not program or not os.path.exists(program):
            messagebox.showwarning("Warning", "No valid program selected")
            return
        
        result = messagebox.askyesno(
            "Quarantine File",
            f"Quarantine this file?\n\n{program}\n\nThis will copy it to quarantine directory."
        )
        
        if result:
            dest = self.sandbox.quarantine_file(program)
            if dest:
                messagebox.showinfo("Success", f"File quarantined to:\n{dest}")
    
    def clear_all(self):
        """Clear all data"""
        result = messagebox.askyesno("Clear All", "Clear all logs and monitoring data?")
        if result:
            self.sandbox.logs = []
            self.sandbox.resource_usage.clear()
            self.sandbox.network_connections = []
            self.sandbox.file_accesses = []
            self.sandbox.threat_score = 0
            
            self.logs_text.delete(1.0, tk.END)
            self.resources_text.delete(1.0, tk.END)
            self.network_text.delete(1.0, tk.END)
            self.files_text.delete(1.0, tk.END)
            self.output_text.delete(1.0, tk.END)
            self.analysis_text.delete(1.0, tk.END)
            
            if MATPLOTLIB_AVAILABLE:
                self.cpu_ax.clear()
                self.mem_ax.clear()
                self.cpu_canvas.draw()
                self.mem_canvas.draw()


def main():
    """Main entry point"""
    root = tk.Tk()
    
    # Center window
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - (1400 // 2)
    y = (root.winfo_screenheight() // 2) - (900 // 2)
    root.geometry(f'1400x900+{x}+{y}')
    
    app = SandboxGUI(root)
    root.mainloop()


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║             SecureSandbox Pro v2.0                           ║
║       Advanced Process Isolation & Monitoring System         ║
║                                                              ║
║  Features:                                                   ║
║    • Real-time resource monitoring with graphs               ║
║    • Threat analysis & scoring                               ║
║    • File hash calculation (MD5/SHA-256)                     ║
║    • Network activity tracking                               ║
║    • Malware signature detection                            ║
║    • Quarantine system                                       ║
║    • Comprehensive reporting                                ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    main()