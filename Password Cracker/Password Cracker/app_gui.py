#!/usr/bin/env python3
"""
Password Cracking Simulator with GUI
Information Security Educational Tool

Demonstrates various password attack techniques:
- Brute Force Attack
- Dictionary Attack
- Rainbow Table Attack
- Hybrid Attack
- Password Strength Analysis

Author: Information Security Project
"""

import hashlib
import itertools
import string
import time
from typing import Optional, Dict, List
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading


class PasswordCracker:
    """Password cracking engine with various attack methods"""
    
    def __init__(self):
        self.attempts = 0
        self.start_time = 0
        self.rainbow_table: Dict[str, str] = {}
        self.stop_flag = False
        
    def hash_password(self, password: str, algorithm: str = 'sha256') -> str:
        """Hash a password using specified algorithm"""
        if algorithm == 'md5':
            return hashlib.md5(password.encode()).hexdigest()
        elif algorithm == 'sha1':
            return hashlib.sha1(password.encode()).hexdigest()
        elif algorithm == 'sha256':
            return hashlib.sha256(password.encode()).hexdigest()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def brute_force_attack(self, target_hash: str, max_length: int = 4, 
                          charset: str = None, algorithm: str = 'sha256',
                          callback=None) -> Optional[str]:
        """Brute force attack - tries all possible combinations"""
        if charset is None:
            charset = string.ascii_lowercase + string.digits
        
        self.attempts = 0
        self.start_time = time.time()
        self.stop_flag = False
        
        for length in range(1, max_length + 1):
            if callback:
                callback(f"Trying passwords of length {length}...\n")
            
            for attempt in itertools.product(charset, repeat=length):
                if self.stop_flag:
                    return None
                    
                password = ''.join(attempt)
                self.attempts += 1
                
                if self.hash_password(password, algorithm) == target_hash:
                    elapsed = time.time() - self.start_time
                    if callback:
                        callback(f"✅ PASSWORD CRACKED!\n")
                        callback(f"Password: {password}\n")
                        callback(f"Attempts: {self.attempts:,}\n")
                        callback(f"Time: {elapsed:.4f} seconds\n")
                        callback(f"Speed: {self.attempts/elapsed:.0f} attempts/sec\n")
                    return password
                
                if self.attempts % 10000 == 0 and callback:
                    callback(f"Attempts: {self.attempts:,}\r")
        
        elapsed = time.time() - self.start_time
        if callback:
            callback(f"\n❌ Password not found\n")
            callback(f"Attempts: {self.attempts:,}\n")
            callback(f"Time: {elapsed:.4f} seconds\n")
        return None
    
    def dictionary_attack(self, target_hash: str, algorithm: str = 'sha256',
                         callback=None) -> Optional[str]:
        """Dictionary attack - tries words from a wordlist"""
        wordlist = self._generate_sample_wordlist()
        self.attempts = 0
        self.start_time = time.time()
        self.stop_flag = False
        
        if callback:
            callback(f"Loaded {len(wordlist)} words\n")
            callback(f"Starting dictionary attack...\n\n")
        
        for word in wordlist:
            if self.stop_flag:
                return None
                
            self.attempts += 1
            
            if self.hash_password(word, algorithm) == target_hash:
                elapsed = time.time() - self.start_time
                if callback:
                    callback(f"✅ PASSWORD CRACKED!\n")
                    callback(f"Password: {word}\n")
                    callback(f"Attempts: {self.attempts:,}\n")
                    callback(f"Time: {elapsed:.4f} seconds\n")
                return word
            
            # Try variations
            variations = self._generate_variations(word)
            for variation in variations:
                if self.stop_flag:
                    return None
                    
                self.attempts += 1
                if self.hash_password(variation, algorithm) == target_hash:
                    elapsed = time.time() - self.start_time
                    if callback:
                        callback(f"✅ PASSWORD CRACKED!\n")
                        callback(f"Password: {variation}\n")
                        callback(f"Attempts: {self.attempts:,}\n")
                        callback(f"Time: {elapsed:.4f} seconds\n")
                    return variation
            
            if self.attempts % 100 == 0 and callback:
                callback(f"Attempts: {self.attempts:,}\r")
        
        elapsed = time.time() - self.start_time
        if callback:
            callback(f"\n❌ Password not found\n")
            callback(f"Attempts: {self.attempts:,}\n")
            callback(f"Time: {elapsed:.4f} seconds\n")
        return None
    
    def rainbow_table_attack(self, target_hash: str, table_size: int = 10000,
                            algorithm: str = 'sha256', callback=None) -> Optional[str]:
        """Rainbow table attack - uses precomputed hash table"""
        if not self.rainbow_table:
            if callback:
                callback(f"Generating rainbow table ({table_size} entries)...\n")
            self._generate_rainbow_table(table_size, algorithm)
            if callback:
                callback(f"✅ Rainbow table generated!\n\n")
        
        self.start_time = time.time()
        
        if callback:
            callback(f"Looking up hash in rainbow table...\n")
        
        if target_hash in self.rainbow_table:
            password = self.rainbow_table[target_hash]
            elapsed = time.time() - self.start_time
            if callback:
                callback(f"\n✅ HASH FOUND!\n")
                callback(f"Password: {password}\n")
                callback(f"Time: {elapsed:.4f} seconds (instant lookup)\n")
                callback(f"Table size: {len(self.rainbow_table):,} entries\n")
            return password
        else:
            elapsed = time.time() - self.start_time
            if callback:
                callback(f"\n❌ Hash not found in rainbow table\n")
                callback(f"Time: {elapsed:.4f} seconds\n")
                callback(f"Table coverage: {len(self.rainbow_table):,} passwords\n")
            return None
    
    def hybrid_attack(self, target_hash: str, algorithm: str = 'sha256',
                     callback=None) -> Optional[str]:
        """Hybrid attack - combines dictionary and brute force"""
        wordlist = self._generate_sample_wordlist()
        self.attempts = 0
        self.start_time = time.time()
        self.stop_flag = False
        
        if callback:
            callback(f"Starting hybrid attack...\n")
            callback(f"Trying dictionary words + patterns...\n\n")
        
        for word in wordlist:
            if self.stop_flag:
                return None
                
            # Try word + numbers
            for num in range(0, 1000):
                if self.stop_flag:
                    return None
                    
                password = f"{word}{num}"
                self.attempts += 1
                
                if self.hash_password(password, algorithm) == target_hash:
                    elapsed = time.time() - self.start_time
                    if callback:
                        callback(f"✅ PASSWORD CRACKED!\n")
                        callback(f"Password: {password}\n")
                        callback(f"Attempts: {self.attempts:,}\n")
                        callback(f"Time: {elapsed:.4f} seconds\n")
                    return password
            
            # Try word + special + numbers
            for char in "!@#$":
                for num in range(0, 100):
                    if self.stop_flag:
                        return None
                        
                    password = f"{word}{char}{num}"
                    self.attempts += 1
                    
                    if self.hash_password(password, algorithm) == target_hash:
                        elapsed = time.time() - self.start_time
                        if callback:
                            callback(f"✅ PASSWORD CRACKED!\n")
                            callback(f"Password: {password}\n")
                            callback(f"Attempts: {self.attempts:,}\n")
                            callback(f"Time: {elapsed:.4f} seconds\n")
                        return password
            
            if self.attempts % 1000 == 0 and callback:
                callback(f"Attempts: {self.attempts:,}\r")
        
        elapsed = time.time() - self.start_time
        if callback:
            callback(f"\n❌ Password not found\n")
            callback(f"Attempts: {self.attempts:,}\n")
            callback(f"Time: {elapsed:.4f} seconds\n")
        return None
    
    def analyze_password_strength(self, password: str) -> Dict:
        """Analyze password strength"""
        analysis = {
            'length': len(password),
            'has_lowercase': any(c.islower() for c in password),
            'has_uppercase': any(c.isupper() for c in password),
            'has_digits': any(c.isdigit() for c in password),
            'has_special': any(c in string.punctuation for c in password),
            'strength': 'Weak',
            'score': 0,
            'recommendations': []
        }
        
        # Calculate score
        if analysis['length'] >= 8:
            analysis['score'] += 25
        if analysis['length'] >= 12:
            analysis['score'] += 15
        if analysis['has_lowercase']:
            analysis['score'] += 15
        if analysis['has_uppercase']:
            analysis['score'] += 15
        if analysis['has_digits']:
            analysis['score'] += 15
        if analysis['has_special']:
            analysis['score'] += 15
        
        # Determine strength
        if analysis['score'] >= 80:
            analysis['strength'] = 'Strong'
            analysis['color'] = '#10b981'
        elif analysis['score'] >= 50:
            analysis['strength'] = 'Medium'
            analysis['color'] = '#f59e0b'
        else:
            analysis['strength'] = 'Weak'
            analysis['color'] = '#ef4444'
        
        # Recommendations
        if analysis['length'] < 8:
            analysis['recommendations'].append("Use at least 8 characters")
        if not analysis['has_uppercase']:
            analysis['recommendations'].append("Add uppercase letters")
        if not analysis['has_lowercase']:
            analysis['recommendations'].append("Add lowercase letters")
        if not analysis['has_digits']:
            analysis['recommendations'].append("Add numbers")
        if not analysis['has_special']:
            analysis['recommendations'].append("Add special characters")
        
        return analysis
    
    def _generate_rainbow_table(self, size: int, algorithm: str):
        """Generate rainbow table"""
        self.rainbow_table = {}
        common_passwords = self._generate_sample_wordlist()
        
        for word in common_passwords:
            hash_val = self.hash_password(word, algorithm)
            self.rainbow_table[hash_val] = word
            
            for num in range(100):
                password = f"{word}{num}"
                hash_val = self.hash_password(password, algorithm)
                self.rainbow_table[hash_val] = password
                
                if len(self.rainbow_table) >= size:
                    return
    
    def _generate_sample_wordlist(self) -> List[str]:
        """Generate sample wordlist"""
        return [
            'password', 'admin', 'letmein', 'welcome', 'monkey',
            'dragon', 'master', 'sunshine', 'princess', 'football',
            'shadow', 'michael', 'superman', 'batman', 'trustno1',
            'hello', 'freedom', 'whatever', 'qwerty', 'mustang',
            'starwars', 'summer', 'winter', 'spring', 'autumn',
            'computer', 'internet', 'service', 'coffee', 'orange',
            'apple', 'banana', 'ninja', 'pirate', 'robot',
            'cookie', 'rocket', 'magic', 'secret', 'awesome'
        ]
    
    def _generate_variations(self, word: str) -> List[str]:
        """Generate password variations"""
        variations = [
            word.capitalize(),
            word.upper(),
            f"{word}123",
            f"{word}1",
            f"{word}!",
            f"{word}@",
        ]
        return variations


class PasswordCrackerGUI:
    """Modern GUI for Password Cracking Simulator"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Password Cracking Simulator")
        self.root.geometry("1000x700")
        self.root.resizable(True, True)
        
        # Color scheme - Modern dark theme
        self.bg_dark = "#0f172a"
        self.bg_medium = "#1e293b"
        self.bg_light = "#334155"
        self.accent_blue = "#3b82f6"
        self.accent_purple = "#8b5cf6"
        self.accent_green = "#10b981"
        self.accent_red = "#ef4444"
        self.accent_yellow = "#f59e0b"
        self.text_color = "#e2e8f0"
        self.text_muted = "#94a3b8"
        
        self.root.configure(bg=self.bg_dark)
        
        # Initialize cracker
        self.cracker = PasswordCracker()
        self.attack_thread = None
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the user interface"""
        
        # Header
        header_frame = tk.Frame(self.root, bg=self.bg_dark)
        header_frame.pack(fill=tk.X, padx=20, pady=(20, 10))
        
        title = tk.Label(
            header_frame,
            text="🔐 Password Cracking Simulator",
            font=("Segoe UI", 28, "bold"),
            bg=self.bg_dark,
            fg=self.accent_blue
        )
        title.pack()
        
        subtitle = tk.Label(
            header_frame,
            text="Educational Security Tool - Demonstration Only",
            font=("Segoe UI", 11),
            bg=self.bg_dark,
            fg=self.text_muted
        )
        subtitle.pack()
        
        # Main container
        main_container = tk.Frame(self.root, bg=self.bg_dark)
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Left panel - Input
        left_panel = tk.Frame(main_container, bg=self.bg_medium, relief=tk.FLAT, bd=0)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        self.setup_input_panel(left_panel)
        
        # Right panel - Output
        right_panel = tk.Frame(main_container, bg=self.bg_medium, relief=tk.FLAT, bd=0)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        self.setup_output_panel(right_panel)
        
        # Footer
        footer = tk.Label(
            self.root,
            text="⚠️ For Educational Purposes Only • Unauthorized Access is Illegal",
            font=("Segoe UI", 9),
            bg=self.bg_dark,
            fg=self.accent_red
        )
        footer.pack(pady=(0, 10))
    
    def setup_input_panel(self, parent):
        """Setup input panel"""
        
        # Title
        title_label = tk.Label(
            parent,
            text="⚙️ Configuration",
            font=("Segoe UI", 16, "bold"),
            bg=self.bg_medium,
            fg=self.text_color
        )
        title_label.pack(pady=(15, 10), padx=15, anchor="w")
        
        # Target Password Section
        target_frame = tk.LabelFrame(
            parent,
            text="Target Password",
            font=("Segoe UI", 11, "bold"),
            bg=self.bg_medium,
            fg=self.text_color,
            bd=2,
            relief=tk.GROOVE
        )
        target_frame.pack(fill=tk.X, padx=15, pady=10)
        
        self.password_entry = tk.Entry(
            target_frame,
            font=("Segoe UI", 12),
            bg=self.bg_light,
            fg=self.text_color,
            insertbackground=self.text_color,
            relief=tk.FLAT,
            bd=0
        )
        self.password_entry.pack(fill=tk.X, padx=10, pady=10, ipady=8)
        self.password_entry.insert(0, "admin")
        
        # Hash display
        hash_label = tk.Label(
            target_frame,
            text="Target Hash (SHA-256):",
            font=("Segoe UI", 9, "bold"),
            bg=self.bg_medium,
            fg=self.text_muted
        )
        hash_label.pack(padx=10, anchor="w")
        
        self.hash_display = tk.Text(
            target_frame,
            font=("Consolas", 9),
            bg=self.bg_dark,
            fg=self.accent_purple,
            height=2,
            wrap=tk.WORD,
            relief=tk.FLAT,
            bd=0
        )
        self.hash_display.pack(fill=tk.X, padx=10, pady=(5, 10))
        
        # Generate hash button
        gen_hash_btn = tk.Button(
            target_frame,
            text="🔄 Generate Hash",
            command=self.generate_hash,
            font=("Segoe UI", 10, "bold"),
            bg=self.accent_purple,
            fg="white",
            activebackground=self.accent_blue,
            relief=tk.FLAT,
            cursor="hand2",
            bd=0
        )
        gen_hash_btn.pack(padx=10, pady=(0, 10), ipady=5, fill=tk.X)
        
        # Attack Type Section
        attack_frame = tk.LabelFrame(
            parent,
            text="Attack Type",
            font=("Segoe UI", 11, "bold"),
            bg=self.bg_medium,
            fg=self.text_color,
            bd=0
        )
        attack_frame.pack(fill=tk.X, padx=15, pady=10)
        
        self.attack_type = tk.StringVar(value="brute_force")
        
        attacks = [
            ("🔨 Brute Force", "brute_force", "Try all combinations"),
            ("📚 Dictionary", "dictionary", "Use common passwords"),
            ("🌈 Rainbow Table", "rainbow", "Precomputed hashes"),
            ("⚡ Hybrid", "hybrid", "Dictionary + patterns")
        ]
        
        for name, value, desc in attacks:
            radio_frame = tk.Frame(attack_frame, bg=self.bg_medium)
            radio_frame.pack(fill=tk.X, padx=10, pady=5)
            
            radio = tk.Radiobutton(
                radio_frame,
                text=name,
                variable=self.attack_type,
                value=value,
                font=("Segoe UI", 11),
                bg=self.bg_medium,
                fg=self.text_color,
                selectcolor=self.bg_light,
                activebackground=self.bg_medium,
                activeforeground=self.accent_blue
            )
            radio.pack(anchor="w")
            
            desc_label = tk.Label(
                radio_frame,
                text=f"  └─ {desc}",
                font=("Segoe UI", 9),
                bg=self.bg_medium,
                fg=self.text_muted
            )
            desc_label.pack(anchor="w")
        
        # Options
        options_frame = tk.LabelFrame(
            parent,
            text="Options",
            font=("Segoe UI", 11, "bold"),
            bg=self.bg_medium,
            fg=self.text_color,
            bd=0
        )
        options_frame.pack(fill=tk.X, padx=15, pady=10)
        
        # Max length for brute force
        length_frame = tk.Frame(options_frame, bg=self.bg_medium)
        length_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(
            length_frame,
            text="Max Length (Brute Force):",
            font=("Segoe UI", 10),
            bg=self.bg_medium,
            fg=self.text_color
        ).pack(side=tk.LEFT)
        
        self.max_length = tk.Spinbox(
            length_frame,
            from_=1,
            to=6,
            font=("Segoe UI", 10),
            bg=self.bg_light,
            fg=self.text_color,
            relief=tk.FLAT,
            width=5
        )
        self.max_length.pack(side=tk.RIGHT, padx=5)
        self.max_length.delete(0, tk.END)
        self.max_length.insert(0, "4")
        
        # Action Buttons
        button_frame = tk.Frame(parent, bg=self.bg_medium)
        button_frame.pack(fill=tk.X, padx=15, pady=20)
        
        self.start_btn = tk.Button(
            button_frame,
            text="🚀 START ATTACK",
            command=self.start_attack,
            font=("Segoe UI", 13, "bold"),
            bg=self.accent_green,
            fg="white",
            activebackground="#059669",
            relief=tk.FLAT,
            cursor="hand2",
            bd=0
        )
        self.start_btn.pack(fill=tk.X, ipady=12)
        
        self.stop_btn = tk.Button(
            button_frame,
            text="⏹️ STOP",
            command=self.stop_attack,
            font=("Segoe UI", 11, "bold"),
            bg=self.accent_red,
            fg="white",
            activebackground="#dc2626",
            relief=tk.FLAT,
            cursor="hand2",
            state="disabled",
            bd=0
        )
        self.stop_btn.pack(fill=tk.X, pady=(10, 0), ipady=8)
        
        # Password Analyzer Button
        analyze_btn = tk.Button(
            button_frame,
            text="📊 Analyze Password Strength",
            command=self.analyze_password,
            font=("Segoe UI", 10),
            bg=self.accent_yellow,
            fg="white",
            activebackground="#d97706",
            relief=tk.FLAT,
            cursor="hand2",
            bd=0
        )
        analyze_btn.pack(fill=tk.X, pady=(10, 0), ipady=8)
    
    def setup_output_panel(self, parent):
        """Setup output panel"""
        
        # Title
        title_label = tk.Label(
            parent,
            text="📊 Results",
            font=("Segoe UI", 16, "bold"),
            bg=self.bg_medium,
            fg=self.text_color
        )
        title_label.pack(pady=(15, 10), padx=15, anchor="w")
        
        # Output text area
        output_frame = tk.Frame(parent, bg=self.bg_medium)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
        
        self.output_text = scrolledtext.ScrolledText(
            output_frame,
            font=("Consolas", 11),
            bg=self.bg_dark,
            fg=self.text_color,
            insertbackground=self.text_color,
            relief=tk.FLAT,
            wrap=tk.WORD,
            bd=0
        )
        self.output_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure tags for colored output
        self.output_text.tag_config("success", foreground=self.accent_green, font=("Consolas", 11, "bold"))
        self.output_text.tag_config("error", foreground=self.accent_red, font=("Consolas", 11, "bold"))
        self.output_text.tag_config("info", foreground=self.accent_blue, font=("Consolas", 11, "bold"))
        self.output_text.tag_config("warning", foreground=self.accent_yellow, font=("Consolas", 11, "bold"))
        
        # Clear button
        clear_btn = tk.Button(
            parent,
            text="🗑️ Clear Output",
            command=self.clear_output,
            font=("Segoe UI", 9),
            bg=self.bg_light,
            fg=self.text_muted,
            activebackground=self.bg_medium,
            relief=tk.FLAT,
            cursor="hand2",
            bd=0
        )
        clear_btn.pack(padx=15, pady=(0, 15), ipady=5)
    
    def generate_hash(self):
        """Generate hash from password"""
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password!")
            return
        
        hash_value = self.cracker.hash_password(password, 'sha256')
        
        self.hash_display.delete(1.0, tk.END)
        self.hash_display.insert(1.0, hash_value)
        
        self.log_output(f"✅ Hash generated for password: '{password}'\n", "success")
        self.log_output(f"SHA-256: {hash_value}\n\n", "info")
    
    def start_attack(self):
        """Start the selected attack"""
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a target password!")
            return
        
        # Generate hash
        target_hash = self.cracker.hash_password(password, 'sha256')
        
        # Update UI
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.clear_output()
        
        # Get attack type
        attack_type = self.attack_type.get()
        
        self.log_output(f"🎯 Target Password: '{password}'\n", "info")
        self.log_output(f"🔑 Target Hash: {target_hash}\n\n", "info")
        
        # Start attack in thread
        self.attack_thread = threading.Thread(
            target=self.run_attack,
            args=(attack_type, target_hash),
            daemon=True
        )
        self.attack_thread.start()
    
    def run_attack(self, attack_type, target_hash):
        """Run the attack in background thread"""
        try:
            if attack_type == "brute_force":
                max_len = int(self.max_length.get())
                self.log_output(f"🔨 Starting Brute Force Attack (max length: {max_len})\n", "warning")
                self.log_output("=" * 60 + "\n\n")
                self.cracker.brute_force_attack(target_hash, max_len, callback=self.log_output)
                
            elif attack_type == "dictionary":
                self.log_output("📚 Starting Dictionary Attack\n", "warning")
                self.log_output("=" * 60 + "\n\n")
                self.cracker.dictionary_attack(target_hash, callback=self.log_output)
                
            elif attack_type == "rainbow":
                self.log_output("🌈 Starting Rainbow Table Attack\n", "warning")
                self.log_output("=" * 60 + "\n\n")
                self.cracker.rainbow_table_attack(target_hash, 10000, callback=self.log_output)
                
            elif attack_type == "hybrid":
                self.log_output("⚡ Starting Hybrid Attack\n", "warning")
                self.log_output("=" * 60 + "\n\n")
                self.cracker.hybrid_attack(target_hash, callback=self.log_output)
        
        finally:
            self.root.after(0, self.attack_completed)
    
    def stop_attack(self):
        """Stop the current attack"""
        self.cracker.stop_flag = True
        self.log_output("\n\n⏹️ Attack stopped by user\n", "error")
        self.attack_completed()
    
    def attack_completed(self):
        """Called when attack completes"""
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
    
    def analyze_password(self):
        """Analyze password strength"""
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password!")
            return
        
        analysis = self.cracker.analyze_password_strength(password)
        
        self.clear_output()
        self.log_output("📊 PASSWORD STRENGTH ANALYSIS\n", "info")
        self.log_output("=" * 60 + "\n\n")
        
        self.log_output(f"Password: {'*' * len(password)}\n")
        self.log_output(f"Length: {analysis['length']} characters\n\n")
        
        # Strength
        strength_tag = "success" if analysis['strength'] == "Strong" else ("warning" if analysis['strength'] == "Medium" else "error")
        self.log_output(f"Strength: {analysis['strength']} ({analysis['score']}/100)\n", strength_tag)
        
        # Characteristics
        self.log_output("\nCharacteristics:\n", "info")
        self.log_output(f"  {'✓' if analysis['has_lowercase'] else '✗'} Lowercase letters\n")
        self.log_output(f"  {'✓' if analysis['has_uppercase'] else '✗'} Uppercase letters\n")
        self.log_output(f"  {'✓' if analysis['has_digits'] else '✗'} Digits\n")
        self.log_output(f"  {'✓' if analysis['has_special'] else '✗'} Special characters\n")
        
        # Recommendations
        if analysis['recommendations']:
            self.log_output("\n📋 Recommendations:\n", "warning")
            for rec in analysis['recommendations']:
                self.log_output(f"  • {rec}\n")
        else:
            self.log_output("\n✅ Password meets security requirements!\n", "success")
    
    def log_output(self, text, tag=None):
        """Log output to text area"""
        self.output_text.insert(tk.END, text, tag)
        self.output_text.see(tk.END)
        self.root.update()
    
    def clear_output(self):
        """Clear output text"""
        self.output_text.delete(1.0, tk.END)


def main():
    """Main application entry point"""
    root = tk.Tk()
    app = PasswordCrackerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
