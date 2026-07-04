#!/usr/bin/env python3
"""
Password Cracking Simulator
Information Security Educational Tool

Demonstrates various password attack techniques:
- Brute Force Attack
- Dictionary Attack
- Rainbow Table Attack
- Hybrid Attack

Author: Information Security Project
"""

import hashlib
import itertools
import string
import time
from typing import Optional, Dict, List, Tuple
import os


class PasswordCracker:
    """
    Password cracking simulator demonstrating various attack techniques.
    Educational tool for understanding password security.
    """
    
    def __init__(self):
        self.attempts = 0
        self.start_time = 0
        self.rainbow_table: Dict[str, str] = {}
        
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
                          charset: str = None, algorithm: str = 'sha256') -> Optional[str]:
        """
        Brute force attack - tries all possible combinations
        
        Args:
            target_hash: Hash to crack
            max_length: Maximum password length to try
            charset: Character set to use (default: lowercase + digits)
            algorithm: Hash algorithm used
            
        Returns:
            Cracked password or None
        """
        print("\n🔨 BRUTE FORCE ATTACK")
        print("=" * 60)
        
        if charset is None:
            charset = string.ascii_lowercase + string.digits
        
        self.attempts = 0
        self.start_time = time.time()
        
        for length in range(1, max_length + 1):
            print(f"\n⏳ Trying passwords of length {length}...")
            
            # Generate all combinations of given length
            for attempt in itertools.product(charset, repeat=length):
                password = ''.join(attempt)
                self.attempts += 1
                
                # Hash and compare
                if self.hash_password(password, algorithm) == target_hash:
                    elapsed = time.time() - self.start_time
                    self._print_success(password, elapsed)
                    return password
                
                # Progress indicator
                if self.attempts % 10000 == 0:
                    print(f"   Attempts: {self.attempts:,}", end='\r')
        
        elapsed = time.time() - self.start_time
        self._print_failure(elapsed)
        return None
    
    def dictionary_attack(self, target_hash: str, wordlist_path: str = None,
                         algorithm: str = 'sha256') -> Optional[str]:
        """
        Dictionary attack - tries words from a wordlist
        
        Args:
            target_hash: Hash to crack
            wordlist_path: Path to wordlist file
            algorithm: Hash algorithm used
            
        Returns:
            Cracked password or None
        """
        print("\n📚 DICTIONARY ATTACK")
        print("=" * 60)
        
        # Create a sample wordlist if none provided
        if wordlist_path is None:
            wordlist = self._generate_sample_wordlist()
        else:
            try:
                with open(wordlist_path, 'r', encoding='utf-8') as f:
                    wordlist = [line.strip() for line in f]
            except FileNotFoundError:
                print(f"❌ Wordlist file not found: {wordlist_path}")
                return None
        
        self.attempts = 0
        self.start_time = time.time()
        
        print(f"📖 Loaded {len(wordlist)} words")
        print("⏳ Starting attack...\n")
        
        for word in wordlist:
            self.attempts += 1
            
            # Try the word as-is
            if self.hash_password(word, algorithm) == target_hash:
                elapsed = time.time() - self.start_time
                self._print_success(word, elapsed)
                return word
            
            # Try common variations
            variations = self._generate_variations(word)
            for variation in variations:
                self.attempts += 1
                if self.hash_password(variation, algorithm) == target_hash:
                    elapsed = time.time() - self.start_time
                    self._print_success(variation, elapsed)
                    return variation
            
            # Progress indicator
            if self.attempts % 100 == 0:
                print(f"   Attempts: {self.attempts:,}", end='\r')
        
        elapsed = time.time() - self.start_time
        self._print_failure(elapsed)
        return None
    
    def rainbow_table_attack(self, target_hash: str, table_size: int = 10000,
                            algorithm: str = 'sha256') -> Optional[str]:
        """
        Rainbow table attack - uses precomputed hash table
        
        Args:
            target_hash: Hash to crack
            table_size: Size of rainbow table to generate
            algorithm: Hash algorithm used
            
        Returns:
            Cracked password or None
        """
        print("\n🌈 RAINBOW TABLE ATTACK")
        print("=" * 60)
        
        # Generate rainbow table if empty
        if not self.rainbow_table:
            print(f"⚙️  Generating rainbow table ({table_size} entries)...")
            self._generate_rainbow_table(table_size, algorithm)
            print(f"✅ Rainbow table generated!")
        
        self.start_time = time.time()
        
        # Lookup in rainbow table
        print("\n🔍 Looking up hash in rainbow table...")
        
        if target_hash in self.rainbow_table:
            password = self.rainbow_table[target_hash]
            elapsed = time.time() - self.start_time
            print(f"\n✅ HASH FOUND IN RAINBOW TABLE!")
            print(f"   Password: {password}")
            print(f"   Time: {elapsed:.4f} seconds (instant lookup)")
            print(f"   Rainbow table size: {len(self.rainbow_table):,} entries")
            return password
        else:
            elapsed = time.time() - self.start_time
            print(f"\n❌ Hash not found in rainbow table")
            print(f"   Time: {elapsed:.4f} seconds")
            print(f"   Table coverage: {len(self.rainbow_table):,} passwords")
            return None
    
    def hybrid_attack(self, target_hash: str, algorithm: str = 'sha256') -> Optional[str]:
        """
        Hybrid attack - combines dictionary and brute force
        
        Args:
            target_hash: Hash to crack
            algorithm: Hash algorithm used
            
        Returns:
            Cracked password or None
        """
        print("\n⚡ HYBRID ATTACK")
        print("=" * 60)
        print("Combining dictionary attack + common patterns...")
        
        wordlist = self._generate_sample_wordlist()
        self.attempts = 0
        self.start_time = time.time()
        
        # Try dictionary words with number suffixes
        for word in wordlist:
            # Try word + numbers (e.g., password123)
            for num in range(0, 1000):
                password = f"{word}{num}"
                self.attempts += 1
                
                if self.hash_password(password, algorithm) == target_hash:
                    elapsed = time.time() - self.start_time
                    self._print_success(password, elapsed)
                    return password
            
            # Try word + special char + numbers (e.g., password!123)
            for char in "!@#$":
                for num in range(0, 100):
                    password = f"{word}{char}{num}"
                    self.attempts += 1
                    
                    if self.hash_password(password, algorithm) == target_hash:
                        elapsed = time.time() - self.start_time
                        self._print_success(password, elapsed)
                        return password
            
            # Progress
            if self.attempts % 1000 == 0:
                print(f"   Attempts: {self.attempts:,}", end='\r')
        
        elapsed = time.time() - self.start_time
        self._print_failure(elapsed)
        return None
    
    def analyze_password_strength(self, password: str) -> Dict:
        """
        Analyze password strength and provide recommendations
        
        Args:
            password: Password to analyze
            
        Returns:
            Dictionary with analysis results
        """
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
        elif analysis['score'] >= 50:
            analysis['strength'] = 'Medium'
        else:
            analysis['strength'] = 'Weak'
        
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
            analysis['recommendations'].append("Add special characters (!@#$%)")
        
        return analysis
    
    def _generate_rainbow_table(self, size: int, algorithm: str):
        """Generate a rainbow table of common passwords"""
        self.rainbow_table = {}
        
        # Common passwords
        common_passwords = self._generate_sample_wordlist()
        
        for word in common_passwords:
            # Add base word
            hash_val = self.hash_password(word, algorithm)
            self.rainbow_table[hash_val] = word
            
            # Add variations
            for num in range(100):
                password = f"{word}{num}"
                hash_val = self.hash_password(password, algorithm)
                self.rainbow_table[hash_val] = password
                
                if len(self.rainbow_table) >= size:
                    return
    
    def _generate_sample_wordlist(self) -> List[str]:
        """Generate sample wordlist of common passwords"""
        return [
            'password', 'admin', 'letmein', 'welcome', 'monkey',
            'dragon', 'master', 'sunshine', 'princess', 'football',
            'shadow', 'michael', 'superman', 'batman', 'trustno1',
            'hello', 'freedom', 'whatever', 'qwerty', 'mustang',
            'starwars', 'summer', 'winter', 'spring', 'autumn',
            'computer', 'internet', 'service', 'coffee', 'orange',
            'apple', 'banana', 'cheese', 'ninja', 'pirate',
            'robot', 'cookie', 'rocket', 'magic', 'secret',
            'awesome', 'hunter', 'soccer', 'hockey', 'tennis'
        ]
    
    def _generate_variations(self, word: str) -> List[str]:
        """Generate common password variations"""
        variations = []
        
        # Capitalize first letter
        variations.append(word.capitalize())
        
        # All uppercase
        variations.append(word.upper())
        
        # Add common suffixes
        variations.extend([f"{word}123", f"{word}1", f"{word}!", 
                          f"{word}@", f"{word}2024"])
        
        # Leet speak variations (basic)
        leet = word.replace('a', '4').replace('e', '3').replace('o', '0')
        if leet != word:
            variations.append(leet)
        
        return variations
    
    def _print_success(self, password: str, elapsed: float):
        """Print success message"""
        print(f"\n\n🎉 PASSWORD CRACKED!")
        print(f"   Password: {password}")
        print(f"   Attempts: {self.attempts:,}")
        print(f"   Time: {elapsed:.4f} seconds")
        print(f"   Speed: {self.attempts/elapsed:.0f} attempts/second")
    
    def _print_failure(self, elapsed: float):
        """Print failure message"""
        print(f"\n\n❌ PASSWORD NOT FOUND")
        print(f"   Attempts: {self.attempts:,}")
        print(f"   Time: {elapsed:.4f} seconds")


def print_banner():
    """Print application banner"""
    banner = """
    ╔════════════════════════════════════════════════════════════╗
    ║                                                            ║
    ║          🔐 PASSWORD CRACKING SIMULATOR 🔐                ║
    ║                                                            ║
    ║              Information Security Tool                     ║
    ║           Educational Demonstration Only                   ║
    ║                                                            ║
    ╚════════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_menu():
    """Print main menu"""
    print("\n" + "=" * 60)
    print("SELECT ATTACK TYPE:")
    print("=" * 60)
    print("1. Brute Force Attack")
    print("2. Dictionary Attack")
    print("3. Rainbow Table Attack")
    print("4. Hybrid Attack")
    print("5. Password Strength Analyzer")
    print("6. Demo Mode (All Attacks)")
    print("0. Exit")
    print("=" * 60)


def demo_mode():
    """Run demonstration of all attack types"""
    print("\n🎬 DEMO MODE - Password Cracking Demonstrations")
    print("=" * 60)
    
    cracker = PasswordCracker()
    
    # Demo 1: Brute Force (very short password)
    print("\n\n📍 DEMO 1: Brute Force Attack")
    print("-" * 60)
    test_password = "ab1"
    target_hash = cracker.hash_password(test_password)
    print(f"Target: '{test_password}' (Hash: {target_hash[:32]}...)")
    result = cracker.brute_force_attack(target_hash, max_length=3)
    input("\n⏸️  Press Enter to continue...")
    
    # Demo 2: Dictionary Attack
    print("\n\n📍 DEMO 2: Dictionary Attack")
    print("-" * 60)
    test_password = "monkey"
    target_hash = cracker.hash_password(test_password)
    print(f"Target: '{test_password}' (Hash: {target_hash[:32]}...)")
    result = cracker.dictionary_attack(target_hash)
    input("\n⏸️  Press Enter to continue...")
    
    # Demo 3: Rainbow Table
    print("\n\n📍 DEMO 3: Rainbow Table Attack")
    print("-" * 60)
    test_password = "password123"
    target_hash = cracker.hash_password(test_password)
    print(f"Target: '{test_password}' (Hash: {target_hash[:32]}...)")
    result = cracker.rainbow_table_attack(target_hash, table_size=5000)
    input("\n⏸️  Press Enter to continue...")
    
    # Demo 4: Hybrid Attack
    print("\n\n📍 DEMO 4: Hybrid Attack")
    print("-" * 60)
    test_password = "admin!42"
    target_hash = cracker.hash_password(test_password)
    print(f"Target: '{test_password}' (Hash: {target_hash[:32]}...)")
    result = cracker.hybrid_attack(target_hash)
    input("\n⏸️  Press Enter to continue...")
    
    # Demo 5: Password Analysis
    print("\n\n📍 DEMO 5: Password Strength Analysis")
    print("-" * 60)
    test_passwords = ["password", "P@ssw0rd!", "MyS3cur3P@ss!", "abc"]
    
    for pwd in test_passwords:
        analysis = cracker.analyze_password_strength(pwd)
        print(f"\n🔍 Analyzing: '{pwd}'")
        print(f"   Strength: {analysis['strength']} ({analysis['score']}/100)")
        print(f"   Length: {analysis['length']} characters")
        print(f"   Has Uppercase: {'✓' if analysis['has_uppercase'] else '✗'}")
        print(f"   Has Lowercase: {'✓' if analysis['has_lowercase'] else '✗'}")
        print(f"   Has Digits: {'✓' if analysis['has_digits'] else '✗'}")
        print(f"   Has Special: {'✓' if analysis['has_special'] else '✗'}")
        
        if analysis['recommendations']:
            print(f"   Recommendations:")
            for rec in analysis['recommendations']:
                print(f"      • {rec}")
    
    print("\n\n✅ Demo completed!")
    print("\n⚠️  KEY TAKEAWAYS:")
    print("   • Simple passwords are VERY easy to crack")
    print("   • Dictionary words are vulnerable")
    print("   • Use long, complex passwords with mixed characters")
    print("   • Enable two-factor authentication when possible")


def main():
    """Main application entry point"""
    print_banner()
    
    print("\n⚠️  LEGAL DISCLAIMER:")
    print("This tool is for EDUCATIONAL PURPOSES ONLY.")
    print("Unauthorized access to computer systems is illegal.")
    print("Only test on systems you own or have permission to test.\n")
    
    cracker = PasswordCracker()
    
    while True:
        print_menu()
        choice = input("\nEnter your choice: ").strip()
        
        if choice == '0':
            print("\n👋 Goodbye! Stay secure!")
            break
            
        elif choice == '6':
            demo_mode()
            
        elif choice == '5':
            # Password Analyzer
            print("\n📊 PASSWORD STRENGTH ANALYZER")
            print("=" * 60)
            password = input("Enter password to analyze: ")
            
            analysis = cracker.analyze_password_strength(password)
            
            print(f"\n🔍 Analysis Results:")
            print(f"   Password: {'*' * len(password)}")
            print(f"   Strength: {analysis['strength']}")
            print(f"   Score: {analysis['score']}/100")
            print(f"\n   Characteristics:")
            print(f"      Length: {analysis['length']} characters")
            print(f"      Lowercase: {'✓' if analysis['has_lowercase'] else '✗'}")
            print(f"      Uppercase: {'✓' if analysis['has_uppercase'] else '✗'}")
            print(f"      Digits: {'✓' if analysis['has_digits'] else '✗'}")
            print(f"      Special: {'✓' if analysis['has_special'] else '✗'}")
            
            if analysis['recommendations']:
                print(f"\n   📋 Recommendations:")
                for rec in analysis['recommendations']:
                    print(f"      • {rec}")
            else:
                print(f"\n   ✅ Password meets security requirements!")
            
        elif choice in ['1', '2', '3', '4']:
            # Get target password
            print("\nEnter target password (or press Enter for demo):")
            target_password = input("Password: ").strip()
            
            if not target_password:
                target_password = "admin" if choice != '1' else "ab1"
                print(f"Using demo password: '{target_password}'")
            
            # Hash the target
            algorithm = 'sha256'
            target_hash = cracker.hash_password(target_password, algorithm)
            print(f"\nTarget Hash: {target_hash}")
            
            # Run selected attack
            if choice == '1':
                max_len = int(input("Max password length to try (1-6): ") or "4")
                cracker.brute_force_attack(target_hash, max_length=max_len)
                
            elif choice == '2':
                cracker.dictionary_attack(target_hash)
                
            elif choice == '3':
                table_size = int(input("Rainbow table size (default 10000): ") or "10000")
                cracker.rainbow_table_attack(target_hash, table_size=table_size)
                
            elif choice == '4':
                cracker.hybrid_attack(target_hash)
        
        else:
            print("❌ Invalid choice! Please try again.")
        
        input("\n⏸️  Press Enter to continue...")


if __name__ == "__main__":
    main()