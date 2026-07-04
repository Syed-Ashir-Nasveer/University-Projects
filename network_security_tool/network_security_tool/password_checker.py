"""
Password Checker Module
Analyzes password strength and provides detailed feedback
"""

import re
import string
from collections import Counter
import math


class PasswordChecker:
    """Comprehensive password strength analyzer"""
    
    def __init__(self):
        # Common passwords list (top 100 most common)
        self.common_passwords = {
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password1', '12345678', '111111', '123123', 'admin',
            'letmein', 'welcome', 'monkey', '1234567890', 'dragon',
            'master', 'sunshine', 'princess', 'football', 'shadow',
            'login', 'admin123', 'root', 'pass', 'passw0rd',
            '1234', '12345', 'test', 'guest', 'changeme'
        }
        
        # Common patterns
        self.patterns = {
            'sequential': r'(012|123|234|345|456|567|678|789|abc|bcd|cde|def)',
            'repeated': r'(.)\1{2,}',
            'keyboard': r'(qwerty|asdfgh|zxcvbn|qazwsx)',
            'date': r'(19|20)\d{2}',
        }
    
    def analyze(self, password):
        """Comprehensive password analysis"""
        if not password:
            return {
                'score': 0,
                'strength': 'No Password',
                'detailed_report': 'Please enter a password to analyze.'
            }
        
        results = {
            'length': len(password),
            'has_lowercase': bool(re.search(r'[a-z]', password)),
            'has_uppercase': bool(re.search(r'[A-Z]', password)),
            'has_digits': bool(re.search(r'\d', password)),
            'has_special': bool(re.search(r'[^a-zA-Z0-9]', password)),
            'is_common': password.lower() in self.common_passwords,
            'has_patterns': self.check_patterns(password),
            'entropy': self.calculate_entropy(password),
            'charset_size': self.calculate_charset_size(password),
            'crack_time': None
        }
        
        # Calculate score
        score = self.calculate_score(password, results)
        results['score'] = score
        
        # Determine strength level
        strength = self.determine_strength(score)
        results['strength'] = strength
        
        # Calculate estimated crack time
        results['crack_time'] = self.estimate_crack_time(password, results)
        
        # Generate detailed report
        report = self.generate_report(password, results)
        results['detailed_report'] = report
        
        return results
    
    def calculate_score(self, password, results):
        """Calculate overall password score (0-100)"""
        score = 0
        
        # Length scoring (0-30 points)
        length = results['length']
        if length >= 16:
            score += 30
        elif length >= 12:
            score += 25
        elif length >= 8:
            score += 15
        elif length >= 6:
            score += 5
        
        # Character diversity (0-40 points)
        diversity = 0
        if results['has_lowercase']:
            diversity += 10
        if results['has_uppercase']:
            diversity += 10
        if results['has_digits']:
            diversity += 10
        if results['has_special']:
            diversity += 10
        score += diversity
        
        # Entropy bonus (0-20 points)
        entropy = results['entropy']
        if entropy >= 80:
            score += 20
        elif entropy >= 60:
            score += 15
        elif entropy >= 40:
            score += 10
        elif entropy >= 20:
            score += 5
        
        # Penalties
        if results['is_common']:
            score -= 50
        
        for pattern_type, found in results['has_patterns'].items():
            if found:
                score -= 10
        
        # Ensure score is within bounds
        return max(0, min(100, score))
    
    def determine_strength(self, score):
        """Determine password strength level"""
        if score >= 90:
            return "Very Strong"
        elif score >= 70:
            return "Strong"
        elif score >= 50:
            return "Medium"
        elif score >= 30:
            return "Weak"
        else:
            return "Very Weak"
    
    def check_patterns(self, password):
        """Check for common patterns"""
        found_patterns = {}
        
        for pattern_name, pattern_regex in self.patterns.items():
            found_patterns[pattern_name] = bool(re.search(pattern_regex, password.lower()))
        
        return found_patterns
    
    def calculate_entropy(self, password):
        """Calculate Shannon entropy"""
        if not password:
            return 0
        
        # Count character frequencies
        counter = Counter(password)
        length = len(password)
        
        # Calculate entropy
        entropy = 0
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        # Scale entropy to password length
        return entropy * length
    
    def calculate_charset_size(self, password):
        """Calculate character set size"""
        charset_size = 0
        
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            charset_size += 32  # Common special characters
        
        return charset_size
    
    def estimate_crack_time(self, password, results):
        """Estimate time to crack password"""
        # Assumptions:
        # - Attacker can try 10 billion passwords per second (GPU cluster)
        # - This is a simplified calculation
        
        charset_size = results['charset_size']
        length = results['length']
        
        if charset_size == 0:
            return "Instant"
        
        # Total possible combinations
        combinations = charset_size ** length
        
        # Attempts per second
        attempts_per_second = 10_000_000_000
        
        # Time in seconds
        seconds = combinations / (2 * attempts_per_second)  # Divide by 2 for average
        
        return self.format_time(seconds)
    
    def format_time(self, seconds):
        """Format seconds into human-readable time"""
        if seconds < 1:
            return "Less than 1 second"
        elif seconds < 60:
            return f"{seconds:.0f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.0f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.0f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.0f} days"
        elif seconds < 3153600000:
            return f"{seconds/31536000:.0f} years"
        else:
            return f"{seconds/31536000:.2e} years"
    
    def generate_report(self, password, results):
        """Generate detailed analysis report"""
        report = []
        report.append("=" * 60)
        report.append("PASSWORD STRENGTH ANALYSIS")
        report.append("=" * 60)
        report.append("")
        
        # Overall assessment
        report.append(f"Overall Strength: {results['strength']}")
        report.append(f"Security Score: {results['score']}/100")
        report.append(f"Estimated Crack Time: {results['crack_time']}")
        report.append("")
        
        # Character analysis
        report.append("-" * 60)
        report.append("CHARACTER ANALYSIS")
        report.append("-" * 60)
        report.append(f"Length: {results['length']} characters")
        report.append(f"Character Set Size: {results['charset_size']}")
        report.append(f"Entropy: {results['entropy']:.2f} bits")
        report.append("")
        
        # Character types
        report.append("Character Types:")
        report.append(f"  ✓ Lowercase letters: {'Yes' if results['has_lowercase'] else 'No'}")
        report.append(f"  ✓ Uppercase letters: {'Yes' if results['has_uppercase'] else 'No'}")
        report.append(f"  ✓ Digits: {'Yes' if results['has_digits'] else 'No'}")
        report.append(f"  ✓ Special characters: {'Yes' if results['has_special'] else 'No'}")
        report.append("")
        
        # Security issues
        report.append("-" * 60)
        report.append("SECURITY ISSUES")
        report.append("-" * 60)
        
        issues = []
        
        if results['is_common']:
            issues.append("⚠️  Password is in the common passwords list!")
        
        if results['length'] < 8:
            issues.append("⚠️  Password is too short (minimum 8 characters recommended)")
        
        if not results['has_lowercase']:
            issues.append("⚠️  Missing lowercase letters")
        
        if not results['has_uppercase']:
            issues.append("⚠️  Missing uppercase letters")
        
        if not results['has_digits']:
            issues.append("⚠️  Missing numbers")
        
        if not results['has_special']:
            issues.append("⚠️  Missing special characters")
        
        for pattern_type, found in results['has_patterns'].items():
            if found:
                issues.append(f"⚠️  Contains {pattern_type} pattern")
        
        if issues:
            for issue in issues:
                report.append(issue)
        else:
            report.append("✓ No major security issues detected")
        
        report.append("")
        
        # Recommendations
        report.append("-" * 60)
        report.append("RECOMMENDATIONS")
        report.append("-" * 60)
        
        recommendations = []
        
        if results['score'] < 70:
            recommendations.append("• Use at least 12 characters (16+ recommended)")
            recommendations.append("• Mix uppercase and lowercase letters")
            recommendations.append("• Include numbers and special characters")
            recommendations.append("• Avoid common words and patterns")
            recommendations.append("• Don't use personal information")
            recommendations.append("• Use a unique password for each account")
            recommendations.append("• Consider using a password manager")
        else:
            recommendations.append("✓ Your password is strong!")
            recommendations.append("• Keep it confidential")
            recommendations.append("• Change it periodically")
            recommendations.append("• Enable two-factor authentication")
        
        for rec in recommendations:
            report.append(rec)
        
        report.append("")
        report.append("=" * 60)
        
        return "\n".join(report)
    
    def generate_strong_password(self, length=16):
        """Generate a strong random password"""
        import random
        
        # Character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        
        # Ensure at least one of each type
        password = [
            random.choice(lowercase),
            random.choice(uppercase),
            random.choice(digits),
            random.choice(special)
        ]
        
        # Fill remaining length
        all_chars = lowercase + uppercase + digits + special
        password.extend(random.choice(all_chars) for _ in range(length - 4))
        
        # Shuffle
        random.shuffle(password)
        
        return ''.join(password)


def test_passwords():
    """Test password checker with various passwords"""
    checker = PasswordChecker()
    
    test_cases = [
        "password",
        "Password1",
        "P@ssw0rd",
        "MyS3cur3P@ssw0rd!",
        "Tr0ub4dor&3",
        "correcthorsebatterystaple",
        "aB3$fG7!kL9@nM2",
        "123456",
        "qwerty123",
    ]
    
    for password in test_cases:
        print(f"\n{'='*70}")
        print(f"Testing password: {password}")
        print('='*70)
        result = checker.analyze(password)
        print(result['detailed_report'])
        input("\nPress Enter to continue...")


if __name__ == "__main__":
    print("🔐 Password Strength Checker")
    print("\n1. Interactive Mode")
    print("2. Test Mode")
    
    choice = input("\nSelect mode (1 or 2): ")
    
    if choice == "1":
        checker = PasswordChecker()
        while True:
            password = input("\nEnter password to check (or 'quit' to exit): ")
            if password.lower() == 'quit':
                break
            
            result = checker.analyze(password)
            print(result['detailed_report'])
    elif choice == "2":
        test_passwords()
    else:
        print("Invalid choice")
