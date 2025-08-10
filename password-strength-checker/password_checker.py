#!/usr/bin/env python3
"""
Password Strength Checker CLI Tool
Evaluates password strength using regex patterns and entropy calculation
"""

import re
import math
import argparse
from typing import Dict, List, Tuple

class PasswordStrengthChecker:
    def __init__(self):
        self.criteria = {
            'length': {
                'regex': r'.{8,}',
                'weight': 2,
                'description': 'At least 8 characters'
            },
            'uppercase': {
                'regex': r'[A-Z]',
                'weight': 2,
                'description': 'Contains uppercase letters'
            },
            'lowercase': {
                'regex': r'[a-z]',
                'weight': 2,
                'description': 'Contains lowercase letters'
            },
            'digits': {
                'regex': r'\d',
                'weight': 2,
                'description': 'Contains numbers'
            },
            'special': {
                'regex': r'[!@#$%^&*(),.?":{}|<>]',
                'weight': 2,
                'description': 'Contains special characters'
            }
        }
        
    def check_criteria(self, password: str) -> Dict[str, bool]:
        """Check which criteria the password meets"""
        results = {}
        for name, rule in self.criteria.items():
            results[name] = bool(re.search(rule['regex'], password))
        return results
    
    def calculate_entropy(self, password: str) -> float:
        """Calculate password entropy in bits"""
        if not password:
            return 0.0
            
        # Character set sizes
        char_sets = {
            'lowercase': 26,
            'uppercase': 26,
            'digits': 10,
            'special': 32
        }
        
        # Determine which character sets are used
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += char_sets['lowercase']
        if re.search(r'[A-Z]', password):
            charset_size += char_sets['uppercase']
        if re.search(r'\d', password):
            charset_size += char_sets['digits']
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            charset_size += char_sets['special']
        
        # Entropy = log2(charset_size^length)
        entropy = len(password) * math.log2(charset_size) if charset_size > 0 else 0
        return entropy
    
    def check_common_patterns(self, password: str) -> List[str]:
        """Check for common weak patterns"""
        patterns = []
        
        # Common sequences
        sequences = ['123456', 'abcdef', 'qwerty', 'password', 'admin', 'letmein']
        for seq in sequences:
            if seq.lower() in password.lower():
                patterns.append(f"Contains common sequence: '{seq}'")
        
        # Repeated characters
        if re.search(r'(.)\1{2,}', password):
            patterns.append("Contains repeated characters")
            
        # Keyboard patterns
        keyboard_patterns = ['qwerty', 'asdfgh', 'zxcvbn', '1qaz2wsx']
        for pattern in keyboard_patterns:
            if pattern in password.lower():
                patterns.append(f"Contains keyboard pattern: '{pattern}'")
                
        return patterns
    
    def evaluate_strength(self, password: str) -> Dict:
        """Comprehensive password strength evaluation"""
        criteria_results = self.check_criteria(password)
        entropy = self.calculate_entropy(password)
        common_patterns = self.check_common_patterns(password)
        
        # Calculate score
        score = sum(self.criteria[name]['weight'] for name, passed in criteria_results.items() if passed)
        max_score = sum(rule['weight'] for rule in self.criteria.values())
        percentage = (score / max_score) * 100
        
        # Determine strength level
        if percentage >= 80 and entropy >= 50 and not common_patterns:
            strength = "Very Strong"
            color = "\033[92m"  # Green
        elif percentage >= 60 and entropy >= 35:
            strength = "Strong"
            color = "\033[94m"  # Blue
        elif percentage >= 40 and entropy >= 25:
            strength = "Medium"
            color = "\033[93m"  # Yellow
        elif percentage >= 20:
            strength = "Weak"
            color = "\033[91m"  # Red
        else:
            strength = "Very Weak"
            color = "\033[91m"  # Red
            
        return {
            'password': '*' * len(password),
            'strength': strength,
            'color': color,
            'score': score,
            'max_score': max_score,
            'percentage': percentage,
            'entropy': round(entropy, 2),
            'criteria': criteria_results,
            'common_patterns': common_patterns
        }

def format_output(result: Dict) -> str:
    """Format the evaluation results for display"""
    output = []
    output.append(f"\n{result['color']}Password Strength: {result['strength']}\033[0m")
    output.append(f"Score: {result['score']}/{result['max_score']} ({result['percentage']:.1f}%)")
    output.append(f"Entropy: {result['entropy']} bits")
    
    output.append("\nCriteria Check:")
    for name, passed in result['criteria'].items():
        status = "✓" if passed else "✗"
        description = PasswordStrengthChecker().criteria[name]['description']
        output.append(f"  {status} {description}")
    
    if result['common_patterns']:
        output.append("\n⚠️  Issues Found:")
        for pattern in result['common_patterns']:
            output.append(f"  - {pattern}")
    
    return "\n".join(output)

def main():
    parser = argparse.ArgumentParser(description="Password Strength Checker CLI")
    parser.add_argument("password", nargs="?", help="Password to check")
    parser.add_argument("-f", "--file", help="Check passwords from file (one per line)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    checker = PasswordStrengthChecker()
    
    if args.file:
        try:
            with open(args.file, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
            for password in passwords:
                result = checker.evaluate_strength(password)
                print(format_output(result))
                print("-" * 50)
        except FileNotFoundError:
            print(f"Error: File '{args.file}' not found")
    elif args.password:
        result = checker.evaluate_strength(args.password)
        print(format_output(result))
    else:
        # Interactive mode
        print("Password Strength Checker")
        print("Enter passwords to check (type 'quit' to exit)")
        while True:
            try:
                password = input("\nEnter password: ").strip()
                if password.lower() == 'quit':
                    break
                if password:
                    result = checker.evaluate_strength(password)
                    print(format_output(result))
            except KeyboardInterrupt:
                print("\nGoodbye!")
                break

if __name__ == "__main__":
    main()
