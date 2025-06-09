import re
import os
import json
import getpass
from datetime import datetime
from typing import Dict, List, Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Common passwords to check against
COMMON_PASSWORDS = [
    'password', '123456', '123456789', '12345678', '12345', '1234567', '123123', 'qwerty', 'abc123', 'password1',
    'admin', 'welcome', 'letmein', 'monkey', 'dragon', 'baseball', 'football', 'iloveyou', 'starwars', 'sunshine',
    'princess', 'qwertyuiop', 'solo', 'passw0rd', 'master', '654321', 'superman', '1q2w3e4r', '111111', '1234',
    '000000', 'zaq12wsx', 'qazwsx', 'asdfgh', 'zxcvbnm', '1qaz2wsx', 'qwerty123', '1q2w3e', 'qwe123', '1qazxsw2',
    'password123', 'welcome1', 'admin123', 'letmein123', 'test', 'test123', 'user', 'user123', 'root', 'root123',
    'love', 'loveme', 'secret', 'trustno1', 'whatever', 'freedom', 'hello', 'pokemon', 'batman', 'zaq1xsw2',
    'michael', 'jordan', 'shadow', 'killer', 'hannah', 'ashley', 'bailey', 'q1w2e3r4', 'charlie', 'donald',
    'qwerty1', 'qwerty12', 'qwerty1234', 'qwerty12345', 'qwerty123456', '1g2w3e4r', '1q2w3e4r5t', '123qwe',
    '1q2w3e', '1q2w3e4r', '1q2w3e4r5t6y', '123abc', 'abc123456', 'pass', 'pass123', 'passw0rd', 'p@ssw0rd',
    'p@ssword', 'p@ss', 'p@ss123', 'p@ssword123', 'admin1', 'admin12', 'admin1234', 'admin12345', 'admin123456',
    'administrator', 'administrator123', 'administrator1', 'administrator12', 'administrator1234', 'administrator12345',
    'administrator123456', 'q1w2e3', 'q1w2e3r4', 'q1w2e3r4t5', 'asdf', 'asdf1234', 'asdfghjkl', 'zxcvbn', 'zxcvbnm',
    'zaq12wsx', 'zaq1xsw2', 'zaq12wsxcde3', 'zaq1xsw2cde3', 'zaq12wsx3edc', 'zaq1xsw23edc', 'zaq12wsx3edc4rfv',
    'zaq1xsw23edc4rfv', '1qaz2wsx3edc', '1qaz2wsx3edc4rfv', '1qazxsw2', '1qazxsw23edc', '1qazxsw23edc4rfv',
    '1qaz2wsx3edc4rfv', '1qaz2wsx3edc', '1qaz2wsx', '1qaz2wsx3edc', '1qaz2wsx3edc4rfv', '1qazxsw2', '1qazxsw23edc',
    '1qazxsw23edc4rfv', '1qaz2wsx3edc4rfv', '1qaz2wsx3edc', '1qaz2wsx', '1qaz2wsx3edc', '1qaz2wsx3edc4rfv',
    'qwert', 'qwerty', 'qwertyu', 'qwertyui', 'qwertyuiop', 'asdfg', 'asdfgh', 'asdfghj', 'asdfghjk', 'asdfghjkl',
    'zxcvb', 'zxcvbn', 'zxcvbnm', 'poiuy', 'poiuyt', 'poiuytr', 'poiuytre', 'poiuytrew', 'poiuytrewq',
]

class SecurityError(Exception):
    """Custom exception for security-related errors."""
    pass

class PasswordUtils:
    def __init__(self):
        self._failed_attempts: Dict[str, tuple] = {}
        self.backend = default_backend()

    def check_password_strength(self, password: str) -> dict:
        """Check password strength and return detailed analysis as a dict."""
        criteria = {
            'length': len(password) >= 12,
            'uppercase': bool(re.search(r'[A-Z]', password)),
            'lowercase': bool(re.search(r'[a-z]', password)),
            'digit': bool(re.search(r'\d', password)),
            'special': bool(re.search(r'[^A-Za-z0-9]', password)),
            'no_common': not any(word in password.lower() for word in COMMON_PASSWORDS),
            'no_repetition': not bool(re.search(r'(.)\1{2,}', password))
        }
        score = sum(criteria.values())
        criteria['score'] = score
        return criteria

    def password_strength_checker(self, password: str) -> str:
        """Return a detailed, user-friendly string explaining password strength."""
        criteria = self.check_password_strength(password)
        status = "Strong" if criteria['score'] >= 6 else "Medium" if criteria['score'] >= 4 else "Weak"
        output = [f"Password Strength: {status}"]
        output.append("")
        output.append("Criteria:")
        output.append(f"  {'✓' if criteria['length'] else '✗'} At least 12 characters")
        output.append(f"  {'✓' if criteria['uppercase'] else '✗'} Contains uppercase letters")
        output.append(f"  {'✓' if criteria['lowercase'] else '✗'} Contains lowercase letters")
        output.append(f"  {'✓' if criteria['digit'] else '✗'} Contains numbers")
        output.append(f"  {'✓' if criteria['special'] else '✗'} Contains special characters")
        output.append(f"  {'✓' if criteria['no_common'] else '✗'} Not a common password")
        output.append(f"  {'✓' if criteria['no_repetition'] else '✗'} No character repetition (3+ in a row)")
        output.append("")
        output.append(f"Score: {criteria['score']} / 7")
        if status == "Strong":
            output.append("Great! Your password is strong and meets all recommended criteria.")
        elif status == "Medium":
            output.append("Your password is decent, but could be improved. Try to meet all criteria for best security.")
        else:
            output.append("Warning: Your password is weak. Consider using a longer, more complex password.")
        return "\n".join(output)

    def _hash_password(self, password: str, salt: bytes) -> bytes:
        """Hash a password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(password.encode())

    def check_rate_limit(self, master_password: str) -> bool:
        """Check if too many failed attempts."""
        if master_password in self._failed_attempts:
            attempts, timestamp = self._failed_attempts[master_password]
            if attempts >= 5 and (datetime.now() - timestamp).seconds < 300:
                raise SecurityError("Too many failed attempts. Please wait 5 minutes.")
        return True

    def record_failed_attempt(self, master_password: str) -> None:
        """Record a failed attempt."""
        if master_password not in self._failed_attempts:
            self._failed_attempts[master_password] = (1, datetime.now())
        else:
            attempts, _ = self._failed_attempts[master_password]
            self._failed_attempts[master_password] = (attempts + 1, datetime.now())

    def validate_vault_input(self, label: str, password: str) -> None:
        """Validate vault input parameters."""
        if not label or len(label) < 3:
            raise ValueError("Label must be at least 3 characters long.")
        
        if not password:
            raise ValueError("Password cannot be empty.")
        
        strength = self.check_password_strength(password)
        if strength['score'] < 3:
            raise ValueError("Password is too weak.")

    def get_secure_input(self, prompt: str) -> str:
        """Get password input without displaying it."""
        return getpass.getpass(prompt)

    def format_password_strength(self, strength: dict) -> str:
        """Format password strength analysis for display."""
        status = "Strong" if strength['score'] >= 5 else "Medium" if strength['score'] >= 3 else "Weak"
        details = []
        
        if strength['length']:
            details.append("✓ Length (12+ characters)")
        if strength['uppercase']:
            details.append("✓ Uppercase letters")
        if strength['lowercase']:
            details.append("✓ Lowercase letters")
        if strength['digit']:
            details.append("✓ Numbers")
        if strength['special']:
            details.append("✓ Special characters")
        if strength['no_common']:
            details.append("✓ Not a common password")
        if strength['no_repetition']:
            details.append("✓ No character repetition")
            
        return f"Password Strength: {status}\n" + "\n".join(details) 