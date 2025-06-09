import unittest
from unittest.mock import patch, MagicMock
from password_utils import PasswordUtils, SecurityError

class TestPasswordUtils(unittest.TestCase):
    def setUp(self):
        self.password_utils = PasswordUtils()

    def test_password_strength(self):
        # Test strong password
        strong_pw = "P@ssw0rd123!"
        strength = self.password_utils.check_password_strength(strong_pw)
        self.assertGreaterEqual(strength['score'], 5)
        
        # Test weak password
        weak_pw = "password"
        strength = self.password_utils.check_password_strength(weak_pw)
        self.assertLess(strength['score'], 3)

    def test_rate_limiting(self):
        # Test rate limiting
        master_pw = "test123"
        for _ in range(4):
            self.password_utils.record_failed_attempt(master_pw)
        self.assertTrue(self.password_utils.check_rate_limit(master_pw))
        
        # Test exceeding rate limit
        self.password_utils.record_failed_attempt(master_pw)
        with self.assertRaises(SecurityError):
            self.password_utils.check_rate_limit(master_pw)

    def test_vault_input_validation(self):
        # Test valid input
        self.password_utils.validate_vault_input("valid_label", "P@ssw0rd123!")
        
        # Test invalid label
        with self.assertRaises(ValueError):
            self.password_utils.validate_vault_input("ab", "P@ssw0rd123!")
        
        # Test invalid password
        with self.assertRaises(ValueError):
            self.password_utils.validate_vault_input("valid_label", "weak")

    def test_secure_input(self):
        # Test secure input
        with patch('getpass.getpass', return_value="test123"):
            result = self.password_utils.get_secure_input("Enter password: ")
            self.assertEqual(result, "test123")

    def test_password_strength_formatting(self):
        # Test strength formatting
        strength = {
            'score': 5,
            'length': True,
            'uppercase': True,
            'lowercase': True,
            'digit': True,
            'special': True,
            'no_common': True,
            'no_repetition': False
        }
        formatted = self.password_utils.format_password_strength(strength)
        self.assertIn("Strong", formatted)
        self.assertIn("✓ Length", formatted)
        self.assertIn("✓ Uppercase", formatted)

if __name__ == '__main__':
    unittest.main() 