import unittest
from crypto_toolkit import CryptoKit
import os
from unittest.mock import patch

class TestCryptoKit(unittest.TestCase):
    def setUp(self) -> None:
        """Set up test environment before each test"""
        self.crypto = CryptoKit()
        self.test_message = "Hello, World!"
        self.test_file = "test_file.txt"
        
        # Create test file
        with open(self.test_file, 'w') as f:
            f.write(self.test_message)

    def tearDown(self):
        """Clean up after each test"""
        # Remove test files
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
        if os.path.exists(self.test_file + '.encrypted'):
            os.remove(self.test_file + '.encrypted')
        if os.path.exists(os.path.join('decrypted', self.test_file)):
            os.remove(os.path.join('decrypted', self.test_file))

    def test_aes_encryption_decryption(self):
        """Test AES encryption and decryption"""
        # Generate key
        key = self.crypto.generate_aes_key()
        
        # Encrypt
        encrypted = self.crypto.aes_encrypt(self.test_message.encode(), key)
        self.assertNotEqual(encrypted, self.test_message.encode())
        
        # Decrypt
        decrypted = self.crypto.aes_decrypt(encrypted, key)
        self.assertEqual(decrypted.decode(), self.test_message)

    def test_rsa_encryption_decryption(self):
        """Test RSA encryption and decryption"""
        # Generate keys
        key_id, private_key, public_key = self.crypto.generate_rsa_keys()
        
        # Encrypt
        encrypted = self.crypto.rsa_encrypt(self.test_message.encode(), public_key)
        self.assertNotEqual(encrypted, self.test_message.encode())
        
        # Decrypt
        decrypted = self.crypto.rsa_decrypt(encrypted, private_key)
        self.assertEqual(decrypted.decode(), self.test_message)

    def test_digital_signature(self):
        """Test digital signature creation and verification"""
        # Generate keys
        key_id, private_key, public_key = self.crypto.generate_rsa_keys()
        
        # Sign message
        signature = self.crypto.sign_message(self.test_message, private_key)
        self.assertIsNotNone(signature)
        
        # Verify signature
        is_valid = self.crypto.verify_signature(self.test_message, signature, public_key)
        self.assertTrue(is_valid)
        
        # Test invalid signature
        is_valid = self.crypto.verify_signature("Modified message", signature, public_key)
        self.assertFalse(is_valid)

    def test_file_encryption_decryption(self):
        """Test file encryption and decryption"""
        # Use a string password instead of raw key
        password = "test_password"
        
        # Encrypt file
        output_path = self.crypto.encrypt_file(self.test_file, password)
        self.assertTrue(os.path.exists(output_path))
        
        # Decrypt file
        decrypted_path = self.crypto.decrypt_file(output_path, password)
        self.assertTrue(os.path.exists(decrypted_path))
        
        # Verify content
        with open(decrypted_path, 'r') as f:
            decrypted_content = f.read()
        self.assertEqual(decrypted_content, self.test_message)

    def test_key_management(self):
        """Test key management functions"""
        # Generate and save RSA keys
        key_id, private_key, public_key = self.crypto.generate_rsa_keys()
        self.assertIsNotNone(key_id)
        
        # Get saved keys
        keys = self.crypto.get_rsa_keys(key_id)
        self.assertIsNotNone(keys)
        self.assertIn('private', keys)
        self.assertIn('public', keys)

    @patch('crypto_toolkit.os')
    def test_generate_aes_key(self, mock_os):
        # Test AES key generation
        key = self.crypto.generate_aes_key()
        # ... assertions ...

    def test_generate_rsa_keys(self):
        # Test RSA key generation
        keys = self.crypto.generate_rsa_keys()
        # ... assertions ...

    def test_hash_message(self):
        # Test hashing a message
        digest = self.crypto.hash_message('test')
        # ... assertions ...

    def test_hmac_message(self):
        # Test HMAC
        hmac_val = self.crypto.hmac_message('test', b'key')
        # ... assertions ...

    def test_vault_operations(self):
        # Test password vault add/get/list/update/delete
        self.crypto.add_password_to_vault('label', 'password', 'master')
        pw = self.crypto.get_password_from_vault('label', 'master')
        # ... assertions ...
        self.crypto.update_password_in_vault('label', 'newpw', 'master')
        # ... assertions ...
        self.crypto.delete_password_from_vault('label', 'master')
        # ... assertions ...

if __name__ == '__main__':
    unittest.main() 