import os
import base64
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding, ec, ed25519
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from colorama import init, Fore, Style, Back
import json
from pathlib import Path
from cryptography.hazmat.primitives import serialization
import time
from PIL import Image
import hmac
from tqdm import tqdm
import re
import wave
import cv2

# Initialize colorama for colors
init()

# Add this near the top, after imports and before main loop
descriptions = {
    "1": "Generate a random AES key for symmetric encryption.",
    "2": "Generate a new RSA public/private key pair for encryption and digital signatures.",
    "3": "List all saved RSA keys you have generated.",
    "4": "Encrypt a text message using AES (password-based symmetric encryption).",
    "5": "Decrypt a text message that was encrypted with AES.",
    "6": "Encrypt a text message using RSA public key (asymmetric encryption).",
    "7": "Decrypt a text message using your RSA private key.",
    "8": "Create a digital signature for a message (proves authorship and integrity).",
    "9": "Verify a digital signature for a message (checks authenticity and integrity).",
    "10": "Create a digital signature for a file.",
    "11": "Verify a digital signature for a file.",
    "12": "View details about a signature file (size, encoding, etc.).",
    "13": "Encrypt a file using AES (password-based symmetric encryption).",
    "14": "Decrypt a file that was encrypted with AES.",
    "16": "Create a hash (fingerprint) of a message using a hash algorithm.",
    "17": "Create a message authentication code (HMAC) for a message and key.",
    "18": "Hide a secret message inside an image (steganography).",
    "19": "Extract a hidden message from an image (steganography).",
    "20": "Exit the toolkit.",
    "21": "Generate an ECDSA (Elliptic Curve) key pair for digital signatures.",
    "22": "Generate an Ed25519 key pair for digital signatures.",
    "23": "Sign a message using ECDSA.",
    "24": "Verify an ECDSA signature.",
    "25": "Sign a message using Ed25519.",
    "26": "Verify an Ed25519 signature.",
    "27": "Encrypt a file using hybrid encryption (AES for data, RSA for key).",
    "28": "Decrypt a file encrypted with hybrid encryption (AES+RSA).",
    "29": "Export a key (private or public) to a file. Private keys can be password-protected.",
    "30": "Import a key (private or public) from a file. Password required if encrypted.",
    "31": "Add a password to the encrypted password vault.",
    "32": "Retrieve a password from the encrypted password vault.",
    "33": "List all password labels in the encrypted password vault.",
    "34": "Update a password in the encrypted password vault.",
    "35": "Delete a password from the encrypted password vault."
}

# Main menu groupings and submenus for the CLI
main_menu_groups = [
    ("1", "Key Management"),
    ("2", "Text Operations"),
    ("3", "Digital Signatures"),
    ("4", "File Operations"),
    ("5", "Hash & HMAC"),
    ("6", "Steganography"),
    ("7", "Elliptic Curve & Ed25519"),
    ("8", "Hybrid Encryption"),
    ("9", "Key Management (Import/Export)"),
    ("10", "Password Manager"),
    ("11", "Other"),
]

sub_menus = {
    "1": [("1", "Generate AES Key"), ("2", "Generate RSA Keys"), ("3", "Generate ECDSA Keys"), ("4", "Generate Ed25519 Keys"), ("5", "List Saved Keys"), ("6", "Export Key to File"), ("7", "Import Key from File")],
    "2": [("1", "Encrypt Text (AES)"), ("2", "Decrypt Text (AES)"), ("3", "Encrypt Text (RSA)"), ("4", "Decrypt Text (RSA)")],
    "3": [("1", "Sign Message"), ("2", "Verify Signature"), ("3", "Sign File"), ("4", "Verify File Signature"), ("5", "View Signature Details")],
    "4": [("1", "Encrypt File (AES)"), ("2", "Decrypt File (AES)")],
    "5": [("1", "Hash Message"), ("2", "HMAC Message")],
    "6": [("1", "Hide Message in Image"), ("2", "Reveal Message from Image"), ("3", "Hide Message in Audio (WAV)"), ("4", "Reveal Message from Audio (WAV)"), ("5", "Hide Message in Video"), ("6", "Reveal Message from Video"), ("0", "Back"), ("H", "Help / About")],
    "7": [("1", "Generate ECDSA Keys"), ("2", "Generate Ed25519 Keys"), ("3", "Sign Message (ECDSA)"), ("4", "Verify Signature (ECDSA)"), ("5", "Sign Message (Ed25519)"), ("6", "Verify Signature (Ed25519)")],
    "8": [("1", "Hybrid Encrypt File (AES+RSA)"), ("2", "Hybrid Decrypt File (AES+RSA)")],
    "9": [("1", "Export Key to File"), ("2", "Import Key from File")],
    "10": [("1", "Add Password to Vault"), ("2", "Retrieve Password from Vault"), ("3", "List Password Labels in Vault"), ("4", "Update Password in Vault"), ("5", "Delete Password from Vault")],
    "11": [("1", "Exit")],
}

def clear_screen():
    """Clear the screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    """Show the cool header"""
    clear_screen()
    print(f"\n{Fore.CYAN}{'='*50}")
    print(f"{Fore.CYAN}║{Style.BRIGHT}              CRYPTO TOOLKIT v1.0              {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'='*50}")
    print(f"{Fore.CYAN}║{Style.BRIGHT}                    by YNK                     {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")

def print_success(message):
    """Show a success message with a checkmark"""
    print(f"\n{Fore.GREEN}✓ {message}{Style.RESET_ALL}")

def print_error(message):
    """Show an error message with an X"""
    print(f"\n{Fore.RED}✗ {message}{Style.RESET_ALL}")

def print_info(message):
    """Show an info message with an i"""
    print(f"\n{Fore.YELLOW}ℹ {message}{Style.RESET_ALL}")

def print_menu():
    """Show the main menu with all options"""
    print(f"\n{Fore.CYAN}Main Menu:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'─'*50}")
    print(f"\n{Fore.YELLOW}0. Help / About{Style.RESET_ALL}")
    
    # Key stuff
    print(f"\n{Fore.YELLOW}Key Management:{Style.RESET_ALL}")
    print(f"{Fore.WHITE}1. Generate AES Key")
    print(f"2. Generate RSA Keys")
    print(f"3. List Saved Keys{Style.RESET_ALL}")
    
    # Text stuff
    print(f"\n{Fore.YELLOW}Text Operations:{Style.RESET_ALL}")
    print(f"{Fore.WHITE}4. Encrypt Text (AES)")
    print(f"5. Decrypt Text (AES)")
    print(f"6. Encrypt Text (RSA)")
    print(f"7. Decrypt Text (RSA){Style.RESET_ALL}")
    
    # Signature stuff
    print(f"\n{Fore.YELLOW}Digital Signatures:{Style.RESET_ALL}")
    print(f"{Fore.WHITE}8. Sign Message")
    print(f"9. Verify Signature")
    print(f"10. Sign File")
    print(f"11. Verify File Signature")
    print(f"12. View Signature Details{Style.RESET_ALL}")
    
    # File stuff
    print(f"\n{Fore.YELLOW}File Operations:{Style.RESET_ALL}")
    print(f"{Fore.WHITE}13. Encrypt File (AES)")
    print(f"14. Decrypt File (AES){Style.RESET_ALL}")
    
    # Hash & HMAC
    print(f"\n{Fore.YELLOW}Hash & HMAC:{Style.RESET_ALL}")
    print(f"{Fore.WHITE}16. Hash Message")
    print(f"17. HMAC Message{Style.RESET_ALL}")
    
    # Steganography
    print(f"\n{Fore.YELLOW}Steganography:{Style.RESET_ALL}")
    print(f"{Fore.WHITE}18. Hide Message in Image")
    print(f"19. Reveal Message from Image")
    print(f"20. Hide Message in Audio (WAV)")
    print(f"21. Reveal Message from Audio (WAV)")
    print(f"22. Hide Message in Video")
    print(f"23. Reveal Message from Video{Style.RESET_ALL}")
    
    # Elliptic Curve & Ed25519
    print(f"\n{Fore.YELLOW}Elliptic Curve & Ed25519:{Style.RESET_ALL}")
    print(f"{Fore.WHITE}24. Generate ECDSA Keys")
    print(f"25. Generate Ed25519 Keys")
    print(f"26. Sign Message (ECDSA)")
    print(f"27. Verify Signature (ECDSA)")
    print(f"28. Sign Message (Ed25519)")
    print(f"29. Verify Signature (Ed25519){Style.RESET_ALL}")
    
    # Hybrid Encryption
    print(f"\n{Fore.YELLOW}Hybrid Encryption:{Style.RESET_ALL}")
    print(f"{Fore.WHITE}30. Hybrid Encrypt File (AES+RSA)")
    print(f"31. Hybrid Decrypt File (AES+RSA){Style.RESET_ALL}")
    
    # Key Management (Import/Export)
    print(f"\n{Fore.YELLOW}Key Management (Import/Export):{Style.RESET_ALL}")
    print(f"{Fore.WHITE}32. Export Key to File")
    print(f"33. Import Key from File{Style.RESET_ALL}")
    
    # Password Manager
    print(f"\n{Fore.YELLOW}Password Manager:{Style.RESET_ALL}")
    print(f"{Fore.WHITE}34. Add Password to Vault")
    print(f"35. Retrieve Password from Vault")
    print(f"36. List Password Labels in Vault{Style.RESET_ALL}")
    print(f"{Fore.WHITE}37. Update Password in Vault")
    print(f"38. Delete Password from Vault{Style.RESET_ALL}")
    
    # Exit
    print(f"\n{Fore.YELLOW}Other:{Style.RESET_ALL}")
    print(f"{Fore.WHITE}20. Exit{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}{'─'*50}{Style.RESET_ALL}")

def get_input(prompt, required=True):
    """Get user input and make sure it's not empty"""
    while True:
        value = input(f"\n{Fore.GREEN}{prompt}{Style.RESET_ALL}").strip()
        if not required or value:
            return value
        print_error("This field is required!")

def print_loading(message, duration=1):
    """Show a loading animation"""
    print(f"\n{Fore.YELLOW}{message}", end='', flush=True)
    for _ in range(3):
        time.sleep(duration/3)
        print(".", end='', flush=True)
    print(f"{Style.RESET_ALL}")

def print_help():
    """Show help/about and explanations for each function and navigation"""
    print(f"\n{Fore.CYAN}{'='*50}")
    print(f"{Fore.CYAN}CRYPTO TOOLKIT - HELP / ABOUT{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    print(f"\nThis toolkit provides practical cryptography tools for learning and real-world use.")
    print(f"It covers encryption, digital signatures, hashing, HMAC, steganography, and password management.\n")
    print(f"{Fore.YELLOW}Navigation:{Style.RESET_ALL}")
    print(f"  - Enter the number of a menu option to select it.")
    print(f"  - In any submenu, enter '0' to go back to the main menu.")
    print(f"  - In any submenu, enter 'H' to view this help/about screen.")
    print(f"  - In the main menu, enter 'Q' to exit the toolkit.")
    print(f"\n{Fore.YELLOW}Menu Options Explained:{Style.RESET_ALL}")
    print(f"  1. Key Management         - Generate, list, export, and import cryptographic keys.")
    print(f"  2. Text Operations        - Encrypt and decrypt text using AES or RSA.")
    print(f"  3. Digital Signatures     - Sign and verify messages and files using RSA, ECDSA, or Ed25519.")
    print(f"  4. File Operations        - Encrypt and decrypt files using AES.")
    print(f"  5. Hash & HMAC            - Create hashes and HMACs for messages.")
    print(f"  6. Steganography          - Hide or reveal messages in images.")
    print(f"  7. Elliptic Curve & Ed25519- Generate and use ECDSA/Ed25519 keys for signatures.")
    print(f"  8. Hybrid Encryption      - Encrypt files using a combination of AES and RSA.")
    print(f"  9. Key Management (Import/Export) - Export or import keys to/from files.")
    print(f" 10. Password Manager       - Store, retrieve, update, and delete passwords in a secure vault.")
    print(f" 11. Other                  - Exit the toolkit.\n")
    print(f"{Fore.YELLOW}Cryptography Concepts:{Style.RESET_ALL}")
    print("- Encryption: Protects data by making it unreadable without a key.")
    print("- Digital Signatures: Prove who created a message/file and that it wasn't changed.")
    print("- Hashing: Creates a unique fingerprint for data, used for integrity checks.")
    print("- HMAC: Combines a secret key and a hash to verify both integrity and authenticity.")
    print("- Steganography: Hides secret messages inside images.")
    print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")
    input("Press Enter to return to the previous menu...")

def validate_file_path(path, must_exist=True, must_not_be_dir=True):
    if must_exist and not os.path.exists(path):
        raise ValueError("File not found. Please check the path and try again.")
    if must_not_be_dir and os.path.isdir(path):
        raise ValueError("Path is a directory. Please provide a file path.")
    return os.path.abspath(path)

def validate_key_size(key_size, allowed_sizes):
    if key_size not in allowed_sizes:
        raise ValueError(f"Invalid key size. Allowed sizes: {allowed_sizes}")
    return key_size

def validate_algorithm_name(name, allowed):
    if name.lower() not in allowed:
        raise ValueError(f"Unsupported algorithm. Allowed: {', '.join(allowed)}")
    return name.lower()

# Supported algorithms for validation
HASH_ALGOS = ['sha256', 'sha512', 'sha3_256', 'sha3_512', 'blake2b']
RSA_KEY_SIZES = [2048, 3072, 4096]
AES_KEY_SIZES = [128, 192, 256]

def check_password_strength(password):
    length = len(password) >= 8
    upper = re.search(r'[A-Z]', password)
    lower = re.search(r'[a-z]', password)
    digit = re.search(r'\d', password)
    special = re.search(r'[^A-Za-z0-9]', password)
    score = sum([length, bool(upper), bool(lower), bool(digit), bool(special)])
    if score == 5:
        return 'Strong'
    elif score >= 3:
        return 'Medium'
    else:
        return 'Weak'

class CryptoKit:
    def __init__(self):
        """Set up the crypto toolkit"""
        self.backend = default_backend()
        self.rsa_keys = {}  # Keep track of RSA keys
        
        # Make a folder for our stuff
        self.data_dir = os.path.join(os.path.expanduser("~"), ".crypto_toolkit")
        os.makedirs(self.data_dir, exist_ok=True)
        
        self.key_file = os.path.join(self.data_dir, "crypto_keys.json")
        self.load_keys()

    def load_keys(self):
        """Load saved keys from file"""
        try:
            if os.path.exists(self.key_file):
                with open(self.key_file, 'r') as f:
                    self.rsa_keys = json.load(f)
        except Exception as e:
            print(f"Warning: Could not load saved keys: {e}")
            self.rsa_keys = {}

    def save_keys(self):
        """Save keys to file"""
        try:
            os.makedirs(os.path.dirname(self.key_file), exist_ok=True)
            with open(self.key_file, 'w') as f:
                json.dump(self.rsa_keys, f)
            os.chmod(self.key_file, 0o600)
        except Exception as e:
            print(f"Warning: Could not save keys: {e}")

    def generate_aes_key(self, key_size=256):
        """Make a random AES key"""
        return os.urandom(key_size // 8)

    def generate_rsa_keys(self, key_size=2048):
        """Make a pair of RSA keys"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=self.backend
        )
        public_key = private_key.public_key()
        
        # Save the keys with a unique ID
        key_id = base64.b64encode(os.urandom(8)).decode()
        self.rsa_keys[key_id] = {
            'private': private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode(),
            'public': public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        }
        self.save_keys()
        return key_id, private_key, public_key

    def get_rsa_keys(self, key_id):
        """Get saved RSA keys"""
        if key_id not in self.rsa_keys:
            return None
        keys = self.rsa_keys[key_id]
        private_key = serialization.load_pem_private_key(
            keys['private'].encode(),
            password=None,
            backend=self.backend
        )
        public_key = serialization.load_pem_public_key(
            keys['public'].encode(),
            backend=self.backend
        )
        return {'private': private_key, 'public': public_key}

    def aes_encrypt(self, data, key):
        """Encrypt stuff with AES"""
        if not data:
            raise ValueError("Data cannot be empty")
            
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        # Pad the data
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # Encrypt it
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        return iv + encrypted_data

    def aes_decrypt(self, encrypted_data, key):
        """Decrypt stuff with AES"""
        iv = encrypted_data[:16]
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        
        # Decrypt it
        padded_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        return data

    def rsa_encrypt(self, data, public_key):
        """Encrypt stuff with RSA"""
        if not data:
            raise ValueError("Data cannot be empty")
            
        encrypted = public_key.encrypt(
            data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted

    def rsa_decrypt(self, encrypted_data, private_key):
        """Decrypt stuff with RSA"""
        decrypted = private_key.decrypt(
            encrypted_data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted

    def derive_key_from_password(self, password, salt=None):
        """Make a key from a password"""
        if not password:
            raise ValueError("Password cannot be empty")
            
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        
        key = kdf.derive(password.encode())
        return key, salt

    def encrypt_file(self, file_path, password):
        """Encrypt a file with AES"""
        file_path = os.path.abspath(file_path)
        
        if not os.path.exists(file_path):
            raise ValueError("File does not exist")
            
        if os.path.isdir(file_path):
            raise ValueError("Please specify a file, not a directory")
            
        try:
            # Read the file
            with open(file_path, 'rb') as f:
                data = f.read()
                
            # Make a key from the password
            key, salt = self.derive_key_from_password(password)
            
            # Encrypt it
            encrypted_data = self.aes_encrypt(data, key)
            
            # Save it
            output_dir = os.path.join(os.path.dirname(file_path), "encrypted")
            os.makedirs(output_dir, exist_ok=True)
            
            output_path = os.path.join(output_dir, f"{os.path.basename(file_path)}.encrypted")
            with open(output_path, 'wb') as f:
                f.write(salt + encrypted_data)
                
            return output_path
        except PermissionError:
            raise ValueError("Permission denied. Please check file permissions.")
        except Exception as e:
            raise ValueError(f"Error encrypting file: {str(e)}")

    def decrypt_file(self, encrypted_file_path, password):
        """Decrypt a file with AES"""
        encrypted_file_path = os.path.abspath(encrypted_file_path)
        
        if not os.path.exists(encrypted_file_path):
            raise ValueError("File does not exist")
            
        if os.path.isdir(encrypted_file_path):
            raise ValueError("Please specify a file, not a directory")
            
        try:
            # Read the encrypted file
            with open(encrypted_file_path, 'rb') as f:
                data = f.read()
                
            # Get the salt and encrypted data
            salt = data[:16]
            encrypted_data = data[16:]
            
            # Make the key
            key, _ = self.derive_key_from_password(password, salt)
            
            # Decrypt it
            decrypted_data = self.aes_decrypt(encrypted_data, key)
            
            # Save it
            output_dir = os.path.join(os.path.dirname(encrypted_file_path), "decrypted")
            os.makedirs(output_dir, exist_ok=True)
            
            output_path = os.path.join(output_dir, os.path.basename(encrypted_file_path).replace('.encrypted', ''))
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
                
            return output_path
        except PermissionError:
            raise ValueError("Permission denied. Please check file permissions.")
        except Exception as e:
            raise ValueError(f"Error decrypting file: {str(e)}")

    def sign_message(self, message, private_key):
        """Sign a message with RSA"""
        if not message:
            raise ValueError("Message cannot be empty")
            
        signature = private_key.sign(
            message.encode(),
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, message, signature, public_key):
        """Check if a signature is valid"""
        try:
            public_key.verify(
                signature,
                message.encode(),
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def sign_file(self, file_path, private_key):
        """Sign a file with RSA"""
        if not os.path.exists(file_path):
            raise ValueError("File does not exist")
            
        if os.path.isdir(file_path):
            raise ValueError("Please specify a file, not a directory")
            
        try:
            # Read the file
            with open(file_path, 'rb') as f:
                data = f.read()
                
            # Sign it
            signature = private_key.sign(
                data,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Save the signature
            sig_file = file_path + '.sig'
            with open(sig_file, 'wb') as f:
                f.write(signature)
                
            return sig_file
        except Exception as e:
            raise ValueError(f"Error signing file: {str(e)}")

    def verify_file_signature(self, file_path, signature_file, public_key):
        """Check if a file signature is valid"""
        if not os.path.exists(file_path):
            raise ValueError("File does not exist")
            
        if not os.path.exists(signature_file):
            raise ValueError("Signature file does not exist")
            
        try:
            # Read the file
            with open(file_path, 'rb') as f:
                data = f.read()
                
            # Read the signature
            with open(signature_file, 'rb') as f:
                signature = f.read()
                
            # Check if it's valid
            try:
                public_key.verify(
                    signature,
                    data,
                    asym_padding.PSS(
                        mgf=asym_padding.MGF1(hashes.SHA256()),
                        salt_length=asym_padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                return True
            except Exception:
                return False
        except Exception as e:
            raise ValueError(f"Error verifying file signature: {str(e)}")

    def view_signature_details(self, signature_file):
        """Show info about a signature file"""
        if not os.path.exists(signature_file):
            raise ValueError("Signature file does not exist")
            
        try:
            # Read the signature
            with open(signature_file, 'rb') as f:
                signature = f.read()
                
            # Get file info
            file_stats = os.stat(signature_file)
            
            # Make it pretty
            details = {
                "Signature Size": f"{len(signature)} bytes",
                "File Size": f"{file_stats.st_size} bytes",
                "Created": time.ctime(file_stats.st_ctime),
                "Modified": time.ctime(file_stats.st_mtime),
                "Signature (Base64)": base64.b64encode(signature).decode(),
                "Signature (Hex)": signature.hex()
            }
            
            return details
        except Exception as e:
            raise ValueError(f"Error reading signature file: {str(e)}")

    def hash_message(self, message, algorithm='sha256'):
        """Hash a message using the specified algorithm (default: sha256)"""
        if not message:
            raise ValueError("Message cannot be empty")
        digest = hashes.Hash(getattr(hashes, algorithm.upper())(), backend=self.backend)
        digest.update(message.encode())
        return digest.finalize()

    def hmac_message(self, message, key, algorithm='sha256'):
        """Generate HMAC for a message using the specified algorithm (default: sha256)"""
        if not message or not key:
            raise ValueError("Message and key cannot be empty")
        return hmac.new(key, message.encode(), getattr(hashes, algorithm.upper())().name).digest()

    def aes_encrypt_message(self, message, password):
        backend = default_backend()
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=backend
        )
        key = kdf.derive(password.encode())
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded = padder.update(message.encode()) + padder.finalize()
        encrypted = encryptor.update(padded) + encryptor.finalize()
        return salt + iv + encrypted

    def aes_decrypt_message(self, encrypted, password):
        backend = default_backend()
        salt = encrypted[:16]
        iv = encrypted[16:32]
        ciphertext = encrypted[32:]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=backend
        )
        key = kdf.derive(password.encode())
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        return (unpadder.update(padded) + unpadder.finalize()).decode(errors='ignore')

    def steg_hide(self, image_path, message, output_path, password=None):
        """Hide a message in an image using LSB steganography"""
        if password:
            encrypted = self.aes_encrypt_message(message, password)
            # Store as base64 to keep binary safe for LSB
            message = base64.b64encode(encrypted).decode()
        img = Image.open(image_path)
        encoded = img.copy()
        width, height = img.size
        message += chr(0)  # Null-terminate
        data = ''.join([format(ord(i), '08b') for i in message])
        data_len = len(data)
        idx = 0
        for y in range(height):
            for x in range(width):
                pixel = list(img.getpixel((x, y)))
                for n in range(3):
                    if idx < data_len:
                        pixel[n] = pixel[n] & ~1 | int(data[idx])
                        idx += 1
                encoded.putpixel((x, y), tuple(pixel))
                if idx >= data_len:
                    break
            if idx >= data_len:
                break
        encoded.save(output_path)
        return output_path

    def steg_reveal(self, image_path, password=None, max_length=4096):
        """Reveal a hidden message from an image using LSB steganography, with a max length for safety"""
        img = Image.open(image_path)
        width, height = img.size
        bits = []
        char_list = []
        char = ''
        for y in range(height):
            for x in range(width):
                pixel = img.getpixel((x, y))
                for n in range(3):
                    bits.append(str(pixel[n] & 1))
                    if len(bits) == 8:
                        char = chr(int(''.join(bits), 2))
                        if char == chr(0):
                            msg = ''.join(char_list)
                            if password:
                                try:
                                    decrypted = self.aes_decrypt_message(base64.b64decode(msg), password)
                                    return decrypted
                                except Exception:
                                    return '(Wrong password or corrupted data)'
                            return msg
                        char_list.append(char)
                        if len(char_list) >= max_length:
                            return ''.join(char_list) + '... (truncated)'
                        bits = []
        if char_list:
            return ''.join(char_list) + '... (no null terminator found)'
        return '(No hidden message found or image not suitable)'

    def generate_ecdsa_keys(self):
        private_key = ec.generate_private_key(ec.SECP256R1(), self.backend)
        public_key = private_key.public_key()
        key_id = base64.b64encode(os.urandom(8)).decode()
        self.rsa_keys[key_id] = {
            'type': 'ecdsa',
            'private': private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode(),
            'public': public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        }
        self.save_keys()
        return key_id, private_key, public_key

    def generate_ed25519_keys(self):
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        key_id = base64.b64encode(os.urandom(8)).decode()
        self.rsa_keys[key_id] = {
            'type': 'ed25519',
            'private': private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode(),
            'public': public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        }
        self.save_keys()
        return key_id, private_key, public_key

    def get_any_keys(self, key_id):
        if key_id not in self.rsa_keys:
            return None
        keys = self.rsa_keys[key_id]
        key_type = keys.get('type', 'rsa')
        if key_type == 'ecdsa':
            private_key = serialization.load_pem_private_key(
                keys['private'].encode(), password=None, backend=self.backend)
            public_key = serialization.load_pem_public_key(
                keys['public'].encode(), backend=self.backend)
        elif key_type == 'ed25519':
            private_key = serialization.load_pem_private_key(
                keys['private'].encode(), password=None, backend=self.backend)
            public_key = serialization.load_pem_public_key(
                keys['public'].encode(), backend=self.backend)
        else:  # RSA fallback
            private_key = serialization.load_pem_private_key(
                keys['private'].encode(), password=None, backend=self.backend)
            public_key = serialization.load_pem_public_key(
                keys['public'].encode(), backend=self.backend)
        return {'private': private_key, 'public': public_key, 'type': key_type}

    def ecdsa_sign_message(self, message, private_key):
        signature = private_key.sign(
            message.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        return signature

    def ecdsa_verify_signature(self, message, signature, public_key):
        try:
            public_key.verify(
                signature,
                message.encode(),
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception:
            return False

    def ed25519_sign_message(self, message, private_key):
        return private_key.sign(message.encode())

    def ed25519_verify_signature(self, message, signature, public_key):
        try:
            public_key.verify(signature, message.encode())
            return True
        except Exception:
            return False

    def hybrid_encrypt_file(self, file_path, rsa_public_key):
        # Read file
        with open(file_path, 'rb') as f:
            data = f.read()
        # Generate AES key
        aes_key = os.urandom(32)  # AES-256
        # Encrypt data with AES
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        # Encrypt AES key with RSA
        encrypted_key = rsa_public_key.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Save: [len(encrypted_key)][encrypted_key][iv][encrypted_data]
        return encrypted_key, iv, encrypted_data

    def hybrid_decrypt_file(self, encrypted_file_path, rsa_private_key):
        with open(encrypted_file_path, 'rb') as f:
            data = f.read()
        # Read encrypted key length (assume 256 bytes for RSA-2048, 384 for 3072, 512 for 4096)
        # We'll store the length as 2 bytes at the start
        key_len = int.from_bytes(data[:2], 'big')
        encrypted_key = data[2:2+key_len]
        iv = data[2+key_len:2+key_len+16]
        encrypted_data = data[2+key_len+16:]
        # Decrypt AES key
        aes_key = rsa_private_key.decrypt(
            encrypted_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Decrypt data
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data

    def export_key(self, key_id, key_type, is_private, export_path, password=None):
        keys = self.rsa_keys.get(key_id)
        if not keys:
            raise ValueError("Key ID not found.")
        if is_private:
            key_data = keys['private'].encode()
            if password:
                # Encrypt private key with password (PBKDF2 + AES)
                salt = os.urandom(16)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=self.backend
                )
                key = kdf.derive(password.encode())
                iv = os.urandom(16)
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
                encryptor = cipher.encryptor()
                padder = padding.PKCS7(algorithms.AES.block_size).padder()
                padded = padder.update(key_data) + padder.finalize()
                encrypted = encryptor.update(padded) + encryptor.finalize()
                # Save: [b'ENCKEY'][salt][iv][encrypted]
                with open(export_path, 'wb') as f:
                    f.write(b'ENCKEY' + salt + iv + encrypted)
            else:
                with open(export_path, 'wb') as f:
                    f.write(key_data)
        else:
            key_data = keys['public'].encode()
            with open(export_path, 'wb') as f:
                f.write(key_data)

    def import_key(self, import_path, password=None):
        with open(import_path, 'rb') as f:
            data = f.read()
        if data.startswith(b'ENCKEY'):
            # Encrypted private key
            salt = data[6:22]
            iv = data[22:38]
            encrypted = data[38:]
            if not password:
                raise ValueError("Password required to decrypt private key.")
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=self.backend
            )
            key = kdf.derive(password.encode())
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            decryptor = cipher.decryptor()
            padded = decryptor.update(encrypted) + decryptor.finalize()
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            key_data = unpadder.update(padded) + unpadder.finalize()
            # Try to load as private key
            try:
                private_key = serialization.load_pem_private_key(key_data, password=None, backend=self.backend)
                public_key = private_key.public_key()
                # Detect type
                if isinstance(private_key, rsa.RSAPrivateKey):
                    key_type = 'rsa'
                elif isinstance(private_key, ec.EllipticCurvePrivateKey):
                    key_type = 'ecdsa'
                elif isinstance(private_key, ed25519.Ed25519PrivateKey):
                    key_type = 'ed25519'
                else:
                    raise ValueError("Unsupported private key type.")
                key_id = base64.b64encode(os.urandom(8)).decode()
                self.rsa_keys[key_id] = {
                    'type': key_type,
                    'private': key_data.decode(),
                    'public': public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode()
                }
                self.save_keys()
                return key_id, key_type, True
            except Exception:
                raise ValueError("Failed to import private key. Wrong password or corrupted file.")
        else:
            # Try to load as public or unencrypted private key
            try:
                private_key = serialization.load_pem_private_key(data, password=None, backend=self.backend)
                public_key = private_key.public_key()
                if isinstance(private_key, rsa.RSAPrivateKey):
                    key_type = 'rsa'
                elif isinstance(private_key, ec.EllipticCurvePrivateKey):
                    key_type = 'ecdsa'
                elif isinstance(private_key, ed25519.Ed25519PrivateKey):
                    key_type = 'ed25519'
                else:
                    raise ValueError("Unsupported private key type.")
                key_id = base64.b64encode(os.urandom(8)).decode()
                self.rsa_keys[key_id] = {
                    'type': key_type,
                    'private': data.decode(),
                    'public': public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode()
                }
                self.save_keys()
                return key_id, key_type, True
            except Exception:
                # Try as public key
                try:
                    public_key = serialization.load_pem_public_key(data, backend=self.backend)
                    if isinstance(public_key, rsa.RSAPublicKey):
                        key_type = 'rsa'
                    elif isinstance(public_key, ec.EllipticCurvePublicKey):
                        key_type = 'ecdsa'
                    elif isinstance(public_key, ed25519.Ed25519PublicKey):
                        key_type = 'ed25519'
                    else:
                        raise ValueError("Unsupported public key type.")
                    key_id = base64.b64encode(os.urandom(8)).decode()
                    self.rsa_keys[key_id] = {
                        'type': key_type,
                        'public': data.decode()
                    }
                    self.save_keys()
                    return key_id, key_type, False
                except Exception:
                    raise ValueError("Failed to import key. Not a valid PEM key file.")

    def get_vault_path(self):
        return os.path.join(self.data_dir, "password_vault.enc")

    def load_vault(self, master_password):
        path = self.get_vault_path()
        if not os.path.exists(path):
            return {}
        with open(path, 'rb') as f:
            data = f.read()
        salt = data[:16]
        iv = data[16:32]
        encrypted = data[32:]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        key = kdf.derive(master_password.encode())
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded = decryptor.update(encrypted) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        vault_json = unpadder.update(padded) + unpadder.finalize()
        return json.loads(vault_json.decode())

    def save_vault(self, vault, master_password):
        path = self.get_vault_path()
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        key = kdf.derive(master_password.encode())
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        vault_json = json.dumps(vault).encode()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded = padder.update(vault_json) + padder.finalize()
        encrypted = encryptor.update(padded) + encryptor.finalize()
        with open(path, 'wb') as f:
            f.write(salt + iv + encrypted)

    def add_password_to_vault(self, label, password, master_password):
        try:
            vault = self.load_vault(master_password)
        except Exception:
            vault = {}
        vault[label] = password
        self.save_vault(vault, master_password)

    def get_password_from_vault(self, label, master_password):
        vault = self.load_vault(master_password)
        return vault.get(label)

    def list_vault_labels(self, master_password):
        vault = self.load_vault(master_password)
        return list(vault.keys())

    def update_password_in_vault(self, label, new_password, master_password):
        vault = self.load_vault(master_password)
        if label not in vault:
            raise ValueError("Label not found in vault.")
        vault[label] = new_password
        self.save_vault(vault, master_password)

    def delete_password_from_vault(self, label, master_password):
        vault = self.load_vault(master_password)
        if label not in vault:
            raise ValueError("Label not found in vault.")
        del vault[label]
        self.save_vault(vault, master_password)

def print_section(title):
    print(f"\n{Fore.CYAN}{'═'*55}")
    print(f"{Fore.CYAN}{title.center(55)}")
    print(f"{Fore.CYAN}{'═'*55}{Style.RESET_ALL}")

def print_subsection(subtitle):
    print(f"\n{Fore.YELLOW}{subtitle}{Style.RESET_ALL}")

def print_instruction(text):
    print(f"  {Fore.YELLOW}{text}{Style.RESET_ALL}")

def print_result(label, value):
    print(f"  {Fore.CYAN}{label}:{Style.RESET_ALL} {Fore.WHITE}{value}{Style.RESET_ALL}")

def print_success_block(message):
    print(f"\n{Fore.GREEN}✓ {message}{Style.RESET_ALL}")

def print_error_block(message):
    print(f"\n{Fore.RED}✗ {message}{Style.RESET_ALL}")

def print_info_block(message):
    print(f"\n{Fore.YELLOW}ℹ {message}{Style.RESET_ALL}")

def add_back_and_help_to_submenus(sub_menus):
    for key in sub_menus:
        # Remove any existing '0' or 'H' to avoid duplicates
        sub_menus[key] = [item for item in sub_menus[key] if item[0] not in ("0", "H", "h")]
        sub_menus[key].append(("0", "Back"))
        sub_menus[key].append(("H", "Help / About"))

def main():
    crypto = CryptoKit()
    while True:
        print_header()
        print_section("MAIN MENU")
        for key, label in main_menu_groups:
            print_instruction(f"{key}. {label}")
        choice = get_input("Select a group: ").upper()
        if choice == "Q":
            print_section("EXIT")
            print_info_block("Thank you for using Crypto Toolkit!")
            break
        elif choice == "0":
            print_header()
            print_section("HELP / ABOUT")
            print_help()
            continue
        elif choice in sub_menus:
            while True:
                print_header()
                print_section(main_menu_groups[int(choice)-1][1].upper())
                for subkey, sublabel in sub_menus[choice]:
                    print_instruction(f"{subkey}. {sublabel}")
                subchoice = get_input("Select an option: ").upper()
                if subchoice == "0":
                    break
                elif subchoice == "H":
                    print_header()
                    print_section("HELP / ABOUT")
                    print_help()
                    continue
                # Key Management
                if choice == "1":
                    if subchoice == "1":
                        print_header()
                        print_section("GENERATE AES KEY")
                        print_info_block(descriptions["1"])
                        print_info_block("Generating AES Key...")
                        key = crypto.generate_aes_key()
                        print_success_block("AES Key generated successfully!")
                        print_result("AES Key (Base64)", base64.b64encode(key).decode())
                        input("\nPress Enter to continue...")
                    elif subchoice == "2":
                        print_header()
                        print_section("GENERATE RSA KEYS")
                        print_info_block(descriptions["2"])
                        print_info_block("Generating RSA Keys...")
                        try:
                            key_size = int(get_input(f"Enter RSA key size {RSA_KEY_SIZES} [default: 2048]: ") or 2048)
                            validate_key_size(key_size, RSA_KEY_SIZES)
                        except ValueError as e:
                            print_error_block(str(e))
                            input("\nPress Enter to continue...")
                            continue
                        key_id, private_key, public_key = crypto.generate_rsa_keys(key_size)
                        print_success_block("RSA Keys generated successfully!")
                        print_result("Key ID", key_id)
                        input("\nPress Enter to continue...")
                    elif subchoice == "3":
                        print_header()
                        print_section("GENERATE ECDSA KEYS")
                        print_info_block(descriptions["21"])
                        key_id, private_key, public_key = crypto.generate_ecdsa_keys()
                        print_success_block("ECDSA Keys generated successfully!")
                        print_result("Key ID", key_id)
                        input("\nPress Enter to continue...")
                    elif subchoice == "4":
                        print_header()
                        print_section("GENERATE ED25519 KEYS")
                        print_info_block(descriptions["22"])
                        key_id, private_key, public_key = crypto.generate_ed25519_keys()
                        print_success_block("Ed25519 Keys generated successfully!")
                        print_result("Key ID", key_id)
                        input("\nPress Enter to continue...")
                    elif subchoice == "5":
                        print_header()
                        print_section("LIST SAVED KEYS")
                        print_info_block(descriptions["3"])
                        print_info_block("Listing Saved Keys...")
                        if not crypto.rsa_keys:
                            print_error_block("No saved keys found.")
                        else:
                            print_success_block("Found saved keys:")
                            for key_id in crypto.rsa_keys:
                                print_result("Key ID", key_id)
                        input("\nPress Enter to continue...")
                    elif subchoice == "6":
                        print_header()
                        print_section("EXPORT KEY TO FILE")
                        print_info_block(descriptions["29"])
                        key_id = get_input("Enter Key ID to export: ")
                        keys = crypto.rsa_keys.get(key_id)
                        if not keys:
                            print_error_block("Key ID not found.")
                            input("\nPress Enter to continue...")
                            continue
                        is_private = get_input("Export private key? (y/n): ").lower().startswith('y')
                        export_path = get_input("Enter export file path: ")
                        password = None
                        if is_private:
                            pw_choice = get_input("Encrypt private key with password? (y/n): ").lower().startswith('y')
                            if pw_choice:
                                password = get_input("Enter password for key encryption: ")
                        try:
                            crypto.export_key(key_id, keys.get('type', 'rsa'), is_private, export_path, password)
                            print_success_block(f"Key exported successfully to {export_path}")
                        except Exception as e:
                            print_error_block(f"Error exporting key: {str(e)}")
                        input("\nPress Enter to continue...")
                    elif subchoice == "7":
                        print_header()
                        print_section("IMPORT KEY FROM FILE")
                        print_info_block(descriptions["30"])
                        import_path = get_input("Enter key file path to import: ")
                        password = None
                        try:
                            with open(import_path, 'rb') as f:
                                if f.read(6) == b'ENCKEY':
                                    password = get_input("Enter password to decrypt private key: ")
                            key_id, key_type, is_private = crypto.import_key(import_path, password)
                            print_success_block(f"Key imported successfully! Key ID: {key_id} (type: {key_type}, private: {is_private})")
                        except Exception as e:
                            print_error_block(f"Error importing key: {str(e)}")
                        input("\nPress Enter to continue...")
                # Encryption & Decryption
                elif choice == "2":
                    if subchoice == "1":
                        print_header()
                        print_section("ENCRYPT TEXT (AES)")
                        print_info_block(descriptions["4"])
                        print_subsection("AES Text Encryption")
                        text = get_input("Enter text to encrypt: ")
                        password = get_input("Enter password: ")
                        print_info_block("Encrypting...")
                        key, salt = crypto.derive_key_from_password(password)
                        encrypted = crypto.aes_encrypt(text.encode(), key)
                        print_success_block("Text encrypted successfully!")
                        print_result("Encrypted (Base64)", base64.b64encode(encrypted).decode())
                        print_result("Salt (Base64)", base64.b64encode(salt).decode())
                        input("\nPress Enter to continue...")
                    elif subchoice == "2":
                        print_header()
                        print_section("DECRYPT TEXT (AES)")
                        print_info_block(descriptions["5"])
                        print_subsection("AES Text Decryption")
                        encrypted = base64.b64decode(get_input("Enter encrypted text (Base64): "))
                        password = get_input("Enter password: ")
                        salt = base64.b64decode(get_input("Enter salt (Base64): "))
                        print_info_block("Decrypting...")
                        key, _ = crypto.derive_key_from_password(password, salt)
                        decrypted = crypto.aes_decrypt(encrypted, key)
                        print_success_block("Text decrypted successfully!")
                        print_result("Decrypted text", decrypted.decode())
                        input("\nPress Enter to continue...")
                    elif subchoice == "3":
                        print_header()
                        print_section("ENCRYPT TEXT (RSA)")
                        print_info_block(descriptions["6"])
                        print_subsection("RSA Text Encryption")
                        text = get_input("Enter text to encrypt: ")
                        print_info_block("Generating RSA keys and encrypting...")
                        key_id, private_key, public_key = crypto.generate_rsa_keys()
                        encrypted = crypto.rsa_encrypt(text.encode(), public_key)
                        print_success_block("Text encrypted successfully!")
                        print_result("Key ID (save this)", key_id)
                        print_result("Encrypted (Base64)", base64.b64encode(encrypted).decode())
                        input("\nPress Enter to continue...")
                    elif subchoice == "4":
                        print_header()
                        print_section("DECRYPT TEXT (RSA)")
                        print_info_block(descriptions["7"])
                        print_subsection("RSA Text Decryption")
                        encrypted = base64.b64decode(get_input("Enter encrypted text (Base64): "))
                        key_id = get_input("Enter Key ID: ")
                        print_info_block("Decrypting...")
                        keys = crypto.get_rsa_keys(key_id)
                        if not keys:
                            print_error_block("Invalid Key ID")
                            input("\nPress Enter to continue...")
                            continue
                        decrypted = crypto.rsa_decrypt(encrypted, keys['private'])
                        print_success_block("Text decrypted successfully!")
                        print_result("Decrypted text", decrypted.decode())
                        input("\nPress Enter to continue...")
                    elif subchoice == "5":
                        print_header()
                        print_section("ENCRYPT FILE (AES)")
                        print_info_block(descriptions["13"])
                        print_subsection("AES File Encryption")
                        print_instruction("Enter the full path to the file you want to encrypt.")
                        print_instruction("Example: C:\\Users\\YourName\\Desktop\\myfile.txt")
                        try:
                            file_path = validate_file_path(get_input("Enter file path to encrypt: "))
                        except ValueError as e:
                            print_error_block(str(e))
                            input("\nPress Enter to continue...")
                            continue
                        password = get_input("Enter password: ")
                        try:
                            with open(file_path, 'rb') as f:
                                data = f.read()
                            print_info_block("Encrypting file...")
                            for _ in tqdm(range(1), desc="Encrypting", ncols=70):
                                key, salt = crypto.derive_key_from_password(password)
                                encrypted_data = crypto.aes_encrypt(data, key)
                            output_dir = os.path.join(os.path.dirname(file_path), "encrypted")
                            os.makedirs(output_dir, exist_ok=True)
                            output_path = os.path.join(output_dir, f"{os.path.basename(file_path)}.encrypted")
                            with open(output_path, 'wb') as f:
                                f.write(salt + encrypted_data)
                            print_success_block("File encrypted successfully!")
                            print_result("Encrypted file saved as", output_path)
                        except Exception as e:
                            print_error_block(f"Error encrypting file: {str(e)}")
                        input("\nPress Enter to continue...")
                    elif subchoice == "6":
                        print_header()
                        print_section("DECRYPT FILE (AES)")
                        print_info_block(descriptions["14"])
                        print_subsection("AES File Decryption")
                        print_instruction("Enter the full path to the encrypted file.")
                        print_instruction("Example: C:\\Users\\YourName\\Desktop\\encrypted\\myfile.txt.encrypted")
                        try:
                            file_path = validate_file_path(get_input("Enter encrypted file path: "))
                        except ValueError as e:
                            print_error_block(str(e))
                            input("\nPress Enter to continue...")
                            continue
                        password = get_input("Enter password: ")
                        try:
                            with open(file_path, 'rb') as f:
                                data = f.read()
                            print_info_block("Decrypting file...")
                            for _ in tqdm(range(1), desc="Decrypting", ncols=70):
                                salt = data[:16]
                                encrypted_data = data[16:]
                                key, _ = crypto.derive_key_from_password(password, salt)
                                decrypted_data = crypto.aes_decrypt(encrypted_data, key)
                            output_dir = os.path.join(os.path.dirname(file_path), "decrypted")
                            os.makedirs(output_dir, exist_ok=True)
                            output_path = os.path.join(output_dir, os.path.basename(file_path).replace('.encrypted', ''))
                            with open(output_path, 'wb') as f:
                                f.write(decrypted_data)
                            print_success_block("File decrypted successfully!")
                            print_result("Decrypted file saved as", output_path)
                        except Exception as e:
                            print_error_block(f"Error decrypting file: {str(e)}")
                        input("\nPress Enter to continue...")
                # Digital Signatures
                elif choice == "3":
                    if subchoice == "1":
                        print_header()
                        print_section("SIGN MESSAGE (RSA)")
                        print_info_block(descriptions["8"])
                        print_subsection("Digital Signature")
                        message = get_input("Enter message to sign: ")
                        print_info_block("Generating RSA keys...")
                        key_id, private_key, public_key = crypto.generate_rsa_keys()
                        print_info_block("Signing message...")
                        signature = crypto.sign_message(message, private_key)
                        print_success_block("Message signed successfully!")
                        print_result("Key ID (save this)", key_id)
                        print_result("Signature (Base64)", base64.b64encode(signature).decode())
                        input("\nPress Enter to continue...")
                    elif subchoice == "2":
                        print_header()
                        print_section("VERIFY SIGNATURE (RSA)")
                        print_info_block(descriptions["9"])
                        print_subsection("Signature Verification")
                        message = get_input("Enter original message: ")
                        signature = base64.b64decode(get_input("Enter signature (Base64): "))
                        key_id = get_input("Enter Key ID: ")
                        print_info_block("Verifying signature...")
                        keys = crypto.get_rsa_keys(key_id)
                        if not keys:
                            print_error_block("Invalid Key ID")
                            input("\nPress Enter to continue...")
                            continue
                        is_valid = crypto.verify_signature(message, signature, keys['public'])
                        if is_valid:
                            print_success_block("Signature is valid!")
                        else:
                            print_error_block("Signature is invalid!")
                        input("\nPress Enter to continue...")
                    elif subchoice == "3":
                        print_header()
                        print_section("SIGN FILE (RSA)")
                        print_info_block(descriptions["10"])
                        print_subsection("File Signature")
                        print_instruction("Enter the full path to the file you want to sign.")
                        print_instruction("Example: C:\\Users\\YourName\\Desktop\\myfile.txt")
                        try:
                            file_path = validate_file_path(get_input("Enter file path to sign: "))
                        except ValueError as e:
                            print_error_block(str(e))
                            input("\nPress Enter to continue...")
                            continue
                        print_info_block("Generating RSA keys...")
                        key_id, private_key, public_key = crypto.generate_rsa_keys()
                        print_info_block("Signing file...")
                        sig_file = crypto.sign_file(file_path, private_key)
                        print_success_block("File signed successfully!")
                        print_result("Key ID (save this)", key_id)
                        print_result("Signature file saved as", sig_file)
                        input("\nPress Enter to continue...")
                    elif subchoice == "4":
                        print_header()
                        print_section("VERIFY FILE SIGNATURE (RSA)")
                        print_info_block(descriptions["11"])
                        print_subsection("File Signature Verification")
                        print_instruction("Enter the full path to the file and its signature.")
                        print_instruction("Example: C:\\Users\\YourName\\Desktop\\myfile.txt")
                        try:
                            file_path = validate_file_path(get_input("Enter file path to verify: "))
                            sig_file = validate_file_path(get_input("Enter signature file path: "))
                        except ValueError as e:
                            print_error_block(str(e))
                            input("\nPress Enter to continue...")
                            continue
                        key_id = get_input("Enter Key ID: ")
                        print_info_block("Verifying signature...")
                        keys = crypto.get_rsa_keys(key_id)
                        if not keys:
                            print_error_block("Invalid Key ID")
                            input("\nPress Enter to continue...")
                            continue
                        is_valid = crypto.verify_file_signature(file_path, sig_file, keys['public'])
                        if is_valid:
                            print_success_block("File signature is valid!")
                        else:
                            print_error_block("File signature is invalid!")
                        input("\nPress Enter to continue...")
                    elif subchoice == "5":
                        print_header()
                        print_section("SIGN MESSAGE (ECDSA)")
                        print_info_block(descriptions["23"])
                        message = get_input("Enter message to sign: ")
                        key_id = get_input("Enter ECDSA Key ID: ")
                        keys = crypto.get_any_keys(key_id)
                        if not keys or keys['type'] != 'ecdsa':
                            print_error_block("Invalid ECDSA Key ID.")
                            input("\nPress Enter to continue...")
                            continue
                        signature = crypto.ecdsa_sign_message(message, keys['private'])
                        print_success_block("Message signed successfully!")
                        print_result("Signature (Base64)", base64.b64encode(signature).decode())
                        input("\nPress Enter to continue...")
                    elif subchoice == "6":
                        print_header()
                        print_section("VERIFY SIGNATURE (ECDSA)")
                        print_info_block(descriptions["24"])
                        message = get_input("Enter original message: ")
                        signature = base64.b64decode(get_input("Enter signature (Base64): "))
                        key_id = get_input("Enter ECDSA Key ID: ")
                        keys = crypto.get_any_keys(key_id)
                        if not keys or keys['type'] != 'ecdsa':
                            print_error_block("Invalid ECDSA Key ID.")
                            input("\nPress Enter to continue...")
                            continue
                        is_valid = crypto.ecdsa_verify_signature(message, signature, keys['public'])
                        if is_valid:
                            print_success_block("Signature is valid!")
                        else:
                            print_error_block("Signature is invalid!")
                        input("\nPress Enter to continue...")
                    elif subchoice == "7":
                        print_header()
                        print_section("SIGN MESSAGE (ED25519)")
                        print_info_block(descriptions["25"])
                        message = get_input("Enter message to sign: ")
                        key_id = get_input("Enter Ed25519 Key ID: ")
                        keys = crypto.get_any_keys(key_id)
                        if not keys or keys['type'] != 'ed25519':
                            print_error_block("Invalid Ed25519 Key ID.")
                            input("\nPress Enter to continue...")
                            continue
                        signature = crypto.ed25519_sign_message(message, keys['private'])
                        print_success_block("Message signed successfully!")
                        print_result("Signature (Base64)", base64.b64encode(signature).decode())
                        input("\nPress Enter to continue...")
                    elif subchoice == "8":
                        print_header()
                        print_section("VERIFY SIGNATURE (ED25519)")
                        print_info_block(descriptions["26"])
                        message = get_input("Enter original message: ")
                        signature = base64.b64decode(get_input("Enter signature (Base64): "))
                        key_id = get_input("Enter Ed25519 Key ID: ")
                        keys = crypto.get_any_keys(key_id)
                        if not keys or keys['type'] != 'ed25519':
                            print_error_block("Invalid Ed25519 Key ID.")
                            input("\nPress Enter to continue...")
                            continue
                        is_valid = crypto.ed25519_verify_signature(message, signature, keys['public'])
                        if is_valid:
                            print_success_block("Signature is valid!")
                        else:
                            print_error_block("Signature is invalid!")
                        input("\nPress Enter to continue...")
                # Hybrid Encryption
                elif choice == "8":
                    if subchoice == "1":
                        print_header()
                        print_section("HYBRID ENCRYPT FILE (AES+RSA)")
                        print_info_block(descriptions["27"])
                        print_subsection("Hybrid File Encryption")
                        try:
                            file_path = validate_file_path(get_input("Enter file path to encrypt: "))
                        except ValueError as e:
                            print_error_block(str(e))
                            input("\nPress Enter to continue...")
                            continue
                        key_id = get_input("Enter RSA Key ID for encryption: ")
                        keys = crypto.get_any_keys(key_id)
                        if not keys or keys['type'] != 'rsa':
                            print_error_block("Invalid RSA Key ID.")
                            input("\nPress Enter to continue...")
                            continue
                        try:
                            encrypted_key, iv, encrypted_data = crypto.hybrid_encrypt_file(file_path, keys['public'])
                            key_len = len(encrypted_key)
                            output_dir = os.path.join(os.path.dirname(file_path), "hybrid_encrypted")
                            os.makedirs(output_dir, exist_ok=True)
                            output_path = os.path.join(output_dir, os.path.basename(file_path) + ".hybrid")
                            with open(output_path, 'wb') as f:
                                f.write(key_len.to_bytes(2, 'big') + encrypted_key + iv + encrypted_data)
                            print_success_block("File hybrid-encrypted successfully!")
                            print_result("Hybrid Encrypted file saved as", output_path)
                        except Exception as e:
                            print_error_block(f"Error during hybrid encryption: {str(e)}")
                        input("\nPress Enter to continue...")
                    elif subchoice == "2":
                        print_header()
                        print_section("HYBRID DECRYPT FILE (AES+RSA)")
                        print_info_block(descriptions["28"])
                        print_subsection("Hybrid File Decryption")
                        try:
                            file_path = validate_file_path(get_input("Enter hybrid encrypted file path: "))
                        except ValueError as e:
                            print_error_block(str(e))
                            input("\nPress Enter to continue...")
                            continue
                        key_id = get_input("Enter RSA Key ID for decryption: ")
                        keys = crypto.get_any_keys(key_id)
                        if not keys or keys['type'] != 'rsa':
                            print_error_block("Invalid RSA Key ID.")
                            input("\nPress Enter to continue...")
                            continue
                        try:
                            decrypted_data = crypto.hybrid_decrypt_file(file_path, keys['private'])
                            output_dir = os.path.join(os.path.dirname(file_path), "hybrid_decrypted")
                            os.makedirs(output_dir, exist_ok=True)
                            output_path = os.path.join(output_dir, os.path.basename(file_path).replace('.hybrid', ''))
                            with open(output_path, 'wb') as f:
                                f.write(decrypted_data)
                            print_success_block("File hybrid-decrypted successfully!")
                            print_result("Hybrid Decrypted file saved as", output_path)
                        except Exception as e:
                            print_error_block(f"Error during hybrid decryption: {str(e)}")
                        input("\nPress Enter to continue...")
                # Key Management (Import/Export)
                elif choice == "9":
                    if subchoice == "1":
                        print_header()
                        print_section("EXPORT KEY TO FILE")
                        print_info_block(descriptions["29"])
                        key_id = get_input("Enter Key ID to export: ")
                        keys = crypto.rsa_keys.get(key_id)
                        if not keys:
                            print_error_block("Key ID not found.")
                            input("\nPress Enter to continue...")
                            continue
                        is_private = get_input("Export private key? (y/n): ").lower().startswith('y')
                        export_path = get_input("Enter export file path: ")
                        password = None
                        if is_private:
                            pw_choice = get_input("Encrypt private key with password? (y/n): ").lower().startswith('y')
                            if pw_choice:
                                password = get_input("Enter password for key encryption: ")
                        try:
                            crypto.export_key(key_id, keys.get('type', 'rsa'), is_private, export_path, password)
                            print_success_block(f"Key exported successfully to {export_path}")
                        except Exception as e:
                            print_error_block(f"Error exporting key: {str(e)}")
                        input("\nPress Enter to continue...")
                    elif subchoice == "2":
                        print_header()
                        print_section("IMPORT KEY FROM FILE")
                        print_info_block(descriptions["30"])
                        import_path = get_input("Enter key file path to import: ")
                        password = None
                        try:
                            with open(import_path, 'rb') as f:
                                if f.read(6) == b'ENCKEY':
                                    password = get_input("Enter password to decrypt private key: ")
                            key_id, key_type, is_private = crypto.import_key(import_path, password)
                            print_success_block(f"Key imported successfully! Key ID: {key_id} (type: {key_type}, private: {is_private})")
                        except Exception as e:
                            print_error_block(f"Error importing key: {str(e)}")
                        input("\nPress Enter to continue...")
                # Password Manager
                elif choice == "10":
                    if subchoice == "1":
                        print_header()
                        print_section("ADD PASSWORD TO VAULT")
                        print_info_block(descriptions["31"])
                        label = get_input("Enter label for password: ")
                        password = get_input("Enter password to store: ")
                        strength = check_password_strength(password)
                        print_info_block(f"Password strength: {strength}")
                        master_password = get_input("Enter master password for vault: ")
                        try:
                            crypto.add_password_to_vault(label, password, master_password)
                            print_success_block(f"Password for '{label}' added to vault.")
                        except Exception as e:
                            print_error_block(f"Error adding password: {str(e)}")
                        input("\nPress Enter to continue...")
                    elif subchoice == "2":
                        print_header()
                        print_section("RETRIEVE PASSWORD FROM VAULT")
                        print_info_block(descriptions["32"])
                        label = get_input("Enter label to retrieve: ")
                        master_password = get_input("Enter master password for vault: ")
                        try:
                            password = crypto.get_password_from_vault(label, master_password)
                            if password is not None:
                                print_success_block(f"Password for '{label}': {password}")
                            else:
                                print_error_block(f"No password found for label '{label}'.")
                        except Exception as e:
                            print_error_block(f"Error retrieving password: {str(e)}")
                        input("\nPress Enter to continue...")
                    elif subchoice == "3":
                        print_header()
                        print_section("LIST PASSWORD LABELS IN VAULT")
                        print_info_block(descriptions["33"])
                        master_password = get_input("Enter master password for vault: ")
                        try:
                            labels = crypto.list_vault_labels(master_password)
                            if labels:
                                print_success_block("Labels in vault:")
                                for label in labels:
                                    print_result("Label", label)
                            else:
                                print_info_block("No passwords stored in vault.")
                        except Exception as e:
                            print_error_block(f"Error listing vault labels: {str(e)}")
                        input("\nPress Enter to continue...")
                    elif subchoice == "4":
                        print_header()
                        print_section("UPDATE PASSWORD IN VAULT")
                        print_info_block(descriptions["34"])
                        label = get_input("Enter label to update: ")
                        new_password = get_input("Enter new password: ")
                        strength = check_password_strength(new_password)
                        print_info_block(f"Password strength: {strength}")
                        master_password = get_input("Enter master password for vault: ")
                        try:
                            crypto.update_password_in_vault(label, new_password, master_password)
                            print_success_block(f"Password for '{label}' updated in vault.")
                        except Exception as e:
                            print_error_block(f"Error updating password: {str(e)}")
                        input("\nPress Enter to continue...")
                    elif subchoice == "5":
                        print_header()
                        print_section("DELETE PASSWORD FROM VAULT")
                        print_info_block(descriptions["35"])
                        label = get_input("Enter label to delete: ")
                        master_password = get_input("Enter master password for vault: ")
                        try:
                            crypto.delete_password_from_vault(label, master_password)
                            print_success_block(f"Password for '{label}' deleted from vault.")
                        except Exception as e:
                            print_error_block(f"Error deleting password: {str(e)}")
                        input("\nPress Enter to continue...")
                # Steganography
                elif choice == "6":
                    if subchoice == "1":
                        print_header()
                        print_section("HIDE MESSAGE IN IMAGE")
                        print_info_block(descriptions["18"])
                        image_path = get_input("Enter image file path: ")
                        message = get_input("Enter message to hide: ")
                        output_path = get_input("Enter output image file path: ")
                        password = get_input("Enter password to encrypt message (leave blank for none): ", required=False)
                        try:
                            out = crypto.steg_hide(image_path, message, output_path, password if password else None)
                            print_success_block(f"Message hidden in image and saved as {out}")
                        except Exception as e:
                            print_error_block(str(e))
                        input("\nPress Enter to continue...")
                    elif subchoice == "2":
                        print_header()
                        print_section("REVEAL MESSAGE FROM IMAGE")
                        print_info_block(descriptions["19"])
                        image_path = get_input("Enter image file path: ")
                        password = get_input("Enter password to decrypt message (leave blank for none): ", required=False)
                        try:
                            message = crypto.steg_reveal(image_path, password if password else None)
                            print_success_block("Message revealed successfully!")
                            print_result("Hidden Message", message)
                        except Exception as e:
                            print_error_block(str(e))
                        input("\nPress Enter to continue...")
                    elif subchoice == "3":
                        print_header()
                        print_section("HIDE MESSAGE IN AUDIO (WAV)")
                        print_info_block("Hide a secret message inside a WAV audio file.")
                        audio_path = get_input("Enter WAV audio file path: ")
                        message = get_input("Enter message to hide: ")
                        output_path = get_input("Enter output audio file path: ")
                        password = get_input("Enter password to encrypt message (leave blank for none): ", required=False)
                        try:
                            out = audio_steg_hide(audio_path, message, output_path, password if password else None)
                            print_success_block(f"Message hidden in audio and saved as {out}")
                        except Exception as e:
                            print_error_block(str(e))
                        input("\nPress Enter to continue...")
                    elif subchoice == "4":
                        print_header()
                        print_section("REVEAL MESSAGE FROM AUDIO (WAV)")
                        print_info_block("Reveal a hidden message from a WAV audio file.")
                        audio_path = get_input("Enter WAV audio file path: ")
                        password = get_input("Enter password to decrypt message (leave blank for none): ", required=False)
                        try:
                            message = audio_steg_reveal(audio_path, password if password else None)
                            print_success_block("Message revealed successfully!")
                            print_result("Hidden Message", message)
                        except Exception as e:
                            print_error_block(str(e))
                        input("\nPress Enter to continue...")
                    elif subchoice == "5":
                        print_header()
                        print_section("HIDE MESSAGE IN VIDEO")
                        print_info_block("Hide a secret message inside a video file (e.g., MP4, AVI).")
                        video_path = get_input("Enter video file path: ")
                        message = get_input("Enter message to hide: ")
                        output_path = get_input("Enter output video file path: ")
                        password = get_input("Enter password to encrypt message (leave blank for none): ", required=False)
                        try:
                            out = video_steg_hide(video_path, message, output_path, password if password else None)
                            print_success_block(f"Message hidden in video and saved as {out}")
                        except Exception as e:
                            print_error_block(str(e))
                        input("\nPress Enter to continue...")
                    elif subchoice == "6":
                        print_header()
                        print_section("REVEAL MESSAGE FROM VIDEO")
                        print_info_block("Reveal a hidden message from a video file (e.g., MP4, AVI).")
                        video_path = get_input("Enter video file path: ")
                        password = get_input("Enter password to decrypt message (leave blank for none): ", required=False)
                        try:
                            message = video_steg_reveal(video_path, password if password else None)
                            print_success_block("Message revealed successfully!")
                            print_result("Hidden Message", message)
                        except Exception as e:
                            print_error_block(str(e))
                        input("\nPress Enter to continue...")
                    else:
                        print_error_block("Invalid option. Please try again.")
                # Other (Exit)
                elif choice == "11" and subchoice == "1":
                    print_section("EXIT")
                    print_info_block("Thank you for using Crypto Toolkit!")
                    exit(0)
                else:
                    print_error_block("Invalid option. Please try again.")
        else:
            print_error_block("Invalid group. Please try again.")

def video_steg_hide(video_path, message, output_path, password=None):
    if password:
        encrypted = crypto.aes_encrypt_message(message, password)
        message = base64.b64encode(encrypted).decode()
    message += chr(0)  # Null-terminate
    message_bits = ''.join([format(ord(i), '08b') for i in message])
    cap = cv2.VideoCapture(video_path)
    fourcc = cv2.VideoWriter_fourcc(*'XVID')
    fps = cap.get(cv2.CAP_PROP_FPS)
    width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    out = cv2.VideoWriter(output_path, fourcc, fps, (width, height))
    bit_idx = 0
    success, frame = cap.read()
    while success:
        for y in range(frame.shape[0]):
            for x in range(frame.shape[1]):
                for c in range(3):
                    if bit_idx < len(message_bits):
                        frame[y, x, c] = (frame[y, x, c] & ~1) | int(message_bits[bit_idx])
                        bit_idx += 1
        out.write(frame)
        success, frame = cap.read()
    cap.release()
    out.release()
    if bit_idx < len(message_bits):
        raise ValueError('Message too large to hide in video file.')
    return output_path

if __name__ == "__main__":
    add_back_and_help_to_submenus(sub_menus)
    main() 