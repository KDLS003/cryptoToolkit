import os
import base64
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from colorama import init, Fore, Style, Back
import json
from pathlib import Path
from cryptography.hazmat.primitives import serialization
import time

# Initialize colorama for colors
init()

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
    
    # Exit
    print(f"\n{Fore.YELLOW}Other:{Style.RESET_ALL}")
    print(f"{Fore.WHITE}15. Exit{Style.RESET_ALL}")
    
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

def main():
    crypto = CryptoKit()
    
    while True:
        print_header()
        print_menu()
        
        try:
            choice = get_input("Enter your choice (1-15): ")
            
            if choice == "1":
                print_header()
                print_info("Generating AES Key...")
                key = crypto.generate_aes_key()
                print_success("AES Key generated successfully!")
                print(f"\n{Fore.CYAN}AES Key (Base64):{Style.RESET_ALL}")
                print(f"{Fore.WHITE}{base64.b64encode(key).decode()}{Style.RESET_ALL}")
                input("\nPress Enter to continue...")
                
            elif choice == "2":
                print_header()
                print_info("Generating RSA Keys...")
                key_id, private_key, public_key = crypto.generate_rsa_keys()
                print_success("RSA Keys generated successfully!")
                print(f"\n{Fore.CYAN}Key ID:{Style.RESET_ALL}")
                print(f"{Fore.WHITE}{key_id}{Style.RESET_ALL}")
                print_info("Save this Key ID for encryption/decryption operations")
                input("\nPress Enter to continue...")
                
            elif choice == "3":
                print_header()
                print_info("Listing Saved Keys...")
                if not crypto.rsa_keys:
                    print_error("No saved keys found.")
                else:
                    print_success("Found saved keys:")
                    for key_id in crypto.rsa_keys:
                        print(f"\n{Fore.CYAN}Key ID:{Style.RESET_ALL}")
                        print(f"{Fore.WHITE}{key_id}{Style.RESET_ALL}")
                input("\nPress Enter to continue...")
                
            elif choice == "4":
                print_header()
                print_info("AES Text Encryption")
                text = get_input("Enter text to encrypt: ")
                password = get_input("Enter password: ")
                
                print_loading("Encrypting")
                key, salt = crypto.derive_key_from_password(password)
                encrypted = crypto.aes_encrypt(text.encode(), key)
                
                print_success("Text encrypted successfully!")
                print(f"\n{Fore.CYAN}Encrypted (Base64):{Style.RESET_ALL}")
                print(f"{Fore.WHITE}{base64.b64encode(encrypted).decode()}{Style.RESET_ALL}")
                print(f"\n{Fore.CYAN}Salt (Base64):{Style.RESET_ALL}")
                print(f"{Fore.WHITE}{base64.b64encode(salt).decode()}{Style.RESET_ALL}")
                input("\nPress Enter to continue...")
                
            elif choice == "5":
                print_header()
                print_info("AES Text Decryption")
                encrypted = base64.b64decode(get_input("Enter encrypted text (Base64): "))
                password = get_input("Enter password: ")
                salt = base64.b64decode(get_input("Enter salt (Base64): "))
                
                print_loading("Decrypting")
                key, _ = crypto.derive_key_from_password(password, salt)
                decrypted = crypto.aes_decrypt(encrypted, key)
                
                print_success("Text decrypted successfully!")
                print(f"\n{Fore.CYAN}Decrypted text:{Style.RESET_ALL}")
                print(f"{Fore.WHITE}{decrypted.decode()}{Style.RESET_ALL}")
                input("\nPress Enter to continue...")
                
            elif choice == "6":
                print_header()
                print_info("RSA Text Encryption")
                text = get_input("Enter text to encrypt: ")
                
                print_loading("Generating RSA keys and encrypting")
                key_id, private_key, public_key = crypto.generate_rsa_keys()
                encrypted = crypto.rsa_encrypt(text.encode(), public_key)
                
                print_success("Text encrypted successfully!")
                print(f"\n{Fore.CYAN}Key ID (save this):{Style.RESET_ALL}")
                print(f"{Fore.WHITE}{key_id}{Style.RESET_ALL}")
                print(f"\n{Fore.CYAN}Encrypted (Base64):{Style.RESET_ALL}")
                print(f"{Fore.WHITE}{base64.b64encode(encrypted).decode()}{Style.RESET_ALL}")
                input("\nPress Enter to continue...")
                
            elif choice == "7":
                print_header()
                print_info("RSA Text Decryption")
                encrypted = base64.b64decode(get_input("Enter encrypted text (Base64): "))
                key_id = get_input("Enter Key ID: ")
                
                print_loading("Decrypting")
                keys = crypto.get_rsa_keys(key_id)
                if not keys:
                    raise ValueError("Invalid Key ID")
                    
                decrypted = crypto.rsa_decrypt(encrypted, keys['private'])
                
                print_success("Text decrypted successfully!")
                print(f"\n{Fore.CYAN}Decrypted text:{Style.RESET_ALL}")
                print(f"{Fore.WHITE}{decrypted.decode()}{Style.RESET_ALL}")
                input("\nPress Enter to continue...")
                
            elif choice == "8":
                print_header()
                print_info("Digital Signature")
                message = get_input("Enter message to sign: ")
                
                print_loading("Generating RSA keys")
                key_id, private_key, public_key = crypto.generate_rsa_keys()
                
                print_loading("Signing message")
                signature = crypto.sign_message(message, private_key)
                
                print_success("Message signed successfully!")
                print(f"\n{Fore.CYAN}Key ID (save this):{Style.RESET_ALL}")
                print(f"{Fore.WHITE}{key_id}{Style.RESET_ALL}")
                print(f"\n{Fore.CYAN}Signature (Base64):{Style.RESET_ALL}")
                print(f"{Fore.WHITE}{base64.b64encode(signature).decode()}{Style.RESET_ALL}")
                input("\nPress Enter to continue...")
                
            elif choice == "9":
                print_header()
                print_info("Signature Verification")
                message = get_input("Enter original message: ")
                signature = base64.b64decode(get_input("Enter signature (Base64): "))
                key_id = get_input("Enter Key ID: ")
                
                print_loading("Verifying signature")
                keys = crypto.get_rsa_keys(key_id)
                if not keys:
                    raise ValueError("Invalid Key ID")
                    
                is_valid = crypto.verify_signature(message, signature, keys['public'])
                
                if is_valid:
                    print_success("Signature is valid!")
                else:
                    print_error("Signature is invalid!")
                input("\nPress Enter to continue...")
                
            elif choice == "10":
                print_header()
                print_info("File Signature")
                print("Enter the full path to the file you want to sign.")
                print(f"{Fore.YELLOW}Example: C:\\Users\\YourName\\Desktop\\myfile.txt{Style.RESET_ALL}")
                
                file_path = get_input("Enter file path to sign: ")
                if not os.path.exists(file_path):
                    raise ValueError("File does not exist")
                    
                if os.path.isdir(file_path):
                    raise ValueError("Please specify a file, not a directory")
                
                print_loading("Generating RSA keys")
                key_id, private_key, public_key = crypto.generate_rsa_keys()
                
                print_loading("Signing file")
                sig_file = crypto.sign_file(file_path, private_key)
                
                print_success("File signed successfully!")
                print(f"\n{Fore.CYAN}Key ID (save this):{Style.RESET_ALL}")
                print(f"{Fore.WHITE}{key_id}{Style.RESET_ALL}")
                print(f"\n{Fore.CYAN}Signature file saved as:{Style.RESET_ALL}")
                print(f"{Fore.WHITE}{sig_file}{Style.RESET_ALL}")
                input("\nPress Enter to continue...")
                
            elif choice == "11":
                print_header()
                print_info("File Signature Verification")
                print("Enter the full path to the file and its signature.")
                print(f"{Fore.YELLOW}Example: C:\\Users\\YourName\\Desktop\\myfile.txt{Style.RESET_ALL}")
                
                file_path = get_input("Enter file path to verify: ")
                sig_file = get_input("Enter signature file path: ")
                key_id = get_input("Enter Key ID: ")
                
                print_loading("Verifying signature")
                keys = crypto.get_rsa_keys(key_id)
                if not keys:
                    raise ValueError("Invalid Key ID")
                    
                is_valid = crypto.verify_file_signature(file_path, sig_file, keys['public'])
                
                if is_valid:
                    print_success("File signature is valid!")
                else:
                    print_error("File signature is invalid!")
                input("\nPress Enter to continue...")
                
            elif choice == "12":
                print_header()
                print_info("View Signature Details")
                print("Enter the full path to the signature file.")
                print(f"{Fore.YELLOW}Example: C:\\Users\\YourName\\Desktop\\myfile.txt.sig{Style.RESET_ALL}")
                
                sig_file = get_input("Enter signature file path: ")
                
                print_loading("Reading signature file")
                details = crypto.view_signature_details(sig_file)
                
                print_success("Signature details retrieved successfully!")
                print(f"\n{Fore.CYAN}Signature Information:{Style.RESET_ALL}")
                for key, value in details.items():
                    print(f"\n{Fore.YELLOW}{key}:{Style.RESET_ALL}")
                    print(f"{Fore.WHITE}{value}{Style.RESET_ALL}")
                input("\nPress Enter to continue...")
                
            elif choice == "13":
                print_header()
                print_info("AES File Encryption")
                print("Enter the full path to the file you want to encrypt.")
                print(f"{Fore.YELLOW}Example: C:\\Users\\YourName\\Desktop\\myfile.txt{Style.RESET_ALL}")
                
                file_path = get_input("Enter file path to encrypt: ")
                if not os.path.exists(file_path):
                    raise ValueError("File does not exist")
                    
                if os.path.isdir(file_path):
                    raise ValueError("Please specify a file, not a directory")
                    
                password = get_input("Enter password: ")
                
                print_loading("Encrypting file")
                output_path = crypto.encrypt_file(file_path, password)
                
                print_success("File encrypted successfully!")
                print(f"\n{Fore.CYAN}Encrypted file saved as:{Style.RESET_ALL}")
                print(f"{Fore.WHITE}{output_path}{Style.RESET_ALL}")
                input("\nPress Enter to continue...")
                
            elif choice == "14":
                print_header()
                print_info("AES File Decryption")
                print("Enter the full path to the encrypted file.")
                print(f"{Fore.YELLOW}Example: C:\\Users\\YourName\\Desktop\\encrypted\\myfile.txt.encrypted{Style.RESET_ALL}")
                
                file_path = get_input("Enter encrypted file path: ")
                if not os.path.exists(file_path):
                    raise ValueError("File does not exist")
                    
                if os.path.isdir(file_path):
                    raise ValueError("Please specify a file, not a directory")
                    
                password = get_input("Enter password: ")
                
                print_loading("Decrypting file")
                output_path = crypto.decrypt_file(file_path, password)
                
                print_success("File decrypted successfully!")
                print(f"\n{Fore.CYAN}Decrypted file saved as:{Style.RESET_ALL}")
                print(f"{Fore.WHITE}{output_path}{Style.RESET_ALL}")
                input("\nPress Enter to continue...")
                
            elif choice == "15":
                print_header()
                print_success("Thank you for using Crypto Toolkit!")
                print_info("Goodbye!")
                break
                
            else:
                print_error("Invalid choice! Please try again.")
                time.sleep(1)
                
        except ValueError as e:
            print_error(str(e))
            input("\nPress Enter to continue...")
        except Exception as e:
            print_error(f"An error occurred: {str(e)}")
            input("\nPress Enter to continue...")

if __name__ == "__main__":
    main() 