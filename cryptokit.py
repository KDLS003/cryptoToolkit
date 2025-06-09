import os
import base64
import json
import time
from pathlib import Path
from typing import Optional, Dict, Any
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding, ec, ed25519
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import hmac
from password_utils import PasswordUtils, SecurityError
import sys

class CryptoKit:
    def __init__(self) -> None:
        self.backend = default_backend()
        self.rsa_keys = {}
        # Cross-platform secure data directory
        if sys.platform == "win32":
            self.data_dir = os.path.join(os.environ["LOCALAPPDATA"], "crypto_toolkit")
        else:
            self.data_dir = os.path.join(os.path.expanduser("~"), ".config", "crypto_toolkit")
        os.makedirs(self.data_dir, exist_ok=True)
        try:
            os.chmod(self.data_dir, 0o700)
        except Exception:
            pass  # On Windows, chmod may not work as expected
        self.key_file = os.path.join(self.data_dir, "crypto_keys.json")
        self.password_utils = PasswordUtils()
        self.load_keys()

    def load_keys(self) -> None:
        try:
            if os.path.exists(self.key_file):
                with open(self.key_file, 'r') as f:
                    self.rsa_keys = json.load(f)
        except Exception as e:
            print(f"Warning: Could not load saved keys: {e}")
            self.rsa_keys = {}

    def save_keys(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.key_file), exist_ok=True)
            with open(self.key_file, 'w') as f:
                json.dump(self.rsa_keys, f)
            try:
                os.chmod(self.key_file, 0o600)
            except Exception:
                pass
        except Exception as e:
            print(f"Warning: Could not save keys: {e}")

    def generate_aes_key(self, key_size: int = 256) -> bytes:
        return os.urandom(key_size // 8)

    def generate_rsa_keys(self, key_size: int = 2048):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=self.backend
        )
        public_key = private_key.public_key()
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

    def get_rsa_keys(self, key_id: str) -> Optional[Dict[str, Any]]:
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

    def aes_encrypt(self, data: bytes, key: bytes) -> bytes:
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return iv + encrypted_data

    def aes_decrypt(self, encrypted_data: bytes, key: bytes) -> bytes:
        iv = encrypted_data[:16]
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data

    def rsa_encrypt(self, data: bytes, public_key: Any) -> bytes:
        encrypted = public_key.encrypt(
            data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted

    def rsa_decrypt(self, encrypted_data: bytes, private_key: Any) -> bytes:
        decrypted = private_key.decrypt(
            encrypted_data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted

    def derive_key_from_password(self, password: str, salt: Optional[bytes] = None):
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

    def encrypt_file(self, file_path: str, password: str) -> str:
        file_path = os.path.abspath(file_path)
        with open(file_path, 'rb') as f:
            data = f.read()
        key, salt = self.derive_key_from_password(password)
        encrypted_data = self.aes_encrypt(data, key)
        output_dir = os.path.join(os.path.dirname(file_path), "encrypted")
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, f"{os.path.basename(file_path)}.encrypted")
        with open(output_path, 'wb') as f:
            f.write(salt + encrypted_data)
        return output_path

    def decrypt_file(self, encrypted_file_path: str, password: str) -> str:
        encrypted_file_path = os.path.abspath(encrypted_file_path)
        with open(encrypted_file_path, 'rb') as f:
            data = f.read()
        salt = data[:16]
        encrypted_data = data[16:]
        key, _ = self.derive_key_from_password(password, salt)
        decrypted_data = self.aes_decrypt(encrypted_data, key)
        output_dir = os.path.join(os.path.dirname(encrypted_file_path), "decrypted")
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, os.path.basename(encrypted_file_path).replace('.encrypted', ''))
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
        return output_path

    def sign_message(self, message: str, private_key: Any) -> bytes:
        signature = private_key.sign(
            message.encode(),
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, message: str, signature: bytes, public_key: Any) -> bool:
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

    def sign_file(self, file_path: str, private_key: Any) -> bytes:
        with open(file_path, 'rb') as f:
            data = f.read()
        signature = private_key.sign(
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        sig_file = file_path + '.sig'
        with open(sig_file, 'wb') as f:
            f.write(signature)
        return sig_file

    def verify_file_signature(self, file_path: str, signature_file: str, public_key: Any) -> bool:
        with open(file_path, 'rb') as f:
            data = f.read()
        with open(signature_file, 'rb') as f:
            signature = f.read()
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

    def view_signature_details(self, signature_file: str) -> Dict[str, Any]:
        with open(signature_file, 'rb') as f:
            signature = f.read()
        file_stats = os.stat(signature_file)
        details = {
            "Signature Size": f"{len(signature)} bytes",
            "File Size": f"{file_stats.st_size} bytes",
            "Created": time.ctime(file_stats.st_ctime),
            "Modified": time.ctime(file_stats.st_mtime),
            "Signature (Base64)": base64.b64encode(signature).decode(),
            "Signature (Hex)": signature.hex()
        }
        return details

    def hash_message(self, message: str, algorithm: str = 'sha256') -> str:
        digest = hashes.Hash(getattr(hashes, algorithm.upper())(), backend=self.backend)
        digest.update(message.encode())
        return digest.finalize()

    def hmac_message(self, message: str, key: bytes, algorithm: str = 'sha256') -> str:
        return hmac.new(key, message.encode(), getattr(hashes, algorithm.upper())().name).digest()

    def aes_encrypt_message(self, message: str, password: str) -> bytes:
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
        padded = padder.update(message.encode()) + padder.finalize()
        encrypted = encryptor.update(padded) + encryptor.finalize()
        return salt + iv + encrypted

    def aes_decrypt_message(self, encrypted: bytes, password: str) -> str:
        salt = encrypted[:16]
        iv = encrypted[16:32]
        ciphertext = encrypted[32:]
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
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        return (unpadder.update(padded) + unpadder.finalize()).decode(errors='ignore')

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

    def get_any_keys(self, key_id: str) -> Optional[Dict[str, Any]]:
        if key_id not in self.rsa_keys:
            return None
        keys = self.rsa_keys[key_id]
        key_type = keys.get('type', 'rsa')
        private_key = serialization.load_pem_private_key(
            keys['private'].encode(), password=None, backend=self.backend)
        public_key = serialization.load_pem_public_key(
            keys['public'].encode(), backend=self.backend)
        return {'private': private_key, 'public': public_key, 'type': key_type}

    def ecdsa_sign_message(self, message: str, private_key: Any) -> bytes:
        return private_key.sign(
            message.encode(),
            ec.ECDSA(hashes.SHA256())
        )

    def ecdsa_verify_signature(self, message: str, signature: bytes, public_key: Any) -> bool:
        try:
            public_key.verify(
                signature,
                message.encode(),
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception:
            return False

    def ed25519_sign_message(self, message: str, private_key: Any) -> bytes:
        return private_key.sign(message.encode())

    def ed25519_verify_signature(self, message: str, signature: bytes, public_key: Any) -> bool:
        try:
            public_key.verify(signature, message.encode())
            return True
        except Exception:
            return False

    def hybrid_encrypt_file(self, file_path: str, rsa_public_key: Any):
        with open(file_path, 'rb') as f:
            data = f.read()
        aes_key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        encrypted_key = rsa_public_key.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_key, iv, encrypted_data

    def hybrid_decrypt_file(self, encrypted_file_path: str, rsa_private_key: Any):
        with open(encrypted_file_path, 'rb') as f:
            data = f.read()
        key_len = int.from_bytes(data[:2], 'big')
        encrypted_key = data[2:2+key_len]
        iv = data[2+key_len:2+key_len+16]
        encrypted_data = data[2+key_len+16:]
        aes_key = rsa_private_key.decrypt(
            encrypted_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data

    def export_key(self, key_id: str, key_type: str, is_private: bool, export_path: str, password: Optional[str] = None) -> None:
        keys = self.rsa_keys.get(key_id)
        if not keys:
            raise ValueError("Key ID not found.")
        if is_private:
            key_data = keys['private'].encode()
            if password:
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
                with open(export_path, 'wb') as f:
                    f.write(b'ENCKEY' + salt + iv + encrypted)
            else:
                with open(export_path, 'wb') as f:
                    f.write(key_data)
        else:
            key_data = keys['public'].encode()
            with open(export_path, 'wb') as f:
                f.write(key_data)

    def import_key(self, import_path: str, password: Optional[str] = None):
        with open(import_path, 'rb') as f:
            data = f.read()
        if data.startswith(b'ENCKEY'):
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
            private_key = serialization.load_pem_private_key(key_data, password=None, backend=self.backend)
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
                'private': key_data.decode(),
                'public': public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()
            }
            self.save_keys()
            return key_id, key_type, True
        else:
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

    def get_vault_path(self) -> str:
        return os.path.join(self.data_dir, "password_vault.enc")

    def load_vault(self, master_password: str) -> Dict[str, str]:
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

    def save_vault(self, vault: Dict[str, str], master_password: str) -> None:
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
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass

    def add_password_to_vault(self, label: str, password: str, master_password: str) -> None:
        try:
            # Validate inputs
            self.password_utils.validate_vault_input(label, password)
            
            # Check rate limit
            self.password_utils.check_rate_limit(master_password)
            
            # Load and update vault
            vault = self.load_vault(master_password)
            vault[label] = password
            self.save_vault(vault, master_password)
        except SecurityError as e:
            raise e
        except Exception as e:
            self.password_utils.record_failed_attempt(master_password)
            raise e

    def get_password_from_vault(self, label: str, master_password: str) -> Optional[str]:
        try:
            # Check rate limit
            self.password_utils.check_rate_limit(master_password)
            
            # Get password
            vault = self.load_vault(master_password)
            return vault.get(label)
        except SecurityError as e:
            raise e
        except Exception as e:
            self.password_utils.record_failed_attempt(master_password)
            raise e

    def list_vault_labels(self, master_password: str) -> list:
        try:
            # Check rate limit
            self.password_utils.check_rate_limit(master_password)
            
            # List labels
            vault = self.load_vault(master_password)
            return list(vault.keys())
        except SecurityError as e:
            raise e
        except Exception as e:
            self.password_utils.record_failed_attempt(master_password)
            raise e

    def update_password_in_vault(self, label: str, new_password: str, master_password: str) -> None:
        try:
            # Validate inputs
            self.password_utils.validate_vault_input(label, new_password)
            
            # Check rate limit
            self.password_utils.check_rate_limit(master_password)
            
            # Update vault
            vault = self.load_vault(master_password)
            if label not in vault:
                raise ValueError("Label not found in vault.")
            vault[label] = new_password
            self.save_vault(vault, master_password)
        except SecurityError as e:
            raise e
        except Exception as e:
            self.password_utils.record_failed_attempt(master_password)
            raise e

    def delete_password_from_vault(self, label: str, master_password: str) -> None:
        try:
            # Check rate limit
            self.password_utils.check_rate_limit(master_password)
            
            # Delete from vault
            vault = self.load_vault(master_password)
            if label not in vault:
                raise ValueError("Label not found in vault.")
            del vault[label]
            self.save_vault(vault, master_password)
        except SecurityError as e:
            raise e
        except Exception as e:
            self.password_utils.record_failed_attempt(master_password)
            raise e

    def change_master_password(self, old_password: str, new_password: str) -> None:
        """Change the master password for the vault."""
        # Validate new password
        self.password_utils.validate_vault_input("master", new_password)
        # Load vault with old password
        try:
            vault = self.load_vault(old_password)
        except Exception:
            raise SecurityError("Old master password is incorrect.")
        # Save vault with new password
        self.save_vault(vault, new_password) 