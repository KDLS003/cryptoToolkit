from cryptokit import CryptoKit
from stegokit import StegoKit
from ui import UI
import base64
import os
from colorama import Fore, Style

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
    "6": [("1", "Hide Message in Image"), ("2", "Reveal Message from Image"), ("3", "Hide Message in Audio (WAV)"), ("4", "Reveal Message from Audio (WAV)"), ("5", "Hide Message in Video"), ("6", "Reveal Message from Video")],
    "7": [("1", "Generate ECDSA Keys"), ("2", "Generate Ed25519 Keys"), ("3", "Sign Message (ECDSA)"), ("4", "Verify Signature (ECDSA)"), ("5", "Sign Message (Ed25519)"), ("6", "Verify Signature (Ed25519)")],
    "8": [("1", "Hybrid Encrypt File (AES+RSA)"), ("2", "Hybrid Decrypt File (AES+RSA)")],
    "9": [("1", "Export Key to File"), ("2", "Import Key from File")],
    "10": [("1", "Add Password to Vault"), ("2", "Retrieve Password from Vault"), ("3", "List Password Labels in Vault"), ("4", "Update Password in Vault"), ("5", "Delete Password from Vault")],
    "11": [("1", "Exit")],
}

def add_back_help_exit_to_submenus(sub_menus):
    for key in sub_menus:
        sub_menus[key] = [item for item in sub_menus[key] if item[0] not in ("0", "H", "Q")]
        sub_menus[key].append(("0", "Back"))
        sub_menus[key].append(("H", "Help / About"))
        sub_menus[key].append(("Q", "Exit"))
add_back_help_exit_to_submenus(sub_menus)

def print_full_help():
    UI.clear_screen()
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'CRYPTO TOOLKIT - FULL HELP & USER GUIDE'.center(60)}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    print(f"{Fore.YELLOW}Welcome to the Crypto Toolkit!{Style.RESET_ALL} This toolkit provides a wide range of cryptography and steganography tools for both learning and practical use.\n")
    print(f"{Fore.MAGENTA}Navigation:{Style.RESET_ALL}")
    print(f"  - Use the {Fore.GREEN}number keys{Style.RESET_ALL} to select menu options.")
    print(f"  - In any menu, enter {Fore.YELLOW}'0'{Style.RESET_ALL} for {Fore.YELLOW}Back{Style.RESET_ALL}, {Fore.YELLOW}'H'{Style.RESET_ALL} for {Fore.YELLOW}Help{Style.RESET_ALL}, or {Fore.RED}'Q'{Style.RESET_ALL} to {Fore.RED}Exit{Style.RESET_ALL}.")
    print(f"  - Prompts will guide you for required input. Press {Fore.GREEN}Enter{Style.RESET_ALL} to confirm.")
    print(f"\n{Fore.MAGENTA}Main Features:{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}1. Key Management:{Style.RESET_ALL} Generate, list, export, and import cryptographic keys ({Fore.YELLOW}AES, RSA, ECDSA, Ed25519{Style.RESET_ALL}).\n")
    print(f"  {Fore.CYAN}2. Text Operations:{Style.RESET_ALL} Encrypt and decrypt text using {Fore.YELLOW}AES{Style.RESET_ALL} (password-based) or {Fore.YELLOW}RSA{Style.RESET_ALL} (public key).\n")
    print(f"  {Fore.CYAN}3. Digital Signatures:{Style.RESET_ALL} Sign and verify messages and files using {Fore.YELLOW}RSA, ECDSA, or Ed25519{Style.RESET_ALL}.\n")
    print(f"  {Fore.CYAN}4. File Operations:{Style.RESET_ALL} Encrypt and decrypt files using {Fore.YELLOW}AES{Style.RESET_ALL}.\n")
    print(f"  {Fore.CYAN}5. Hash & HMAC:{Style.RESET_ALL} Create {Fore.YELLOW}hashes{Style.RESET_ALL} and {Fore.YELLOW}HMACs{Style.RESET_ALL} for messages.\n")
    print(f"  {Fore.CYAN}6. Steganography:{Style.RESET_ALL} Hide or reveal messages in {Fore.YELLOW}images, audio, or video files{Style.RESET_ALL}, with optional password protection.\n")
    print(f"  {Fore.CYAN}7. Elliptic Curve & Ed25519:{Style.RESET_ALL} Generate and use {Fore.YELLOW}ECDSA/Ed25519{Style.RESET_ALL} keys for signatures.\n")
    print(f"  {Fore.CYAN}8. Hybrid Encryption:{Style.RESET_ALL} Encrypt files using a combination of {Fore.YELLOW}AES and RSA{Style.RESET_ALL}.\n")
    print(f"  {Fore.CYAN}9. Key Management (Import/Export):{Style.RESET_ALL} Export or import keys to/from files.\n")
    print(f"  {Fore.CYAN}10. Password Manager:{Style.RESET_ALL} Store, retrieve, update, and delete passwords in a secure vault.\n")
    print(f"\n{Fore.MAGENTA}Usage Tips:{Style.RESET_ALL}")
    print(f"- Always remember your {Fore.YELLOW}passwords{Style.RESET_ALL} and {Fore.YELLOW}key IDs{Style.RESET_ALL}. Losing them may make decryption or recovery impossible.")
    print(f"- For file encryption, the output is saved in an {Fore.GREEN}'encrypted'{Style.RESET_ALL} or {Fore.GREEN}'decrypted'{Style.RESET_ALL} folder next to your file.")
    print(f"- For steganography, use {Fore.YELLOW}lossless formats{Style.RESET_ALL} ({Fore.GREEN}PNG{Style.RESET_ALL} for images, {Fore.GREEN}WAV{Style.RESET_ALL} for audio) for best results.")
    print(f"- You can use the {Fore.CYAN}Password Manager{Style.RESET_ALL} to safely store credentials, protected by a master password.")
    print(f"\n{Fore.MAGENTA}Example Workflows:{Style.RESET_ALL}")
    print(f"- {Fore.CYAN}Encrypt a file:{Style.RESET_ALL} 4 > 1, then provide the file path and password.")
    print(f"- {Fore.CYAN}Hide a message in an image:{Style.RESET_ALL} 6 > 1, then provide the image path, message, and output path.")
    print(f"- {Fore.CYAN}Sign a message:{Style.RESET_ALL} 3 > 1, then enter your message. Save the Key ID for verification.")
    print(f"- {Fore.CYAN}Retrieve a password:{Style.RESET_ALL} 10 > 2, then enter the label and master password.\n")
    print(f"{Fore.MAGENTA}Security Notes:{Style.RESET_ALL}")
    print(f"- All cryptographic operations use {Fore.GREEN}strong, modern algorithms{Style.RESET_ALL} ({Fore.YELLOW}AES-256, RSA-2048+, PBKDF2{Style.RESET_ALL}, etc.).")
    print(f"- Private keys and vaults are stored {Fore.YELLOW}encrypted{Style.RESET_ALL} on disk when a password is provided.")
    print(f"- {Fore.RED}Never share your private keys or master password.{Style.RESET_ALL}\n")
    print(f"For more details, see the {Fore.CYAN}README{Style.RESET_ALL} or the source code.\n")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    input(f"{Fore.GREEN}Press Enter to return to the previous menu...{Style.RESET_ALL}")

class CryptoToolkitApp:
    def __init__(self) -> None:
        self.crypto = CryptoKit()
        self.stego = StegoKit()
        self.ui = UI
        self.show_steps = False

    def prompt_educational_mode(self):
        self.ui.print_header()
        print(f"{Fore.MAGENTA}Would you like to enable Educational Mode?{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Educational Mode will show step-by-step explanations and real-world meaning for each operation.{Style.RESET_ALL}")
        choice = self.ui.get_input("Enable Educational Mode? (y/n): ").lower()
        self.show_steps = choice.startswith('y')

    def explain(self, operation: str, output: str = "", **kwargs):
        if not self.show_steps:
            return
        explanations = {
            'aes_key': f"""
{Fore.CYAN}Step 1: Generating a random AES key{Style.RESET_ALL}
- AES (Advanced Encryption Standard) is a symmetric encryption algorithm, meaning the same key is used for both encryption and decryption.
- The key is generated using a secure random number generator.
- {Fore.YELLOW}Keep this key secret! Anyone with this key can decrypt your data.{Style.RESET_ALL}

{Fore.GREEN}Output Explanation:{Style.RESET_ALL}
- The output is your AES key, shown in Base64 for easy copying. You will need this key (and the salt, if using password-based encryption) to decrypt any data you encrypt with it.
            """,
            'rsa_keys': f"""
{Fore.CYAN}Step 1: Generating an RSA key pair{Style.RESET_ALL}
- RSA is an asymmetric encryption algorithm, using a public/private key pair.
- The private key is kept secret and used for decryption/signing.
- The public key can be shared and is used for encryption/verification.
- Keys are generated securely and saved for later use.

{Fore.GREEN}Output Explanation:{Style.RESET_ALL}
- The Key ID is a unique identifier for your key pair. Use it to reference your keys for encryption, decryption, or signing.
- {Fore.YELLOW}Never share your private key! Only share the public key.{Style.RESET_ALL}
            """,
            'ecdsa_keys': f"""
{Fore.CYAN}Step 1: Generating an ECDSA key pair{Style.RESET_ALL}
- ECDSA (Elliptic Curve Digital Signature Algorithm) is used for digital signatures.
- Like RSA, it uses a public/private key pair, but is more efficient and secure for the same key size.

{Fore.GREEN}Output Explanation:{Style.RESET_ALL}
- The Key ID is your reference for this key pair. Use it for signing and verifying messages/files.
            """,
            'ed25519_keys': f"""
{Fore.CYAN}Step 1: Generating an Ed25519 key pair{Style.RESET_ALL}
- Ed25519 is a modern, fast, and secure digital signature algorithm.
- It is widely used in modern cryptographic systems (e.g., SSH, OpenSSH, Signal).

{Fore.GREEN}Output Explanation:{Style.RESET_ALL}
- The Key ID is your reference for this key pair. Use it for signing and verifying messages/files.
            """,
            'list_keys': f"""
{Fore.CYAN}Step 1: Listing all saved keys{Style.RESET_ALL}
- This shows all key pairs you have generated or imported.
- Use the Key ID to select a key for encryption, decryption, or signing.
            """,
            'export_key': f"""
{Fore.CYAN}Step 1: Exporting a key to a file{Style.RESET_ALL}
- You can export your public or private key to a file for backup or sharing.
- Private keys can be encrypted with a password for extra security.

{Fore.GREEN}Output Explanation:{Style.RESET_ALL}
- The exported file contains your key in PEM format (or encrypted PEM for private keys).
- {Fore.YELLOW}Keep private key files secure!{Style.RESET_ALL}
            """,
            'import_key': f"""
{Fore.CYAN}Step 1: Importing a key from a file{Style.RESET_ALL}
- You can import a public or private key from a PEM file (optionally encrypted).
- Imported keys are added to your key list with a new Key ID.
            """,
            'aes_encrypt': f"""
{Fore.CYAN}Step 1: Encrypting data with AES{Style.RESET_ALL}
- Your data is padded (if needed) and encrypted using the AES algorithm in CBC mode.
- A random IV (Initialization Vector) is used for each encryption for extra security.
- If using a password, a salt is generated and used with PBKDF2 to derive the key.

{Fore.GREEN}Output Explanation:{Style.RESET_ALL}
- The output is the encrypted data (Base64) and the salt (Base64, if password-based).
- You will need both to decrypt the data later.
            """,
            'aes_decrypt': f"""
{Fore.CYAN}Step 1: Decrypting data with AES{Style.RESET_ALL}
- The encrypted data is decrypted using the same key and IV used for encryption.
- If a password was used, the salt is required to derive the key.

{Fore.GREEN}Output Explanation:{Style.RESET_ALL}
- The output is the original plaintext data, restored from the encrypted form.
            """,
            'rsa_encrypt': f"""
{Fore.CYAN}Step 1: Encrypting data with RSA{Style.RESET_ALL}
- The plaintext is encrypted using the recipient's public key.
- Only the holder of the matching private key can decrypt it.

{Fore.GREEN}Output Explanation:{Style.RESET_ALL}
- The output is the encrypted data (Base64). Share this with the recipient, who will use their private key to decrypt it.
            """,
            'rsa_decrypt': f"""
{Fore.CYAN}Step 1: Decrypting data with RSA{Style.RESET_ALL}
- The encrypted data is decrypted using your private key.
- Only you (the private key holder) can decrypt data sent to you.

{Fore.GREEN}Output Explanation:{Style.RESET_ALL}
- The output is the original plaintext data.
            """,
            'signature': f"""
{Fore.CYAN}Step 1: Signing a message or file{Style.RESET_ALL}
- The message or file is hashed, and the hash is signed with your private key.
- This proves you (the key holder) created the message/file and that it hasn't been changed.

{Fore.GREEN}Output Explanation:{Style.RESET_ALL}
- The output is a digital signature (Base64). Share it with your message/file for verification.
            """,
            'verify_signature': f"""
{Fore.CYAN}Step 1: Verifying a digital signature{Style.RESET_ALL}
- The signature is checked against the message/file and the public key.
- If valid, the message/file is authentic and unchanged.

{Fore.GREEN}Output Explanation:{Style.RESET_ALL}
- The result tells you if the signature is valid (authentic) or not.
            """,
            'hash': f"""
{Fore.CYAN}Step 1: Hashing a message{Style.RESET_ALL}
- The message is processed with a cryptographic hash function (e.g., SHA-256).
- The output (digest) uniquely represents the message and is used for integrity checks.

{Fore.GREEN}Output Explanation:{Style.RESET_ALL}
- The output is the hash (digest) in Base64. Even a tiny change in the message will produce a different hash.
            """,
            'hmac': f"""
{Fore.CYAN}Step 1: Creating an HMAC{Style.RESET_ALL}
- HMAC (Hash-based Message Authentication Code) combines a secret key and a hash function.
- It is used to verify both the integrity and authenticity of a message.

{Fore.GREEN}Output Explanation:{Style.RESET_ALL}
- The output is the HMAC in Base64. Only someone with the same key can verify it.
            """,
            'steg_hide': f"""
{Fore.CYAN}Step 1: Hiding a message in a file (Steganography){Style.RESET_ALL}
- The message is optionally encrypted with a password, then hidden in the least significant bits of the file (image/audio/video).
- Only someone who knows the method (and password, if set) can extract it.

{Fore.GREEN}Output Explanation:{Style.RESET_ALL}
- The output is the file with the hidden message. Share it with others, but keep the password secret if used.
            """,
            'steg_reveal': f"""
{Fore.CYAN}Step 1: Revealing a hidden message (Steganography){Style.RESET_ALL}
- The file is scanned for hidden data. If a password was used, it is required to decrypt the message.

{Fore.GREEN}Output Explanation:{Style.RESET_ALL}
- The output is the extracted message. If it looks wrong, the password may be incorrect or the file may not contain a hidden message.
            """,
            'hybrid_encrypt': f"""
{Fore.CYAN}Step 1: Hybrid file encryption (AES + RSA){Style.RESET_ALL}
- The file is encrypted with a random AES key (fast, secure).
- The AES key is then encrypted with the recipient's RSA public key (secure key exchange).
- The result is a file that only the recipient (with the private key) can decrypt.

{Fore.GREEN}Output Explanation:{Style.RESET_ALL}
- The output is the hybrid-encrypted file. Share it with the recipient, who will use their private key to decrypt it.
            """,
            'hybrid_decrypt': f"""
{Fore.CYAN}Step 1: Hybrid file decryption (AES + RSA){Style.RESET_ALL}
- The AES key is decrypted with your RSA private key.
- The file is then decrypted with the AES key.

{Fore.GREEN}Output Explanation:{Style.RESET_ALL}
- The output is the original file, restored from the hybrid-encrypted form.
            """,
            'vault_add': f"""
{Fore.CYAN}Step 1: Adding a password to the vault{Style.RESET_ALL}
- The password is stored in an encrypted vault, protected by your master password.
- Only you (with the master password) can retrieve or update it.

{Fore.GREEN}Output Explanation:{Style.RESET_ALL}
- The password is now securely stored. Use the label to retrieve it later.
            """,
            'vault_get': f"""
{Fore.CYAN}Step 1: Retrieving a password from the vault{Style.RESET_ALL}
- The vault is decrypted with your master password.
- The password for the given label is retrieved.

{Fore.GREEN}Output Explanation:{Style.RESET_ALL}
- The output is your stored password for the label.
            """,
            'vault_list': f"""
{Fore.CYAN}Step 1: Listing all password labels in the vault{Style.RESET_ALL}
- The vault is decrypted with your master password.
- All stored labels are shown.
            """,
            'vault_update': f"""
{Fore.CYAN}Step 1: Updating a password in the vault{Style.RESET_ALL}
- The vault is decrypted with your master password.
- The password for the label is updated and the vault is re-encrypted.
            """,
            'vault_delete': f"""
{Fore.CYAN}Step 1: Deleting a password from the vault{Style.RESET_ALL}
- The vault is decrypted with your master password.
- The password for the label is removed and the vault is re-encrypted.
            """,
        }
        if operation in explanations:
            print(explanations[operation])
        elif output:
            print(f"{Fore.YELLOW}{output}{Style.RESET_ALL}")

    def run(self) -> None:
        self.prompt_educational_mode()
        while True:
            self.ui.print_header()
            self.ui.print_section("MAIN MENU")
            for key, label in main_menu_groups:
                self.ui.print_instruction(f"{key}. {label}")
            self.ui.print_instruction("Q. Exit")
            self.ui.print_instruction("H. Help / About")
            choice = self.ui.get_input("Select a group: ").upper()
            if choice == "Q":
                self.ui.print_section("EXIT")
                self.ui.print_info_block("Thank you for using Crypto Toolkit!")
                break
            elif choice == "H":
                print_full_help()
                continue
            elif choice in sub_menus:
                while True:
                    self.ui.print_header()
                    self.ui.print_section(main_menu_groups[int(choice)-1][1].upper())
                    for subkey, sublabel in sub_menus[choice]:
                        self.ui.print_instruction(f"{subkey}. {sublabel}")
                    subchoice = self.ui.get_input("Select an option: ").upper()
                    if subchoice == "0":
                        break
                    elif subchoice == "H":
                        print_full_help()
                        continue
                    elif subchoice == "Q":
                        self.ui.print_section("EXIT")
                        self.ui.print_info_block("Thank you for using Crypto Toolkit!")
                        exit(0)
                    # Key Management
                    if choice == "1":
                        if subchoice == "1":
                            self.ui.print_header()
                            self.ui.print_section("GENERATE AES KEY")
                            self.ui.print_info_block(descriptions["1"])
                            key = self.crypto.generate_aes_key()
                            self.ui.print_success_block("AES Key generated successfully!")
                            self.ui.print_result("AES Key (Base64)", base64.b64encode(key).decode())
                            self.explain('aes_key')
                            input("\nPress Enter to continue...")
                        elif subchoice == "2":
                            self.ui.print_header()
                            self.ui.print_section("GENERATE RSA KEYS")
                            self.ui.print_info_block(descriptions["2"])
                            key_id, private_key, public_key = self.crypto.generate_rsa_keys()
                            self.ui.print_success_block("RSA Keys generated successfully!")
                            self.ui.print_result("Key ID", key_id)
                            self.explain('rsa_keys')
                            input("\nPress Enter to continue...")
                        elif subchoice == "3":
                            self.ui.print_header()
                            self.ui.print_section("GENERATE ECDSA KEYS")
                            self.ui.print_info_block(descriptions["21"])
                            key_id, private_key, public_key = self.crypto.generate_ecdsa_keys()
                            self.ui.print_success_block("ECDSA Keys generated successfully!")
                            self.ui.print_result("Key ID", key_id)
                            self.explain('ecdsa_keys')
                            input("\nPress Enter to continue...")
                        elif subchoice == "4":
                            self.ui.print_header()
                            self.ui.print_section("GENERATE ED25519 KEYS")
                            self.ui.print_info_block(descriptions["22"])
                            key_id, private_key, public_key = self.crypto.generate_ed25519_keys()
                            self.ui.print_success_block("Ed25519 Keys generated successfully!")
                            self.ui.print_result("Key ID", key_id)
                            self.explain('ed25519_keys')
                            input("\nPress Enter to continue...")
                        elif subchoice == "5":
                            self.ui.print_header()
                            self.ui.print_section("LIST SAVED KEYS")
                            self.ui.print_info_block(descriptions["3"])
                            if not self.crypto.rsa_keys:
                                self.ui.print_error_block("No saved keys found.")
                            else:
                                self.ui.print_success_block("Found saved keys:")
                                for key_id in self.crypto.rsa_keys:
                                    self.ui.print_result("Key ID", key_id)
                            self.explain('list_keys')
                            input("\nPress Enter to continue...")
                        elif subchoice == "6":
                            self.ui.print_header()
                            self.ui.print_section("EXPORT KEY TO FILE")
                            self.ui.print_info_block(descriptions["29"])
                            key_id = self.ui.get_input("Enter Key ID to export: ")
                            keys = self.crypto.rsa_keys.get(key_id)
                            if not keys:
                                self.ui.print_error_block("Key ID not found.")
                                input("\nPress Enter to continue...")
                                continue
                            is_private = self.ui.get_input("Export private key? (y/n): ").lower().startswith('y')
                            export_path = self.ui.get_input("Enter export file path: ")
                            password = None
                            if is_private:
                                pw_choice = self.ui.get_input("Encrypt private key with password? (y/n): ").lower().startswith('y')
                                if pw_choice:
                                    password = self.ui.get_input("Enter password for key encryption: ")
                            try:
                                self.crypto.export_key(key_id, keys.get('type', 'rsa'), is_private, export_path, password)
                                self.ui.print_success_block(f"Key exported successfully to {export_path}")
                                self.explain('export_key')
                            except Exception as e:
                                self.ui.print_error_block(f"Error exporting key: {str(e)}")
                            input("\nPress Enter to continue...")
                        elif subchoice == "7":
                            self.ui.print_header()
                            self.ui.print_section("IMPORT KEY FROM FILE")
                            self.ui.print_info_block(descriptions["30"])
                            import_path = self.ui.get_input("Enter key file path to import: ")
                            password = None
                            try:
                                with open(import_path, 'rb') as f:
                                    if f.read(6) == b'ENCKEY':
                                        password = self.ui.get_input("Enter password to decrypt private key: ")
                                key_id, key_type, is_private = self.crypto.import_key(import_path, password)
                                self.ui.print_success_block(f"Key imported successfully! Key ID: {key_id} (type: {key_type}, private: {is_private})")
                                self.explain('import_key')
                            except Exception as e:
                                self.ui.print_error_block(f"Error importing key: {str(e)}")
                            input("\nPress Enter to continue...")
                    # Text Operations
                    elif choice == "2":
                        if subchoice == "1":
                            self.ui.print_header()
                            self.ui.print_section("ENCRYPT TEXT (AES)")
                            self.ui.print_info_block(descriptions["4"])
                            text = self.ui.get_input("Enter text to encrypt: ")
                            password = self.ui.get_input("Enter password: ")
                            key, salt = self.crypto.derive_key_from_password(password)
                            encrypted = self.crypto.aes_encrypt(text.encode(), key)
                            self.ui.print_success_block("Text encrypted successfully!")
                            self.ui.print_result("Encrypted (Base64)", base64.b64encode(encrypted).decode())
                            self.ui.print_result("Salt (Base64)", base64.b64encode(salt).decode())
                            self.explain('aes_encrypt')
                            input("\nPress Enter to continue...")
                        elif subchoice == "2":
                            self.ui.print_header()
                            self.ui.print_section("DECRYPT TEXT (AES)")
                            self.ui.print_info_block(descriptions["5"])
                            encrypted = base64.b64decode(self.ui.get_input("Enter encrypted text (Base64): "))
                            password = self.ui.get_input("Enter password: ")
                            salt = base64.b64decode(self.ui.get_input("Enter salt (Base64): "))
                            key, _ = self.crypto.derive_key_from_password(password, salt)
                            decrypted = self.crypto.aes_decrypt(encrypted, key)
                            self.ui.print_success_block("Text decrypted successfully!")
                            self.ui.print_result("Decrypted text", decrypted.decode())
                            self.explain('aes_decrypt')
                            input("\nPress Enter to continue...")
                        elif subchoice == "3":
                            self.ui.print_header()
                            self.ui.print_section("ENCRYPT TEXT (RSA)")
                            self.ui.print_info_block(descriptions["6"])
                            text = self.ui.get_input("Enter text to encrypt: ")
                            key_id, private_key, public_key = self.crypto.generate_rsa_keys()
                            encrypted = self.crypto.rsa_encrypt(text.encode(), public_key)
                            self.ui.print_success_block("Text encrypted successfully!")
                            self.ui.print_result("Key ID (save this)", key_id)
                            self.ui.print_result("Encrypted (Base64)", base64.b64encode(encrypted).decode())
                            self.explain('rsa_encrypt')
                            input("\nPress Enter to continue...")
                        elif subchoice == "4":
                            self.ui.print_header()
                            self.ui.print_section("DECRYPT TEXT (RSA)")
                            self.ui.print_info_block(descriptions["7"])
                            encrypted = base64.b64decode(self.ui.get_input("Enter encrypted text (Base64): "))
                            key_id = self.ui.get_input("Enter Key ID: ")
                            keys = self.crypto.get_rsa_keys(key_id)
                            if not keys:
                                self.ui.print_error_block("Invalid Key ID")
                                input("\nPress Enter to continue...")
                                continue
                            decrypted = self.crypto.rsa_decrypt(encrypted, keys['private'])
                            self.ui.print_success_block("Text decrypted successfully!")
                            self.ui.print_result("Decrypted text", decrypted.decode())
                            self.explain('rsa_decrypt')
                            input("\nPress Enter to continue...")
                    # Digital Signatures
                    elif choice == "3":
                        if subchoice == "1":
                            self.ui.print_header()
                            self.ui.print_section("SIGN MESSAGE (RSA)")
                            self.ui.print_info_block(descriptions["8"])
                            message = self.ui.get_input("Enter message to sign: ")
                            key_id, private_key, public_key = self.crypto.generate_rsa_keys()
                            signature = self.crypto.sign_message(message, private_key)
                            self.ui.print_success_block("Message signed successfully!")
                            self.ui.print_result("Key ID (save this)", key_id)
                            self.ui.print_result("Signature (Base64)", base64.b64encode(signature).decode())
                            self.explain('signature')
                            input("\nPress Enter to continue...")
                        elif subchoice == "2":
                            self.ui.print_header()
                            self.ui.print_section("VERIFY SIGNATURE (RSA)")
                            self.ui.print_info_block(descriptions["9"])
                            message = self.ui.get_input("Enter original message: ")
                            signature = base64.b64decode(self.ui.get_input("Enter signature (Base64): "))
                            key_id = self.ui.get_input("Enter Key ID: ")
                            keys = self.crypto.get_rsa_keys(key_id)
                            if not keys:
                                self.ui.print_error_block("Invalid Key ID")
                                input("\nPress Enter to continue...")
                                continue
                            is_valid = self.crypto.verify_signature(message, signature, keys['public'])
                            if is_valid:
                                self.ui.print_success_block("Signature is valid!")
                            else:
                                self.ui.print_error_block("Signature is invalid!")
                            self.explain('verify_signature')
                            input("\nPress Enter to continue...")
                        elif subchoice == "3":
                            self.ui.print_header()
                            self.ui.print_section("SIGN FILE (RSA)")
                            self.ui.print_info_block(descriptions["10"])
                            file_path = self.ui.get_input("Enter file path to sign: ")
                            key_id, private_key, public_key = self.crypto.generate_rsa_keys()
                            sig_file = self.crypto.sign_file(file_path, private_key)
                            self.ui.print_success_block("File signed successfully!")
                            self.ui.print_result("Key ID (save this)", key_id)
                            self.ui.print_result("Signature file saved as", sig_file)
                            self.explain('signature')
                            input("\nPress Enter to continue...")
                        elif subchoice == "4":
                            self.ui.print_header()
                            self.ui.print_section("VERIFY FILE SIGNATURE (RSA)")
                            self.ui.print_info_block(descriptions["11"])
                            file_path = self.ui.get_input("Enter file path to verify: ")
                            sig_file = self.ui.get_input("Enter signature file path: ")
                            key_id = self.ui.get_input("Enter Key ID: ")
                            keys = self.crypto.get_rsa_keys(key_id)
                            if not keys:
                                self.ui.print_error_block("Invalid Key ID")
                                input("\nPress Enter to continue...")
                                continue
                            is_valid = self.crypto.verify_file_signature(file_path, sig_file, keys['public'])
                            if is_valid:
                                self.ui.print_success_block("File signature is valid!")
                            else:
                                self.ui.print_error_block("File signature is invalid!")
                            self.explain('verify_signature')
                            input("\nPress Enter to continue...")
                        elif subchoice == "5":
                            self.ui.print_header()
                            self.ui.print_section("VIEW SIGNATURE DETAILS")
                            self.ui.print_info_block(descriptions["12"])
                            sig_file = self.ui.get_input("Enter signature file path: ")
                            try:
                                details = self.crypto.view_signature_details(sig_file)
                                for k, v in details.items():
                                    self.ui.print_result(k, v)
                                self.explain('signature')
                            except Exception as e:
                                self.ui.print_error_block(f"Error: {str(e)}")
                            input("\nPress Enter to continue...")
                    # File Operations
                    elif choice == "4":
                        if subchoice == "1":
                            self.ui.print_header()
                            self.ui.print_section("ENCRYPT FILE (AES)")
                            self.ui.print_info_block(descriptions["13"])
                            file_path = self.ui.get_input("Enter file path to encrypt: ")
                            password = self.ui.get_input("Enter password: ")
                            try:
                                output_path = self.crypto.encrypt_file(file_path, password)
                                self.ui.print_success_block("File encrypted successfully!")
                                self.ui.print_result("Encrypted file saved as", output_path)
                                self.explain('aes_encrypt')
                            except Exception as e:
                                self.ui.print_error_block(f"Error encrypting file: {str(e)}")
                            input("\nPress Enter to continue...")
                        elif subchoice == "2":
                            self.ui.print_header()
                            self.ui.print_section("DECRYPT FILE (AES)")
                            self.ui.print_info_block(descriptions["14"])
                            file_path = self.ui.get_input("Enter encrypted file path: ")
                            password = self.ui.get_input("Enter password: ")
                            try:
                                output_path = self.crypto.decrypt_file(file_path, password)
                                self.ui.print_success_block("File decrypted successfully!")
                                self.ui.print_result("Decrypted file saved as", output_path)
                                self.explain('aes_decrypt')
                            except Exception as e:
                                self.ui.print_error_block(f"Error decrypting file: {str(e)}")
                            input("\nPress Enter to continue...")
                    # Hash & HMAC
                    elif choice == "5":
                        if subchoice == "1":
                            self.ui.print_header()
                            self.ui.print_section("HASH MESSAGE")
                            self.ui.print_info_block(descriptions["16"])
                            message = self.ui.get_input("Enter message to hash: ")
                            digest = self.crypto.hash_message(message)
                            self.ui.print_success_block("Message hashed successfully!")
                            self.ui.print_result("Digest (Base64)", base64.b64encode(digest).decode())
                            self.explain('hash')
                            input("\nPress Enter to continue...")
                        elif subchoice == "2":
                            self.ui.print_header()
                            self.ui.print_section("HMAC MESSAGE")
                            self.ui.print_info_block(descriptions["17"])
                            message = self.ui.get_input("Enter message: ")
                            key = self.ui.get_input("Enter key: ").encode()
                            hmac_val = self.crypto.hmac_message(message, key)
                            self.ui.print_success_block("HMAC generated successfully!")
                            self.ui.print_result("HMAC (Base64)", base64.b64encode(hmac_val).decode())
                            self.explain('hmac')
                            input("\nPress Enter to continue...")
                    # Steganography
                    elif choice == "6":
                        if subchoice == "1":
                            self.ui.print_header()
                            self.ui.print_section("HIDE MESSAGE IN IMAGE")
                            self.ui.print_info_block(descriptions["18"])
                            image_path = self.ui.get_input("Enter image file path: ")
                            message = self.ui.get_input("Enter message to hide: ")
                            output_path = self.ui.get_input("Enter output image file path: ")
                            password = self.ui.get_input("Enter password to encrypt message (leave blank for none): ", required=False)
                            try:
                                out = self.stego.steg_hide(image_path, message, output_path, password if password else None)
                                self.ui.print_success_block(f"Message hidden in image and saved as {out}")
                                self.explain('steg_hide')
                            except Exception as e:
                                self.ui.print_error_block(str(e))
                            input("\nPress Enter to continue...")
                        elif subchoice == "2":
                            self.ui.print_header()
                            self.ui.print_section("REVEAL MESSAGE FROM IMAGE")
                            self.ui.print_info_block(descriptions["19"])
                            image_path = self.ui.get_input("Enter image file path: ")
                            password = self.ui.get_input("Enter password to decrypt message (leave blank for none): ", required=False)
                            try:
                                message = self.stego.steg_reveal(image_path, password if password else None)
                                self.ui.print_success_block("Message revealed successfully!")
                                self.ui.print_result("Hidden Message", message)
                                self.explain('steg_reveal')
                            except Exception as e:
                                self.ui.print_error_block(str(e))
                            input("\nPress Enter to continue...")
                        elif subchoice == "3":
                            self.ui.print_header()
                            self.ui.print_section("HIDE MESSAGE IN AUDIO (WAV)")
                            self.ui.print_info_block("Hide a secret message inside a WAV audio file.")
                            audio_path = self.ui.get_input("Enter WAV audio file path: ")
                            message = self.ui.get_input("Enter message to hide: ")
                            output_path = self.ui.get_input("Enter output audio file path: ")
                            password = self.ui.get_input("Enter password to encrypt message (leave blank for none): ", required=False)
                            try:
                                out = self.stego.audio_steg_hide(audio_path, message, output_path, password if password else None)
                                self.ui.print_success_block(f"Message hidden in audio and saved as {out}")
                                self.explain('steg_hide')
                            except Exception as e:
                                self.ui.print_error_block(str(e))
                            input("\nPress Enter to continue...")
                        elif subchoice == "4":
                            self.ui.print_header()
                            self.ui.print_section("REVEAL MESSAGE FROM AUDIO (WAV)")
                            self.ui.print_info_block("Reveal a hidden message from a WAV audio file.")
                            audio_path = self.ui.get_input("Enter WAV audio file path: ")
                            password = self.ui.get_input("Enter password to decrypt message (leave blank for none): ", required=False)
                            try:
                                message = self.stego.audio_steg_reveal(audio_path, password if password else None)
                                self.ui.print_success_block("Message revealed successfully!")
                                self.ui.print_result("Hidden Message", message)
                                self.explain('steg_reveal')
                            except Exception as e:
                                self.ui.print_error_block(str(e))
                            input("\nPress Enter to continue...")
                        elif subchoice == "5":
                            self.ui.print_header()
                            self.ui.print_section("HIDE MESSAGE IN VIDEO")
                            self.ui.print_info_block("Hide a secret message inside a video file (e.g., MP4, AVI).")
                            video_path = self.ui.get_input("Enter video file path: ")
                            message = self.ui.get_input("Enter message to hide: ")
                            output_path = self.ui.get_input("Enter output video file path: ")
                            password = self.ui.get_input("Enter password to encrypt message (leave blank for none): ", required=False)
                            try:
                                out = self.stego.video_steg_hide(video_path, message, output_path, password if password else None)
                                self.ui.print_success_block(f"Message hidden in video and saved as {out}")
                                self.explain('steg_hide')
                            except Exception as e:
                                self.ui.print_error_block(str(e))
                            input("\nPress Enter to continue...")
                        elif subchoice == "6":
                            self.ui.print_header()
                            self.ui.print_section("REVEAL MESSAGE FROM VIDEO")
                            self.ui.print_info_block("Reveal a hidden message from a video file (e.g., MP4, AVI).")
                            video_path = self.ui.get_input("Enter video file path: ")
                            password = self.ui.get_input("Enter password to decrypt message (leave blank for none): ", required=False)
                            try:
                                message = self.stego.video_steg_reveal(video_path, password if password else None)
                                self.ui.print_success_block("Message revealed successfully!")
                                self.ui.print_result("Hidden Message", message)
                                self.explain('steg_reveal')
                            except Exception as e:
                                self.ui.print_error_block(str(e))
                            input("\nPress Enter to continue...")
                    # Elliptic Curve & Ed25519
                    elif choice == "7":
                        if subchoice == "1":
                            self.ui.print_header()
                            self.ui.print_section("GENERATE ECDSA KEYS")
                            key_id, private_key, public_key = self.crypto.generate_ecdsa_keys()
                            self.ui.print_success_block("ECDSA Keys generated successfully!")
                            self.ui.print_result("Key ID", key_id)
                            self.explain('ecdsa_keys')
                            input("\nPress Enter to continue...")
                        elif subchoice == "2":
                            self.ui.print_header()
                            self.ui.print_section("GENERATE ED25519 KEYS")
                            key_id, private_key, public_key = self.crypto.generate_ed25519_keys()
                            self.ui.print_success_block("Ed25519 Keys generated successfully!")
                            self.ui.print_result("Key ID", key_id)
                            self.explain('ed25519_keys')
                            input("\nPress Enter to continue...")
                        elif subchoice == "3":
                            self.ui.print_header()
                            self.ui.print_section("SIGN MESSAGE (ECDSA)")
                            message = self.ui.get_input("Enter message to sign: ")
                            key_id = self.ui.get_input("Enter ECDSA Key ID: ")
                            keys = self.crypto.get_any_keys(key_id)
                            if not keys or keys['type'] != 'ecdsa':
                                self.ui.print_error_block("Invalid ECDSA Key ID.")
                                input("\nPress Enter to continue...")
                                continue
                            signature = self.crypto.ecdsa_sign_message(message, keys['private'])
                            self.ui.print_success_block("Message signed successfully!")
                            self.ui.print_result("Signature (Base64)", base64.b64encode(signature).decode())
                            self.explain('signature')
                            input("\nPress Enter to continue...")
                        elif subchoice == "4":
                            self.ui.print_header()
                            self.ui.print_section("VERIFY SIGNATURE (ECDSA)")
                            message = self.ui.get_input("Enter original message: ")
                            signature = base64.b64decode(self.ui.get_input("Enter signature (Base64): "))
                            key_id = self.ui.get_input("Enter ECDSA Key ID: ")
                            keys = self.crypto.get_any_keys(key_id)
                            if not keys or keys['type'] != 'ecdsa':
                                self.ui.print_error_block("Invalid ECDSA Key ID.")
                                input("\nPress Enter to continue...")
                                continue
                            is_valid = self.crypto.ecdsa_verify_signature(message, signature, keys['public'])
                            if is_valid:
                                self.ui.print_success_block("Signature is valid!")
                            else:
                                self.ui.print_error_block("Signature is invalid!")
                            input("\nPress Enter to continue...")
                        elif subchoice == "5":
                            self.ui.print_header()
                            self.ui.print_section("SIGN MESSAGE (ED25519)")
                            message = self.ui.get_input("Enter message to sign: ")
                            key_id = self.ui.get_input("Enter Ed25519 Key ID: ")
                            keys = self.crypto.get_any_keys(key_id)
                            if not keys or keys['type'] != 'ed25519':
                                self.ui.print_error_block("Invalid Ed25519 Key ID.")
                                input("\nPress Enter to continue...")
                                continue
                            signature = self.crypto.ed25519_sign_message(message, keys['private'])
                            self.ui.print_success_block("Message signed successfully!")
                            self.ui.print_result("Signature (Base64)", base64.b64encode(signature).decode())
                            self.explain('signature')
                            input("\nPress Enter to continue...")
                        elif subchoice == "6":
                            self.ui.print_header()
                            self.ui.print_section("VERIFY SIGNATURE (ED25519)")
                            message = self.ui.get_input("Enter original message: ")
                            signature = base64.b64decode(self.ui.get_input("Enter signature (Base64): "))
                            key_id = self.ui.get_input("Enter Ed25519 Key ID: ")
                            keys = self.crypto.get_any_keys(key_id)
                            if not keys or keys['type'] != 'ed25519':
                                self.ui.print_error_block("Invalid Ed25519 Key ID.")
                                input("\nPress Enter to continue...")
                                continue
                            is_valid = self.crypto.ed25519_verify_signature(message, signature, keys['public'])
                            if is_valid:
                                self.ui.print_success_block("Signature is valid!")
                            else:
                                self.ui.print_error_block("Signature is invalid!")
                            input("\nPress Enter to continue...")
                    # Hybrid Encryption
                    elif choice == "8":
                        if subchoice == "1":
                            self.ui.print_header()
                            self.ui.print_section("HYBRID ENCRYPT FILE (AES+RSA)")
                            file_path = self.ui.get_input("Enter file path to encrypt: ")
                            key_id = self.ui.get_input("Enter RSA Key ID for encryption: ")
                            keys = self.crypto.get_any_keys(key_id)
                            if not keys or keys['type'] != 'rsa':
                                self.ui.print_error_block("Invalid RSA Key ID.")
                                input("\nPress Enter to continue...")
                                continue
                            try:
                                encrypted_key, iv, encrypted_data = self.crypto.hybrid_encrypt_file(file_path, keys['public'])
                                key_len = len(encrypted_key)
                                output_dir = os.path.join(os.path.dirname(file_path), "hybrid_encrypted")
                                os.makedirs(output_dir, exist_ok=True)
                                output_path = os.path.join(output_dir, os.path.basename(file_path) + ".hybrid")
                                with open(output_path, 'wb') as f:
                                    f.write(key_len.to_bytes(2, 'big') + encrypted_key + iv + encrypted_data)
                                self.ui.print_success_block("File hybrid-encrypted successfully!")
                                self.ui.print_result("Hybrid Encrypted file saved as", output_path)
                                self.explain('hybrid_encrypt')
                            except Exception as e:
                                self.ui.print_error_block(f"Error during hybrid encryption: {str(e)}")
                            input("\nPress Enter to continue...")
                        elif subchoice == "2":
                            self.ui.print_header()
                            self.ui.print_section("HYBRID DECRYPT FILE (AES+RSA)")
                            file_path = self.ui.get_input("Enter hybrid encrypted file path: ")
                            key_id = self.ui.get_input("Enter RSA Key ID for decryption: ")
                            keys = self.crypto.get_any_keys(key_id)
                            if not keys or keys['type'] != 'rsa':
                                self.ui.print_error_block("Invalid RSA Key ID.")
                                input("\nPress Enter to continue...")
                                continue
                            try:
                                decrypted_data = self.crypto.hybrid_decrypt_file(file_path, keys['private'])
                                output_dir = os.path.join(os.path.dirname(file_path), "hybrid_decrypted")
                                os.makedirs(output_dir, exist_ok=True)
                                output_path = os.path.join(output_dir, os.path.basename(file_path).replace('.hybrid', ''))
                                with open(output_path, 'wb') as f:
                                    f.write(decrypted_data)
                                self.ui.print_success_block("File hybrid-decrypted successfully!")
                                self.ui.print_result("Hybrid Decrypted file saved as", output_path)
                                self.explain('hybrid_decrypt')
                            except Exception as e:
                                self.ui.print_error_block(f"Error during hybrid decryption: {str(e)}")
                            input("\nPress Enter to continue...")
                    # Key Management (Import/Export)
                    elif choice == "9":
                        if subchoice == "1":
                            self.ui.print_header()
                            self.ui.print_section("EXPORT KEY TO FILE")
                            key_id = self.ui.get_input("Enter Key ID to export: ")
                            keys = self.crypto.rsa_keys.get(key_id)
                            if not keys:
                                self.ui.print_error_block("Key ID not found.")
                                input("\nPress Enter to continue...")
                                continue
                            is_private = self.ui.get_input("Export private key? (y/n): ").lower().startswith('y')
                            export_path = self.ui.get_input("Enter export file path: ")
                            password = None
                            if is_private:
                                pw_choice = self.ui.get_input("Encrypt private key with password? (y/n): ").lower().startswith('y')
                                if pw_choice:
                                    password = self.ui.get_input("Enter password for key encryption: ")
                            try:
                                self.crypto.export_key(key_id, keys.get('type', 'rsa'), is_private, export_path, password)
                                self.ui.print_success_block(f"Key exported successfully to {export_path}")
                                self.explain('export_key')
                            except Exception as e:
                                self.ui.print_error_block(f"Error exporting key: {str(e)}")
                            input("\nPress Enter to continue...")
                        elif subchoice == "2":
                            self.ui.print_header()
                            self.ui.print_section("IMPORT KEY FROM FILE")
                            import_path = self.ui.get_input("Enter key file path to import: ")
                            password = None
                            try:
                                with open(import_path, 'rb') as f:
                                    if f.read(6) == b'ENCKEY':
                                        password = self.ui.get_input("Enter password to decrypt private key: ")
                                key_id, key_type, is_private = self.crypto.import_key(import_path, password)
                                self.ui.print_success_block(f"Key imported successfully! Key ID: {key_id} (type: {key_type}, private: {is_private})")
                                self.explain('import_key')
                            except Exception as e:
                                self.ui.print_error_block(f"Error importing key: {str(e)}")
                            input("\nPress Enter to continue...")
                    # Password Manager
                    elif choice == "10":
                        if subchoice == "1":
                            self.ui.print_header()
                            self.ui.print_section("ADD PASSWORD TO VAULT")
                            label = self.ui.get_input("Enter label for password: ")
                            password = self.ui.get_input("Enter password to store: ")
                            master_password = self.ui.get_input("Enter master password for vault: ")
                            try:
                                self.crypto.add_password_to_vault(label, password, master_password)
                                self.ui.print_success_block(f"Password for '{label}' added to vault.")
                                self.explain('vault_add')
                            except Exception as e:
                                self.ui.print_error_block(f"Error adding password: {str(e)}")
                            input("\nPress Enter to continue...")
                        elif subchoice == "2":
                            self.ui.print_header()
                            self.ui.print_section("RETRIEVE PASSWORD FROM VAULT")
                            label = self.ui.get_input("Enter label to retrieve: ")
                            master_password = self.ui.get_input("Enter master password for vault: ")
                            try:
                                password = self.crypto.get_password_from_vault(label, master_password)
                                if password is not None:
                                    self.ui.print_success_block(f"Password for '{label}': {password}")
                                    self.explain('vault_get')
                                else:
                                    self.ui.print_error_block(f"No password found for label '{label}'.")
                            except Exception as e:
                                self.ui.print_error_block(f"Error retrieving password: {str(e)}")
                            input("\nPress Enter to continue...")
                        elif subchoice == "3":
                            self.ui.print_header()
                            self.ui.print_section("LIST PASSWORD LABELS IN VAULT")
                            master_password = self.ui.get_input("Enter master password for vault: ")
                            try:
                                labels = self.crypto.list_vault_labels(master_password)
                                if labels:
                                    self.ui.print_success_block("Labels in vault:")
                                    for label in labels:
                                        self.ui.print_result("Label", label)
                                    self.explain('vault_list')
                                else:
                                    self.ui.print_info_block("No passwords stored in vault.")
                            except Exception as e:
                                self.ui.print_error_block(f"Error listing vault labels: {str(e)}")
                            input("\nPress Enter to continue...")
                        elif subchoice == "4":
                            self.ui.print_header()
                            self.ui.print_section("UPDATE PASSWORD IN VAULT")
                            label = self.ui.get_input("Enter label to update: ")
                            new_password = self.ui.get_input("Enter new password: ")
                            master_password = self.ui.get_input("Enter master password for vault: ")
                            try:
                                self.crypto.update_password_in_vault(label, new_password, master_password)
                                self.ui.print_success_block(f"Password for '{label}' updated in vault.")
                                self.explain('vault_update')
                            except Exception as e:
                                self.ui.print_error_block(f"Error updating password: {str(e)}")
                            input("\nPress Enter to continue...")
                        elif subchoice == "5":
                            self.ui.print_header()
                            self.ui.print_section("DELETE PASSWORD FROM VAULT")
                            label = self.ui.get_input("Enter label to delete: ")
                            master_password = self.ui.get_input("Enter master password for vault: ")
                            try:
                                self.crypto.delete_password_from_vault(label, master_password)
                                self.ui.print_success_block(f"Password for '{label}' deleted from vault.")
                                self.explain('vault_delete')
                            except Exception as e:
                                self.ui.print_error_block(f"Error deleting password: {str(e)}")
                            input("\nPress Enter to continue...")
                    # Other (Exit)
                    elif choice == "11" and subchoice == "1":
                        self.ui.print_section("EXIT")
                        self.ui.print_info_block("Thank you for using Crypto Toolkit!")
                        exit(0)
                    else:
                        self.ui.print_error_block("Invalid option. Please try again.")
            else:
                self.ui.print_error_block("Invalid group. Please try again.")

if __name__ == "__main__":
    app = CryptoToolkitApp()
    app.run() 