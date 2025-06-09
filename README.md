# Crypto Toolkit ![version](https://img.shields.io/badge/version-2.1-blue)

A modular, object-oriented cryptography and steganography toolkit for educational and practical use.

---

## What's New in v2.1
- **Expanded common password blacklist** for stronger password security.
- **Improved password strength checker**: now provides a detailed, user-friendly checklist in the CLI.
- **Password Manager UI**: shows a full password strength breakdown when adding, updating, or changing passwords.
- **Stricter file permissions** for all sensitive files and folders.
- **Data directory moved** to a more secure, less obvious location:
  - **Windows:** `%LOCALAPPDATA%\crypto_toolkit`
  - **Linux/macOS:** `~/.config/crypto_toolkit`
- **Bug fixes and usability improvements**.

---

## Features
- Symmetric and asymmetric encryption (AES, RSA, ECDSA, Ed25519)
- Digital signatures and verification
- File and text encryption/decryption
- Steganography (hide/reveal messages in images, audio, video)
- Password manager with enhanced security:
  - Password strength checking (with detailed feedback)
  - Rate limiting
  - Secure input
  - Input validation
  - Password history
  - **Change Master Password**
- Hybrid encryption (AES+RSA)
- Colorful, menu-driven CLI
- **Educational mode** with step-by-step explanations for all operations, including password management

## Security Notes
- **Sensitive files (keys, vault) are stored in:**
  - **Windows:** `%LOCALAPPDATA%\crypto_toolkit`
  - **Linux/macOS:** `~/.config/crypto_toolkit`
- **File permissions:**
  - The toolkit enforces strict permissions: only your user account can read/write these files (where supported by the OS).
- **Do not delete or move this folder unless you have a backup!**
- All vault and key files are encrypted at rest.
- If you forget your master password, you cannot recover your vault.

## Installation Guide

### 1. Install Python 3.8+
- **Windows:**
  - Download from [python.org](https://www.python.org/downloads/windows/)
  - During install, check "Add Python to PATH"
- **macOS:**
  - Use [Homebrew](https://brew.sh/):
    ```sh
    brew install python
    ```
  - Or download from [python.org](https://www.python.org/downloads/macos/)
- **Linux (Debian/Ubuntu):**
    ```sh
    sudo apt update
    sudo apt install python3 python3-pip python3-venv
    ```
- **Linux (Fedora):**
    ```sh
    sudo dnf install python3 python3-pip python3-virtualenv
    ```

### 2. Clone the Repository
```sh
git clone https://github.com/KDLS003/cryptoToolkit.git
cd cryptoToolkit
```

### 3. Create a Virtual Environment (Recommended)
```sh
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 4. Install Dependencies
```sh
pip install -r requirements.txt
```

#### Main dependencies:
- cryptography
- colorama
- pillow
- tqdm
- opencv-python

## Structure

- `cryptokit.py`: Cryptography, key management, digital signatures, hybrid encryption, password vault
- `stegokit.py`: Steganography (image, audio, video)
- `ui.py`: User interface, CLI, menu logic
- `main.py`: Entry point, application logic
- `password_utils.py`: Password security utilities

## Usage

```sh
python main.py
```

## Example

```python
from cryptokit import CryptoKit
from stegokit import StegoKit
from password_utils import PasswordUtils

crypto = CryptoKit()
stego = StegoKit()
password_utils = PasswordUtils()

# Generate AES key
key = crypto.generate_aes_key()

# Encrypt a message
encrypted = crypto.aes_encrypt_message("Hello", "password123")

# Hide a message in an image
stego.steg_hide("input.png", "Secret", "output.png")

# Check password strength (detailed)
print(password_utils.password_strength_checker("P@ssw0rd123!"))
```

**Sample Output:**
```
Password Strength: Strong

Criteria:
  ✓ At least 12 characters
  ✓ Contains uppercase letters
  ✓ Contains lowercase letters
  ✓ Contains numbers
  ✓ Contains special characters
  ✓ Not a common password
  ✓ No character repetition (3+ in a row)

Score: 7 / 7
Great! Your password is strong and meets all recommended criteria.
```

## Password Manager & Master Password
- The password vault is protected by a master password.
- **You can now change your master password from the Password Manager menu.**
- If you forget your master password, you must delete the vault file and start over (all stored passwords will be lost).
- All password manager operations now include educational explanations when Educational Mode is enabled.
- The password manager UI now provides a detailed checklist for password strength.

## Running Tests

```sh
python -m unittest discover test
```

## Contributing

Pull requests are welcome! Please add tests for new features and follow the code style.

## Author

- **YNK** - *3rd Year Cybersecurity Student*

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
