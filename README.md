# Crypto Toolkit ![version](https://img.shields.io/badge/version-2.0-blue)

A modular, object-oriented cryptography and steganography toolkit for educational and practical use.

---

## What's New in v2.0
- Full OOP refactor: code is now split into clear modules/classes
- Educational Mode: step-by-step explanations for every operation
- Color-coded, user-friendly CLI
- All test files organized in a `tests/` folder
- Improved help and onboarding
- Cleaner directory structure
- Expanded cryptography and steganography features
- See the repo for the full changelog

---

## Features
- Symmetric and asymmetric encryption (AES, RSA, ECDSA, Ed25519)
- Digital signatures and verification
- File and text encryption/decryption
- Steganography (hide/reveal messages in images, audio, video)
- Password manager (encrypted vault)
- Hybrid encryption (AES+RSA)
- Colorful, menu-driven CLI
- Educational mode with step-by-step explanations

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

## Usage

```sh
python main.py
```

## Example

```python
from cryptokit import CryptoKit
from stegokit import StegoKit

crypto = CryptoKit()
stego = StegoKit()

# Generate AES key
key = crypto.generate_aes_key()

# Encrypt a message
encrypted = crypto.aes_encrypt_message("Hello", "password123")

# Hide a message in an image
stego.steg_hide("input.png", "Secret", "output.png")
```

## Running Tests

```sh
python -m unittest discover tests
```

## Contributing

Pull requests are welcome! Please add tests for new features and follow the code style.

## License

MIT 