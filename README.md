# Crypto Toolkit

A comprehensive Python-based cryptography toolkit developed as a side project by me. This project demonstrates practical implementation of various cryptographic concepts and secure data handling techniques.

## Features

### Encryption
- AES-256 encryption (text and files)
- RSA-2048 encryption
- Password-based key derivation
- Secure key storage

### Digital Signatures
- RSA message signing
- File signing
- Signature verification
- Signature details viewer

### Security
- Secure random number generation
- Password-based key derivation
- Safe file handling
- Input validation

### User Interface
- Clean CLI with colors
- Progress indicators
- Clear error messages
- Easy-to-use menu

## Getting Started

### Requirements
- Python 3.8+
- Required packages in `requirements.txt`

### Install
```bash
git clone https://github.com/yourusername/crypto-toolkit.git
cd crypto-toolkit
pip install -r requirements.txt
```

### Run
```bash
python crypto_toolkit.py
```

## Menu Options

### Key Management
1. Generate AES Key
2. Generate RSA Keys
3. List Saved Keys

### Text Operations
4. Encrypt Text (AES)
5. Decrypt Text (AES)
6. Encrypt Text (RSA)
7. Decrypt Text (RSA)

### Digital Signatures
8. Sign Message
9. Verify Signature
10. Sign File
11. Verify File Signature
12. View Signature Details

### File Operations
13. Encrypt File (AES)
14. Decrypt File (AES)

## How It Works

### AES Encryption
- Uses AES-256 in CBC mode
- PKCS7 padding
- Random IV generation
- PBKDF2 key derivation

### RSA Encryption
- 2048-bit keys
- OAEP padding with SHA-256
- PEM format key storage
- Secure key management

### Digital Signatures
- RSA-PSS with SHA-256
- File and message signing
- Signature verification
- Signature details viewer

## Author

- **YNK** - *3rd Year Cybersecurity Student*

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 
