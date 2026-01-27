# CybS3

A secure, command-line S3-compatible object storage browser and file transfer tool, written in pure Swift.

**CybS3** distinguishes itself with robust **Client-Side Encryption** and **Secure Vault Management** derived from BIP39 Mnemonics. It is designed to work with any S3-compatible provider (AWS, MinIO, Ceph, Google Cloud Storage, etc.).

## Features

- **Standard S3 Operations**:
  - `ls`: List objects (supports prefixes).
  - `list`: List all buckets.
  - `mb`: Make (create) a bucket.
  - `put`: Upload files (automatically encrypted).
  - `get`: Download files (automatically decrypted).
  - `delete`: Delete objects.
  
- **Security & Encryption**:
  - **BIP39 Mnemonic Support**: Uses standard 12-word recovery phrases as the root of trust.
  - **Client-Side Encryption**: Files are encrypted **before** leaving your machine using AES-GCM (Streaming). You own the keys, not the cloud provider.
  - **Secure Vaults**: Store credentials (Access/Secret keys, Endpoints) in an encrypted local vault (`~/.cybs3/config.enc`), protected by your mnemonic.
  - **Key Rotation**: Rotate your Mnemonic (Master Key) without re-encrypting all your data (uses a preserved internal Data Key).
  - **Zero-Knowledge**: Your mnemonic is never stored in plain text. It is required purely in memory for operations.

## Architecture

CybS3 is built using modern Swift technologies:
- **Language**: Swift 6.2+
- **CLI**: `swift-argument-parser` for robust command-line interaction.
- **Networking**: `async-http-client` (built on SwiftNIO) for high-performance, non-blocking I/O.
- **Cryptography**: `swift-crypto` (BoringSSL) for standard compliant cryptographic primitives.

### Encryption Design

CybS3 uses a **two-tier encryption architecture**:

1.  **Master Key**: Derived from your personal **BIP39 Mnemonic** (using PBKDF2-HMAC-SHA512 + HKDF). This key wraps (encrypts) the local configuration file.
2.  **Data Key**: A random 256-bit symmetric key stored *inside* the encrypted configuration. This key is used to encrypt/decrypt your actual files on S3.

**Why this matters?**
This distinction allows you to use the `keys rotate` command to change your Mnemonic (e.g., if you suspect it was compromised) *without* needing to download and re-encrypt terabytes of data stored on S3. Depending on the operation, CybS3 simply re-encrypts the Data Key with your new Mnemonic.

## Installation

### Prerequisites
- macOS 12.0+ (Tested)
- Swift 6.2 toolchain

### Build from Source

```bash
git clone https://github.com/cybou-fr/CybS3.git
cd CybS3
swift build -c release
# Optional: Install to /usr/local/bin
cp .build/release/cybs3 /usr/local/bin/
```

## Usage

### 1. Key Management
Everything starts with a key.

**Generate a new Mnemonic:**
```bash
cybs3 keys create
```
*Output: A 12-word phrase. Write this down and keep it safe!*

**Validate a Mnemonic:**
```bash
cybs3 keys validate "word1 word2 ... word12"
```

**Rotate Mnemonic (Change Password):**
```bash
cybs3 keys rotate
```
*Follow the prompts to authenticate with the old phrase and generate/set a new one.*

### 2. Vault Management
Manage different S3 environments (e.g., "Personal", "Work", "Archive") securely.

**Add a Vault:**
```bash
cybs3 vaults add --name AWS-Production
# Prompts for Entity Endpoint, Access Key, Secret Key, etc.
```

**List Vaults:**
```bash
cybs3 vaults list
```

**Select a Vault (Make Active):**
```bash
cybs3 vaults select AWS-Production
```
*This sets the global context for subsequent `put`/`get` commands.*

**Delete a Vault:**
```bash
cybs3 vaults delete AWS-Production
```

### 3. File Operations
Once a vault is selected, operations are simple. The tool will ask for your Mnemonic to unlock the session.

**Upload (Encrypt):**
```bash
cybs3 put ./my-secret-backup.zip
# or with custom key
cybs3 put ./my-secret-backup.zip --key backup/2023/january.zip
```
*The file is encrypted in 1MB chunks on the fly.*

**Download (Decrypt):**
```bash
cybs3 get backup/2023/january.zip
# or to specific path
cybs3 get backup/2023/january.zip --output ./restore.zip
```

**Listing Objects:**
```bash
# List all objects
cybs3 ls

# List with prefix (folder)
cybs3 ls backup/2023/
```

### 4. Direct Configuration (Advanced)
If you prefer not to use named vaults, you can configure the active settings directly:
```bash
cybs3 config --endpoint s3.us-east-1.amazonaws.com --bucket my-bucket
```

## Security Technical Details
- **Key Derivation**: PBKDF2 (2048 rounds) -> HKDF-SHA256.
- **Config Encryption**: AES-GCM (256-bit).
- **File Encryption**: AES-GCM (256-bit) in streaming mode. Each 1MB chunk has a unique nonce.
- **Configuration Path**: `~/.cybs3/config.enc` (Permissions set to `600`).

## License
MIT