# CybS3

A command-line S3 compatible object storage browser and file transfer tool, written in pure Swift without AWS SDK dependencies.

It now features **Client-Side Encryption** and **Secure Vault Management** based on BIP39 Mnemonics.

## Features

- **S3 Operations**:
  - List buckets and objects (`ls`)
  - Upload/download files (`put`, `get`)
  - Create/delete objects (`put`, `delete`)
  - Create buckets (`mb`)
  - S3 v4 authentication
  - Works with any S3-compatible storage (AWS, MinIO, Ceph, etc.)

- **Security & Encryption**:
  - **BIP39 Mnemonic Support**: Generate and validate standardized 12-word recovery phrases.
  - **Secure Vaults**: Store your S3 credentials (access keys, secret keys, endpoints) in an encrypted local vault protected by your mnemonic.
  - **Transparent File Encryption**: files uploaded with `put` are automatically encrypted (AES-GCM) on-the-fly. Files downloaded with `get` are automatically decrypted.
  - **Zero-Knowledge**: Your mnemonic is never stored in plain text. It is required for every sensitive operation.

## Installation

### Build from source:

```bash
git clone <repository-url>
cd CybS3
swift build -c release
cp .build/release/cybs3 /usr/local/bin/
```

## Usage

### 1. Generate a Mnemonic
First, generate a secure mnemonic. You will need this to encrypt your vaults and files.
```bash
cybs3 keys create
```
*Save this phrase securely! If you lose it, you cannot recover your encrypted data.*

### 2. Configure a Vault
Instead of storing credentials in plain text, create an encrypted vault:
```bash
cybs3 vaults add --name MyProject
# Follow the prompts to enter credentials and your mnemonic.
```

### 3. Manage Vaults
List your encrypted vaults (requires mnemonic):
```bash
cybs3 vaults list
```

Select a vault to be the active configuration:
```bash
cybs3 vaults select MyProject
```

Delete a vault:
```bash
cybs3 vaults delete MyProject
```

### 4. Encrypted File Transfer
Once your vault is configured (or credentials set via environment variables), file operations are encrypted by default.

**Upload (Encrypt):**
```bash
cybs3 put large-file.zip
# Prompts for mnemonic -> Encrypts stream -> Uploads to S3
```

**Download (Decrypt):**
```bash
cybs3 get large-file.zip
# Prompts for mnemonic -> Downloads stream -> Decrypts
```

### 5. Standard S3 Commands
List buckets:
```bash
cybs3 list
```

List objects in a bucket:
```bash
cybs3 ls
```

Create a bucket:
```bash
cybs3 mb my-new-bucket
```

Delete an object:
```bash
cybs3 delete my-file.txt
```

## Security Details
- **Key Derivation**: Keys are derived from your BIP39 mnemonic using standard PBKDF2-HMAC-SHA512 (2048 rounds), followed by HKDF for specific sub-keys. This ensures stability and compatibility with standard BIP39 seeds.
- **Vault Encryption**: Vault configurations are stored in `~/.cybs3.vaults` encrypted with AES-GCM.
- **File Encryption**: Files are encrypted using streaming AES-GCM with 1MB chunk size, generating a unique nonce for each chunk.

## License
MIT