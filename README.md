# CybS3

A secure, command-line S3-compatible object storage browser and file transfer tool, written in pure Swift.

**CybS3** distinguishes itself with robust **Client-Side Encryption** and **Secure Vault Management** derived from BIP39 Mnemonics. It is designed to work with any S3-compatible provider (AWS, MinIO, Ceph, Google Cloud Storage, etc.).

## Features

- **Standard S3 Operations**:
  - `files list`: List objects (supports prefixes).
  - `buckets list`: List all buckets.
  - `buckets create`: Make (create) a bucket.
  - `files put`: Upload files (automatically encrypted, with progress bar).
  - `files get`: Download files (automatically decrypted, with progress bar).
  - `files delete`: Delete objects.

- **Folder Operations** (NEW):
  - `folders put`: Upload entire folders recursively with **smart deduplication** (only uploads new/changed files).
  - `folders get`: Download entire folders recursively.
  - `folders sync`: Synchronize local folder with S3 (with optional `--delete` for remote cleanup).
  - `folders watch`: **Live watch mode** - automatically upload changes as files are modified.
  
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

### Running Tests
To run the automated test suite:
```bash
swift test
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
*This sets the global context for subsequent `files put`/`files get` commands.*

**Delete a Vault:**
```bash
cybs3 vaults delete AWS-Production
```

### 3. File Operations
Once a vault is selected, operations are simple. The tool will ask for your Mnemonic to unlock the session.

**Upload (Encrypt):**
```bash
cybs3 files put ./my-secret-backup.zip
# or with custom key (positional argument)
cybs3 files put ./my-secret-backup.zip backup/2023/january.zip
```
*The file is encrypted in 1MB chunks on the fly. A progress bar shows the status.*

**Download (Decrypt):**
```bash
cybs3 files get backup/2023/january.zip
# or to specific path
cybs3 files get backup/2023/january.zip ./restore.zip
```

**Delete Object:**
```bash
# Interactive (asks for confirmation)
cybs3 files delete backup/2023/january.zip
# Non-interactive (force delete)
cybs3 files delete backup/2023/january.zip --force
```

**Listing Objects:**
```bash
# List all objects
cybs3 files list

# List with prefix (folder) (Note: Currently `list` lists all, prefix filtering may vary by implementation)
# For now, assumes basic list.
```

### 4. Folder Operations (Recursive)
Manage entire directories with automatic encryption.

**Upload a Folder (with deduplication):**
```bash
# Upload folder to S3 (uses folder name as prefix)
cybs3 folders put ./my-project

# Upload to specific S3 path
cybs3 folders put ./my-project backups/2026/project

# Dry-run to see what would be uploaded
cybs3 folders put ./my-project --dry-run

# Force upload all files (ignore deduplication)
cybs3 folders put ./my-project --force

# Exclude patterns
cybs3 folders put ./my-project --exclude ".git,node_modules,*.log"
```

**Download a Folder:**
```bash
# Download folder from S3
cybs3 folders get backups/2026/project

# Download to specific local path
cybs3 folders get backups/2026/project ./restored-project

# Overwrite existing files
cybs3 folders get backups/2026/project --overwrite
```

**Sync a Folder:**
```bash
# Sync local folder to S3 (upload new/changed files)
cybs3 folders sync ./my-project

# Sync and delete remote files that don't exist locally
cybs3 folders sync ./my-project --delete

# Dry-run sync
cybs3 folders sync ./my-project --dry-run
```

**Watch for Changes (Live Sync):**
```bash
# Watch folder and auto-upload changes
cybs3 folders watch ./my-project

# Watch with initial sync
cybs3 folders watch ./my-project --initial-sync

# Custom poll interval (in seconds)
cybs3 folders watch ./my-project --interval 5
```

### 5. Direct Configuration (Advanced)
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