# CybS3 User Guide

A complete guide to using CybS3 for secure S3 storage operations.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Authentication & Sessions](#authentication--sessions)
3. [Key Management](#key-management)
4. [Vault Management](#vault-management)
5. [File Operations](#file-operations)
6. [Folder Operations](#folder-operations)
7. [Configuration Options](#configuration-options)
8. [Troubleshooting](#troubleshooting)

---

## Getting Started

### Prerequisites

- macOS 12.0+ (tested)
- Swift 6.2+ toolchain

### Installation

```bash
# Clone the repository
git clone https://github.com/cybou-fr/CybS3.git
cd CybS3

# Build in release mode
swift build -c release

# (Optional) Install globally
cp .build/release/cybs3 /usr/local/bin/
```

### First-Time Setup

1. **Generate a mnemonic** (your master key):
   ```bash
   cybs3 keys create
   ```
   > ⚠️ **IMPORTANT**: Write down the 12 words and store them safely. This is your only way to decrypt your data!

2. **Log in** (store mnemonic in Keychain for convenience):
   ```bash
   cybs3 login
   ```

3. **Add your first vault** (S3 connection):
   ```bash
   cybs3 vaults add --name MyAWS
   # Follow the prompts for endpoint, access key, secret key, etc.
   ```

4. **Select the vault**:
   ```bash
   cybs3 vaults select MyAWS
   ```

You're now ready to use CybS3!

---

## Authentication & Sessions

### Login (Recommended)

Store your mnemonic securely in the macOS Keychain:

```bash
cybs3 login
```

Once logged in, you won't need to enter your mnemonic for each command.

### Logout

Remove your mnemonic from the Keychain:

```bash
cybs3 logout
```

### Manual Entry

If you prefer not to use Keychain storage, CybS3 will prompt for your mnemonic when needed.

---

## Key Management

### Create a New Mnemonic

```bash
cybs3 keys create
```

Generates a new BIP39-compliant 12-word phrase. Example output:

```
Your new mnemonic phrase (KEEP THIS SAFE!):
------------------------------------------------
abandon ability able about above absent absorb abstract absurd abuse access accident
------------------------------------------------
```

### Validate a Mnemonic

```bash
cybs3 keys validate word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12
```

Verifies the phrase is valid BIP39 with correct checksum.

### Rotate Mnemonic (Change Master Key)

```bash
cybs3 keys rotate
```

This command allows you to change your mnemonic **without re-encrypting** your S3 data:

1. Authenticate with your current mnemonic
2. Choose to generate a new one or enter manually
3. The internal Data Key is re-encrypted with the new mnemonic

> 💡 **Use case**: If you suspect your mnemonic was compromised, rotate immediately. Your S3 files remain encrypted with the same Data Key.

---

## Vault Management

Vaults store S3 connection profiles (endpoint, credentials, bucket) encrypted locally.

### Add a Vault

```bash
cybs3 vaults add --name Production
```

You'll be prompted for:
- S3 Endpoint (e.g., `s3.amazonaws.com`, `minio.example.com`)
- Access Key ID
- Secret Access Key
- Region (default: `us-east-1`)
- Default Bucket (optional)

### List Vaults

```bash
cybs3 vaults list
```

### Select a Vault

```bash
cybs3 vaults select Production
```

Sets this vault as the active configuration for all subsequent commands.

### Delete a Vault

```bash
cybs3 vaults delete Production
```

---

## File Operations

All file operations use automatic client-side encryption.

### Upload a File

```bash
# Upload with original filename
cybs3 files put ./document.pdf

# Upload with custom remote key
cybs3 files put ./document.pdf backups/2026/january/report.pdf

# Preview upload without executing
cybs3 files put ./document.pdf --dry-run
```

### Download a File

```bash
# Download to current directory
cybs3 files get backups/2026/january/report.pdf

# Download to specific path
cybs3 files get backups/2026/january/report.pdf ./restored-report.pdf
```

### List Files

```bash
# List all files in bucket
cybs3 files list

# List with prefix filter
cybs3 files list --prefix backups/2026/

# Output as JSON
cybs3 files list --json
```

### Delete a File

```bash
# Interactive deletion (asks for confirmation)
cybs3 files delete backups/2026/january/report.pdf

# Force deletion (no prompt)
cybs3 files delete backups/2026/january/report.pdf --force
```

### Copy a File

```bash
cybs3 files copy source-key destination-key
```

---

## Folder Operations

Powerful recursive folder management with smart features.

### Upload a Folder

```bash
# Upload using folder name as S3 prefix
cybs3 folders put ./my-project

# Upload to specific S3 path
cybs3 folders put ./my-project backups/projects/my-project

# Preview changes (dry-run)
cybs3 folders put ./my-project --dry-run

# Force upload all files (skip deduplication)
cybs3 folders put ./my-project --force

# Exclude patterns
cybs3 folders put ./my-project --exclude ".git,node_modules,*.log,__pycache__"
```

**Smart Deduplication**: By default, CybS3 only uploads new or changed files by comparing:
- File size
- Modification date
- Content hash (SHA256)

### Download a Folder

```bash
# Download to folder matching S3 prefix name
cybs3 folders get backups/projects/my-project

# Download to specific local path
cybs3 folders get backups/projects/my-project ./restored-project

# Overwrite existing files
cybs3 folders get backups/projects/my-project --overwrite
```

### Sync a Folder

Bidirectional synchronization between local and S3:

```bash
# Sync local → S3 (upload new/changed)
cybs3 folders sync ./my-project

# Sync with deletion (remove S3 files not in local)
cybs3 folders sync ./my-project --delete

# Sync to specific S3 prefix
cybs3 folders sync ./my-project backups/current

# Preview sync plan
cybs3 folders sync ./my-project --dry-run
```

### Watch Mode (Live Sync)

Automatically upload changes as they happen:

```bash
# Start watching a folder
cybs3 folders watch ./my-project

# Watch with initial sync
cybs3 folders watch ./my-project --initial-sync

# Custom poll interval (seconds)
cybs3 folders watch ./my-project --interval 5

# Specify S3 destination
cybs3 folders watch ./my-project backups/live

# Exclude patterns
cybs3 folders watch ./my-project --exclude ".git,*.tmp"
```

Press `Ctrl+C` to stop watching.

---

## Configuration Options

### Global Options

Available for all commands:

| Option | Description |
|--------|-------------|
| `--vault <name>` | Use specific vault |
| `--endpoint <url>` | Override S3 endpoint |
| `--access-key <key>` | Override access key |
| `--secret-key <key>` | Override secret key |
| `--bucket <name>` | Override bucket |
| `--region <region>` | Override region |
| `--ssl / --no-ssl` | Enable/disable SSL |
| `--verbose` | Verbose output |

### Direct Configuration

Configure defaults without creating a vault:

```bash
cybs3 config --endpoint s3.amazonaws.com --bucket my-bucket --region us-west-2
```

### Bucket Operations

```bash
# List all buckets
cybs3 buckets list

# Create a bucket
cybs3 buckets create my-new-bucket
```

---

## Troubleshooting

### "No mnemonic found in Keychain"

Run `cybs3 login` to store your mnemonic.

### "Authentication Failed"

Check your Access Key and Secret Key. Verify they have the necessary S3 permissions.

### "Decryption failed"

The file may have been encrypted with a different Data Key, or the file is corrupted.

### "Bucket Not Found"

Ensure you've either:
- Selected a vault with a default bucket (`cybs3 vaults select`)
- Specified a bucket with `--bucket`

### Files appear larger after download

This is expected! CybS3 adds encryption overhead (~28 bytes per 1MB chunk) during upload. Downloaded files are decrypted and should match the original size.

### Configuration file location

All encrypted configuration is stored at: `~/.cybs3/config.enc`

File permissions are set to `600` (owner read/write only).

---

## Cross-Platform Support

CybS3 works on macOS, Linux, and Windows with platform-specific optimizations:

### macOS
- **Keychain Integration**: Secure mnemonic storage
- **Optimized Locking**: Uses `os_unfair_lock` for performance
- **Native Notifications**: System integration for watch mode

### Linux
- **Encrypted File Storage**: Secure credential storage in `~/.cybs3/`
- **POSIX Threading**: Uses `pthread_mutex` for thread safety
- **File Permissions**: Restrictive permissions (600) on sensitive files

### Windows
- **Credential Manager**: Secure storage integration
- **Native Threading**: Windows threading primitives
- **Path Handling**: Proper Windows path support

### Platform-Specific Setup

```bash
# All platforms use the same commands
cybs3 keys create  # Works identically across platforms
cybs3 login        # Uses platform-specific secure storage
cybs3 vaults add   # Cross-platform vault management
```

---

## Performance Features

### Concurrent Operations

CybS3 supports parallel uploads and downloads for maximum throughput:

```bash
# Upload with high concurrency (planned feature)
cybs3 files put large-file.zip --concurrency 8

# Download with high parallelism (planned feature)
cybs3 files get large-file.zip --concurrency 16

# Folder sync with parallelism (planned feature)
cybs3 folders sync ./data --concurrency 6
```

### Streaming Encryption

Large files are processed in memory-efficient chunks:

- **Chunk Size**: 1MB (configurable via environment variables)
- **Memory Usage**: Constant regardless of file size
- **Progress Tracking**: Real-time upload/download progress

### Connection Pooling

HTTP connections are reused for better performance:

- **Keep-Alive**: Persistent connections
- **Connection Limits**: Configurable pool size
- **Timeout Handling**: Automatic connection recovery

### Performance Monitoring

Monitor CybS3's performance characteristics:

```bash
# Run performance benchmarks
cybs3 performance benchmark

# Check system health
cybs3 health check
```

---

## Security Features

### Enhanced Key Security

- **PBKDF2 + HKDF**: Double key derivation for maximum security
- **Secure Memory**: Automatic zeroing of sensitive data
- **Key Rotation**: Change mnemonics without re-encrypting data

### Audit Logging

All operations are logged for security monitoring:

```bash
# View recent activity
cybs3 health check --verbose

# Logs are stored securely and never contain sensitive data
```

### Fault Tolerance

CybS3 includes enterprise-grade resilience:

- **Circuit Breaker**: Prevents cascade failures
- **Retry Logic**: Exponential backoff for transient errors
- **Health Monitoring**: Automatic system diagnostics

### Secure Configuration

- **Encrypted Config**: All settings stored encrypted
- **File Permissions**: Restrictive access controls
- **Platform Security**: Uses OS security facilities

---

## Advanced Configuration

### Environment Variables

```bash
# Override default settings
export CYBS3_CHUNK_SIZE=2097152          # 2MB chunks (planned feature)
export CYBS3_MAX_CONCURRENCY=8           # Max parallel operations (planned feature)
export CYBS3_CONNECTION_TIMEOUT=30       # Connection timeout (seconds)
export CYBS3_RETRY_MAX_ATTEMPTS=5        # Max retry attempts
```

### Custom Chunk Sizes

For specific performance requirements (planned feature):

```bash
# Larger chunks for high-latency networks
cybs3 files put large-file.dat --chunk-size 4194304  # 4MB

# Smaller chunks for low-memory systems
cybs3 files put small-file.dat --chunk-size 524288   # 512KB
```

### Health Monitoring

Regular health checks ensure system reliability:

```bash
# Comprehensive system check
cybs3 health check

# Check specific components
cybs3 health check --component encryption
cybs3 health check --component network
cybs3 health check --component storage
```

---

## Quick Reference

| Command | Description |
|---------|-------------|
| `cybs3 login` | Store mnemonic in secure storage |
| `cybs3 logout` | Remove mnemonic from secure storage |
| `cybs3 keys create` | Generate new mnemonic |
| `cybs3 keys rotate` | Change mnemonic (keep data access) |
| `cybs3 vaults add --name X` | Add S3 connection |
| `cybs3 vaults select X` | Activate a vault |
| `cybs3 files put <local>` | Upload & encrypt file |
| `cybs3 files get <remote>` | Download & decrypt file |
| `cybs3 folders put <path>` | Upload folder (deduplicated) |
| `cybs3 folders sync <path>` | Sync folder with S3 |
| `cybs3 folders watch <path>` | Live sync on changes |
| `cybs3 health check` | System diagnostics |
| `cybs3 performance benchmark` | Performance testing |
| `cybs3 --help` | Show all commands and options |

---

*For more information, see the main [README.md](README.md) or run `cybs3 --help`.*
