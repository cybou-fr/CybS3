# Changelog

All notable changes to CybS3 will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-01

### Added

- **Core Features**
  - Client-side AES-256-GCM encryption for all file operations
  - BIP39 mnemonic-based key derivation (PBKDF2 + HKDF)
  - Two-tier encryption architecture (Master Key + Data Key)
  - Streaming encryption/decryption for large files (1MB chunks)

- **Key Management**
  - `keys create` - Generate new 12-word BIP39 mnemonic
  - `keys validate` - Validate mnemonic phrase
  - `keys rotate` - Rotate master key without re-encrypting S3 data

- **Vault Management**
  - `vaults add` - Add encrypted S3 connection profiles
  - `vaults list` - List all configured vaults
  - `vaults select` - Set active vault
  - `vaults delete` - Remove vault configuration

- **Session Management**
  - `login` - Store mnemonic in macOS Keychain
  - `logout` - Remove mnemonic from Keychain

- **File Operations**
  - `files put` - Upload and encrypt files
  - `files get` - Download and decrypt files
  - `files list` - List bucket contents (with prefix filtering)
  - `files delete` - Delete objects (with confirmation)
  - `files copy` - Copy objects within bucket

- **Folder Operations**
  - `folders put` - Recursive upload with smart deduplication
  - `folders get` - Recursive download with decryption
  - `folders sync` - Bidirectional sync with optional `--delete`
  - `folders watch` - Live file watching with auto-upload

- **Bucket Operations**
  - `buckets list` - List all buckets
  - `buckets create` - Create new bucket

- **Developer Experience**
  - Progress bars for all upload/download operations
  - JSON output mode (`--json`) for scripting
  - Dry-run mode for preview operations
  - Verbose logging option
  - Colorized terminal output

### Security

- All credentials stored in encrypted config (`~/.cybs3/config.enc`)
- Config file permissions set to 600 (owner only)
- Unique nonce per encryption chunk
- Secure memory clearing for sensitive data

### Compatibility

- macOS 12.0+
- Swift 6.2+
- Any S3-compatible storage (AWS, MinIO, Ceph, GCS, Backblaze B2)

[1.0.0]: https://github.com/cybou-fr/CybS3/releases/tag/v1.0.0
