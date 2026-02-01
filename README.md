# CybS3

> **Zero-knowledge, client-side encrypted S3 storage client** — written in pure Swift.

CybS3 is a command-line tool for managing S3-compatible object storage with **true end-to-end encryption**. Your cloud provider never sees your data unencrypted.

Works with: **AWS S3** • **MinIO** • **Ceph** • **Google Cloud Storage** • **Backblaze B2** • Any S3-compatible service

---

## ✨ What Makes CybS3 Unique

### 🔐 True Client-Side Encryption

Unlike server-side encryption (SSE), **your data is encrypted before it leaves your machine**. The cloud provider stores only ciphertext — they cannot read your files even with a court order.

```
Your File → [AES-256-GCM Encrypt] → Network → S3 (Encrypted Blob)
```

### 🧠 BIP39 Mnemonic as Master Key

Your encryption is secured by a **12-word recovery phrase** (the same standard used by cryptocurrency wallets). No passwords to remember — just 12 words to rule them all.

```bash
$ cybs3 keys create
abandon ability able about above absent absorb abstract absurd abuse access accident
```

### 🔄 Key Rotation Without Re-encryption

Change your mnemonic **without re-uploading terabytes of data**. CybS3 uses a two-tier key architecture:

| Layer | Key | Purpose |
|-------|-----|---------|
| Master | Your Mnemonic | Encrypts local config |
| Data | Random 256-bit | Encrypts actual files |

When you rotate, only the Data Key wrapper changes — your S3 files stay untouched.

### 📂 Smart Folder Sync

Upload entire directories with **automatic deduplication**:

- Compares file size, modification date, and SHA256 hash
- Uploads only changed files
- `--delete` mode removes orphaned remote files
- **Live watch mode** — auto-sync on file changes

### 🗄️ Multi-Vault Management

Store multiple S3 configurations (work, personal, backup) in a single encrypted vault file:

```bash
cybs3 vaults add --name Production
cybs3 vaults add --name Archive  
cybs3 vaults select Production
```

### 🍎 macOS Keychain Integration

Store your mnemonic securely in Keychain for seamless access:

```bash
cybs3 login   # Store mnemonic
cybs3 logout  # Clear session
```

---

## 🚀 Quick Start

```bash
# Install
git clone https://github.com/cybou-fr/CybS3.git && cd CybS3
swift build -c release
cp .build/release/cybs3 /usr/local/bin/

# Setup
cybs3 keys create            # Generate your 12-word mnemonic (SAVE IT!)
cybs3 login                  # Store in Keychain
cybs3 vaults add --name AWS  # Configure S3 connection
cybs3 vaults select AWS

# Use
cybs3 files put ./secret.pdf              # Upload & encrypt
cybs3 files get secret.pdf ./restored.pdf # Download & decrypt
cybs3 folders sync ./project              # Sync entire folder
```

📖 **Full documentation**: See [USER_GUIDE.md](USER_GUIDE.md)

---

## 📋 Command Overview

| Command | Description |
|---------|-------------|
| `cybs3 login` / `logout` | Manage Keychain session |
| `cybs3 keys create` | Generate new mnemonic |
| `cybs3 keys rotate` | Change mnemonic (preserves data) |
| `cybs3 vaults add/list/select/delete` | Manage S3 profiles |
| `cybs3 files put/get/list/delete/copy` | Single file operations |
| `cybs3 folders put/get/sync/watch` | Recursive folder operations |
| `cybs3 buckets list/create` | Bucket management |

---

## 🏗️ Architecture

**Built with modern Swift technologies:**

| Component | Technology |
|-----------|------------|
| Language | Swift 6.2+ (async/await) |
| CLI | swift-argument-parser |
| Networking | async-http-client (SwiftNIO) |
| Crypto | swift-crypto (BoringSSL) |
| BIP39 | SwiftBIP39 |

**Encryption Stack:**

```
Mnemonic → PBKDF2-HMAC-SHA512 (2048 rounds) → HKDF-SHA256 → Master Key (config encryption)
                                                          ↓
                                              Data Key (AES-256-GCM, 1MB streaming chunks)
```

---

## 🔒 Security Details

| Feature | Implementation |
|---------|---------------|
| Key Derivation | PBKDF2 (2048 rounds) + HKDF-SHA256 |
| Config Encryption | AES-256-GCM |
| File Encryption | AES-256-GCM (streaming, 1MB chunks) |
| Per-Chunk Nonce | Unique 12-byte nonce per 1MB |
| Config Location | `~/.cybs3/config.enc` (mode 600) |

---

## 🧪 Testing

```bash
# Unit tests
swift test

# Integration tests (requires S3 credentials)
CYBS3_TEST_ENDPOINT=s3.amazonaws.com \
CYBS3_TEST_ACCESS_KEY=xxx \
CYBS3_TEST_SECRET_KEY=xxx \
swift test --filter IntegrationTests
```

---

## 📄 License

MIT

---

<p align="center">
  <b>Your data. Your keys. Your control.</b>
</p>