# Crypta — Steganography, Cryptography & Steganalysis Toolkit

**Version:** 1.0.0  
**Status:** In Development (Feature 4 Complete)  
**Primary Platform:** Kali Linux  
**Supported Platforms:** Linux & Windows Terminal  
**Language:** Python 3  

---

## 1. Project Overview

**Crypta** is a command-line cybersecurity toolkit designed to securely hide sensitive payload files inside digital PNG images and conduct statistical steganalysis on suspicious media files.

Crypta integrates:
* **Core Cryptography Layer (Feature 4):** AES-256-GCM authenticated encryption with SHA-256 integrity digest and Argon2id password-based key derivation.
* **LSB Steganography (Feature 3):** Spatial-domain 1-bit-per-channel LSB embedding and extraction for PNG carrier images (RGB and RGBA with Alpha channel preservation).
* **Integrity & Capacity Engine (Feature 2):** PNG carrier validation, image integrity check (`img.verify()`), color channel inspection, and capacity fit enforcement.
* **CLI Foundation & Interactive Shell (Feature 1):** Command-line routing with global options, `--no-color` toggles, verbose logging, interactive REPL shell (`crypta>`), and secure interactive password prompts (`getpass`).

---

## 2. Security Architecture

### Encryption
Crypta uses **AES-256-GCM** (Galois/Counter Mode) to ensure:
* **Confidentiality:** Payload data is unreadable without the correct secret password.
* **Authenticity & Integrity:** Built-in 128-bit authentication tag guarantees that tampered ciphertext or wrong passwords trigger a controlled authentication failure.
* **SHA-256 Plaintext Verification:** Embedded SHA-256 digest provides post-decryption byte-for-byte verification of original file contents.

### Key Derivation
Passwords are never used directly as encryption keys. Crypta processes user passwords through **Argon2id** (memory cost: 64 MiB, time cost: 3 iterations, parallelism: 4 threads) to derive a 256-bit AES encryption key.

### Randomness & Non-Determinism
Every encryption operation generates:
* A fresh, cryptographically secure 16-byte random **salt** (`secrets.token_bytes(16)`).
* A fresh, cryptographically secure 12-byte random **nonce** (`secrets.token_bytes(12)`).

Encrypting the exact same file twice with the same password produces completely different salt, nonce, and ciphertext outputs.

> [!WARNING]
> **Steganography vs. Encryption Security Distinction:**
> - **Steganography** hides the *existence* and location of hidden data within a carrier file.
> - **Encryption** protects the *confidentiality* and *authenticity* of the payload data.
> - **Crypta's security** depends on the strength and secrecy of the user's password. A weak password reduces the practical security of the encrypted payload.

---

## 3. CLI & Interactive Shell Usage

### Standalone CLI Commands

```powershell
python -m crypta hide cover.png secret.pdf stego.png
# Prompts for Password & Confirm password securely

python -m crypta extract stego.png -o recovered/
# Prompts for Password securely

python -m crypta capacity cover.png
```

---

## 4. Binary Payload Structure (Version 2 Specification)

```text
+-----------------------+---------------------+
| Field                 | Type / Size         |
+-----------------------+---------------------+
| Magic Header          | b"CRYPTA\x01" (7B)  |
| Header Version        | 1 byte (0x02)       |
| Argon2id Salt         | 16 bytes (Raw)      |
| AES-GCM Nonce         | 12 bytes (Raw)      |
| Filename Length       | 2 bytes (!H)        |
| Filename              | UTF-8 string        |
| Ciphertext Length     | 8 bytes (!Q)        |
| AES-256-GCM Ciphertext| Raw Encrypted Bytes |
| (Includes SHA-256     | (Internal 32B Hash  |
|  & 16B Auth Tag)      |  + Plaintext + Tag) |
+-----------------------+---------------------+
```

---

## 5. Available Commands

| Command | Purpose | Example |
|---|---|---|
| `hide` | Encrypt & hide a file inside a PNG carrier image | `python -m crypta hide cover.png secret.pdf stego.png` |
| `extract` | Extract & decrypt a hidden file from a stego PNG image | `python -m crypta extract stego.png -o recovered/` |
| `capacity` | Calculate image hiding capacity | `python -m crypta capacity cover.png` |
| `info` | Display image and file information | `python -m crypta info image.png` |
| `analyze` | Perform statistical steganalysis | `python -m crypta analyze suspicious.png` |
| `report` | Generate analysis report | `python -m crypta report suspicious.png --format html` |

---

## 6. Development Roadmap

- [x] **Feature 1:** CLI Foundation & Visual Design System (Interactive Shell `crypta>`)
- [x] **Feature 2:** Image Validation & Capacity Calculation Engine
- [x] **Feature 3:** PNG LSB Steganography Encoder & Decoder (Binary Framing & Alpha Preservation)
- [x] **Feature 4:** Core Cryptography Pipeline (Argon2id + AES-256-GCM Payload Encryption)
- [ ] **Feature 5:** Steganalysis Engine & Risk Scoring
- [ ] **Feature 6:** Report Generation Engine (HTML/JSON)
