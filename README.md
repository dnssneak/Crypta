# Crypta — Steganography, Cryptography & Steganalysis Toolkit

**Version:** 1.0.0  
**Status:** In Development (Feature 5 Complete)  
**Primary Platform:** Kali Linux  
**Supported Platforms:** Linux & Windows Terminal  
**Language:** Python 3  

---

## 1. Project Overview

**Crypta** is a command-line cybersecurity toolkit designed to securely hide sensitive payload files inside digital PNG images and conduct statistical steganalysis on suspicious media files.

Crypta integrates:
* **Secure Pipeline Core (Feature 5):** Orchestrated hide/extract workflow (`crypta/core/pipeline.py`) featuring transactional atomic output creation, capacity fit check, SHA-256 plaintext integrity validation, path traversal filename sanitization, and output collision checks.
* **Core Cryptography Layer (Feature 4):** AES-256-GCM authenticated encryption with SHA-256 integrity digest and Argon2id password-based key derivation.
* **LSB Steganography (Feature 3):** Spatial-domain 1-bit-per-channel LSB embedding and extraction for PNG carrier images (RGB and RGBA with Alpha channel preservation).
* **Integrity & Capacity Engine (Feature 2):** PNG carrier validation, image integrity check (`img.verify()`), color channel inspection, and capacity fit enforcement.
* **CLI Foundation & Interactive Shell (Feature 1):** Command-line routing with global options, `--no-color` toggles, verbose logging, interactive REPL shell (`crypta>`), and secure interactive password prompts (`getpass`).

---

## 2. Pipeline & Security Architecture

### Hide Pipeline Architecture
```text
Secret Input File
       ↓
Validate Carrier PNG Image
       ↓
Read Binary Data & Calculate SHA-256
       ↓
Derive 256-bit Key (Argon2id + Random 16B Salt)
       ↓
Encrypt Payload (AES-256-GCM + Random 12B Nonce)
       ↓
Construct Crypta Version 2 Binary Payload Frame
       ↓
Check Exact Serialized Size against Usable Capacity
       ↓
Embed Bitstream into Carrier Image LSBs
       ↓
Atomic Write to Output Stego PNG Image
```

### Extract Pipeline Architecture
```text
Stego PNG Image
       ↓
Validate Stego Carrier
       ↓
Extract Bitstream from Image LSBs
       ↓
Validate Crypta Header & Version 2 Payload Frame
       ↓
Unpack Salt, Nonce, Filename & Ciphertext
       ↓
Derive Key & Decrypt Payload (AES-256-GCM)
       ↓
Verify AES-GCM Tag & Embedded SHA-256 Digest
       ↓
Sanitize Filename & Output Path Resolution
       ↓
Atomic Write Recovered Secret Payload File
```

### Security & Integrity Controls
* **Confidentiality:** Payload data is unreadable without the correct secret password.
* **Authenticity & Integrity:** Built-in AES-GCM 128-bit authentication tag combined with embedded SHA-256 digest guarantees that tampered ciphertext or wrong passwords trigger a controlled authentication failure.
* **Transactional Safety:** Output files are created atomically. If decryption or integrity verification fails, no partial or corrupted file is written to disk.
* **Carrier Immutability:** Original carrier images are strictly read-only and preserved untouched.

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
- [x] **Feature 5:** Secure Hide/Extract Orchestration Pipeline
- [ ] **Feature 6:** Report Generation Engine (HTML/JSON)

