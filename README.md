# Crypta — Steganography, Cryptography & Steganalysis Toolkit

**Version:** 1.0.0  
**Status:** In Development (Feature 7 Complete)  
**Primary Platform:** Kali Linux  
**Supported Platforms:** Linux & Windows Terminal  
**Language:** Python 3  

---

## 1. Project Overview

**Crypta** is a command-line cybersecurity toolkit designed to securely hide sensitive payload files inside digital PNG images and conduct statistical steganalysis on suspicious media files.

Crypta integrates:
* **Forensics Engine (Feature 7):** Read-only evidence collection (`crypta info <image>`) extracting SHA-256 file fingerprints, filesystem metadata, actual format detection vs extension mismatch verification, PNG binary IHDR chunk structure, and safe text/EXIF metadata decoding.
* **Steganalysis Engine (Feature 6):** Comprehensive analytical pipeline (`crypta/steganalysis/`) evaluating Shannon entropy, LSB 0/1 distributions, Pairs of Values Chi-Square test statistics, histogram frequency pairing, and spatial pixel transition dynamics.
* **Secure Pipeline Core (Feature 5):** Orchestrated hide/extract workflow (`crypta/core/pipeline.py`) featuring transactional atomic output creation, capacity fit check, SHA-256 plaintext integrity validation, path traversal filename sanitization, and output collision checks.
* **Core Cryptography Layer (Feature 4):** AES-256-GCM authenticated encryption with SHA-256 integrity digest and Argon2id password-based key derivation.
* **LSB Steganography (Feature 3):** Spatial-domain 1-bit-per-channel LSB embedding and extraction for PNG carrier images (RGB and RGBA with Alpha channel preservation).
* **Integrity & Capacity Engine (Feature 2):** PNG carrier validation, image integrity check (`img.verify()`), color channel inspection, and capacity fit enforcement.
* **CLI Foundation & Interactive Shell (Feature 1):** Command-line routing with global options, `--no-color` toggles, verbose logging, interactive REPL shell (`crypta>`), and secure interactive password prompts (`getpass`).

---

## 2. Forensics & Evidence Collection

Crypta includes a read-only forensic inspection engine (`crypta info <image_path>`) to collect reliable digital evidence:

* **SHA-256 File Fingerprinting:** 64 KB chunked, memory-efficient SHA-256 hash calculation.
* **File & Format Verification:** File size, modification timestamps, actual format detection (Pillow header check), and extension vs format consistency verification (detecting files like JPEG renamed to `.png`).
* **Image Properties:** Dimensions, color mode, channel counts, and bit depth.
* **PNG Structural Analysis:** Signature validation, color type descriptions (Grayscale, Truecolor, Indexed, RGBA), compression method, filter method, and interlace method parsed directly from binary IHDR headers.
* **Metadata Extraction:** Embedded PNG textual metadata (`tEXt`/`zTXt`/`iTXt`) and EXIF tags, with terminal escape code sanitization.

> Forensic metadata is informational evidence and should be interpreted in context. Filesystem timestamps and embedded metadata are not inherently proof of when or how an image was created.

Forensic analysis is strictly **read-only** and guarantees original file immutability.

---

## 3. Steganalysis Engine


Crypta includes a statistical steganalysis engine (`crypta analyze <image_path>`) to evaluate PNG carrier images (RGB and RGBA) for statistical indicators associated with LSB steganography:

* **Entropy Analysis:** Global and per-channel Shannon entropy calculation ($0.0 \le H \le 8.0$).
* **LSB Distribution Analysis:** Bitwise 0-bit vs 1-bit counts, percentages, and absolute percentage deviation from ideal 50/50 balance.
* **Chi-Square Analysis:** Pairs of Values (PoVs $2k$ vs $2k+1$) Chi-Square test statistic, degrees of freedom, and p-value derivation.
* **Histogram Analysis:** Intensity bounds (min/max), mean, median, standard deviation, and adjacent pair differential ratios.
* **Pixel Statistics:** Unique value counts per channel and spatial raster LSB transition frequency.

These metrics represent **heuristic statistical indicators**.

> Steganalysis cannot guarantee detection of hidden information from these metrics alone. Natural image characteristics can produce similar statistical patterns, so the results should be interpreted as indicators rather than proof.

Optional visual chart generation is supported:
```bash
crypta analyze suspicious.png --visualize
```

---

## 3. Pipeline & Security Architecture


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
- [x] **Feature 6:** Steganalysis Engine (Entropy, LSB, Chi-Square, Histogram, Pixel Statistics)
- [x] **Feature 7:** Forensics & Evidence Collection Engine (`crypta info`, SHA-256, PNG IHDR, Metadata)
- [ ] **Feature 8:** Steganalysis Risk Engine (0-100 Risk Score)
- [ ] **Feature 9:** Forensic Report Generation Engine (HTML/JSON)



