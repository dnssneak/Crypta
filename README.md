# Crypta — Cybersecurity Steganography, Cryptography & Steganalysis Toolkit

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)]()
[![Status](https://img.shields.io/badge/status-Active%20Development-success.svg)]()

**Crypta** is an advanced, cross-platform Python cybersecurity CLI toolkit designed for secure **steganographic payload hiding**, **authenticated encryption**, **digital image forensics**, and **statistical steganalysis**.

Whether hiding encrypted sensitive data inside carrier images or inspecting suspicious media files for hidden payloads, Crypta provides a complete end-to-end framework with both standalone CLI commands and an interactive REPL shell (`crypta>`).

---

## Key Features

* **Authenticated Encryption (AES-256-GCM + Argon2id):** Protects payload confidentiality and authenticity using 256-bit AES-GCM encryption with 128-bit authentication tags, Argon2id key derivation, and cryptographically secure 16-byte salts and 12-byte nonces.
* **PNG LSB Steganography Engine:** Embeds encrypted data frames into 1-bit-per-channel Least Significant Bits (LSBs) of PNG images with complete Alpha channel preservation and zero loss of visual image quality.
* **Steganalysis Risk Engine:** Computes a normalized **0–100 steganography risk score** using 5 weighted statistical sub-engines (LSB distribution, Chi-Square PoV testing, Histogram ratios, Shannon entropy, and spatial pixel transitions).
* **Forensic Evidence Collection:** Conducts read-only evidence gathering (`crypta info`), extracting SHA-256 file digests, PNG binary IHDR chunk headers, metadata tags, and file format vs. extension consistency checks.
* **Standalone Reporting Engine:** Generates self-contained, offline **HTML reports** (with zero external CDN dependencies) and machine-readable **JSON exports** for SIEM and incident response workflows.
* **Interactive REPL Shell:** Includes a built-in interactive shell (`crypta>`) with command history, auto-formatting, and colored terminal styling.

---

## Installation & Setup

### Prerequisites

* **Python 3.10+** (Python 3.10, 3.11, 3.12, 3.13, or 3.14)
* **git** and **pip** package manager

### Step 1: Clone the Repository

```bash
git clone https://github.com/dnssneak/Crypta.git
cd Crypta
```

### Step 2: Create a Virtual Environment (Recommended)

**Linux / macOS / Kali Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Step 3: Install Dependencies

Install all required Python packages (Pillow, PyCryptodome, Argon2-cffi, NumPy, Matplotlib):

```bash
pip install -r requirements.txt
```

*(Optional)* Install Crypta in editable development mode so `crypta` becomes available directly as a system command:

```bash
pip install -e .
```

---

## Quick Start & Usage Guide

Crypta can be executed either via standard module syntax (`python -m crypta <command>`) or directly as `crypta <command>` (if installed via pip).

### 1. Hide an Encrypted Payload inside an Image (`hide`)

Encrypt a secret file and hide it inside a cover PNG carrier image:

```bash
python -m crypta hide cover.png secret.pdf stego_output.png
```
> **Security Note:** You will be prompted securely for a encryption password.

### 2. Extract and Decrypt a Hidden Payload (`extract`)

Extract and decrypt the hidden file from a stego PNG image:

```bash
python -m crypta extract stego_output.png -o recovered_secret.pdf
```
> **Security Note:** Enter the password used during embedding. Crypta automatically verifies AES-GCM tags and SHA-256 digests before writing the extracted file.

### 3. Perform Steganalysis & Risk Assessment (`analyze`)

Analyze an image for statistical indicators of LSB steganography:

```bash
python -m crypta analyze suspicious.png
```

Generate visual statistical chart figures alongside the analysis:
```bash
python -m crypta analyze suspicious.png --visualize
```

### 4. Forensic Evidence Collection (`info`)

Inspect file fingerprints, PNG chunk headers, EXIF/text metadata, and format consistency:

```bash
python -m crypta info image.png
```

### 5. Generate Standalone HTML & JSON Reports (`report`)

Generate standalone HTML and machine-readable JSON forensic reports:

```bash
# Generate both HTML and JSON reports in reports/ directory
python -m crypta report suspicious.png

# Generate only HTML report in a specific output directory
python -m crypta report suspicious.png --format html --output /path/to/output_dir/
```

### 6. Calculate Carrier Hiding Capacity (`capacity`)

Check the maximum embeddable secret payload size for a PNG image:

```bash
python -m crypta capacity cover.png
```

### 7. Interactive REPL Shell Mode

Launch Crypta's interactive shell by executing without arguments:

```bash
python -m crypta
```
```text
crypta> capacity cover.png
crypta> analyze suspicious.png
crypta> exit
```

---

## Summary of CLI Commands

| Command | Purpose | Example Syntax |
|---|---|---|
| `hide` | Encrypt & embed secret payload into PNG carrier | `crypta hide cover.png secret.txt stego.png` |
| `extract` | Extract & decrypt payload from stego carrier | `crypta extract stego.png -o output.txt` |
| `analyze` | Run statistical steganalysis & risk assessment | `crypta analyze image.png [--visualize]` |
| `info` | Collect forensic evidence & inspect image metadata | `crypta info image.png` |
| `report` | Generate standalone HTML and JSON report files | `crypta report image.png [--format html\|json\|both]` |
| `capacity` | Calculate maximum byte capacity of carrier PNG | `crypta capacity cover.png` |

---

## Security Architecture & Binary Framing

### Crypta Version 2 Binary Framing Header

Payloads embedded by Crypta are wrapped in a Version 2 binary framing structure prior to LSB embedding:

| Field | Type / Size | Description |
|---|---|---|
| **Magic Header** | `b"CRYPTA\x01"` (7 Bytes) | Crypta protocol signature identification header |
| **Header Version** | `1 byte` (`0x02`) | Binary payload frame specification version |
| **Argon2id Salt** | `16 bytes` (Raw) | Password key derivation salt |
| **AES-GCM Nonce** | `12 bytes` (Raw) | Authenticated encryption initialization vector |
| **Filename Length** | `2 bytes` (`!H` uint16) | Length of original payload filename |
| **Filename** | Variable UTF-8 String | Original sanitized payload filename |
| **Ciphertext Length** | `8 bytes` (`!Q` uint64) | Total size of encrypted payload container |
| **AES-256-GCM Ciphertext** | Raw Encrypted Bytes | Encrypted SHA-256 Hash + Payload Data + 16B Tag |


### Security & Integrity Controls

* **Confidentiality:** Payload data is unreadable without the correct secret password.
* **Authenticity & Integrity:** 128-bit AES-GCM authentication tags combined with embedded SHA-256 plaintext digests ensure that modified ciphertext or incorrect passwords trigger controlled authentication failures.
* **Transactional Safety:** Output files are created atomically. If decryption or integrity verification fails, no partial or corrupted files are written to disk.
* **Carrier Immutability:** Original carrier images are opened in read-only mode and preserved untouched.

---

## Running Automated Unit Tests

Crypta includes a test suite covering all modules:

```bash
python -m pytest
```

Run test suite with verbose output:
```bash
python -m pytest -v
```

---

## Development Roadmap

- [x] **Feature 1:** CLI Foundation, Styling System & Interactive Shell (`crypta>`)
- [x] **Feature 2:** PNG Carrier Validation & Capacity Calculation Engine
- [x] **Feature 3:** PNG LSB Steganography Encoder & Decoder (Binary Framing & Alpha Preservation)
- [x] **Feature 4:** AES-256-GCM Encryption + Argon2id Key Derivation Layer
- [x] **Feature 5:** Secure Hide/Extract Orchestration Pipeline Core
- [x] **Feature 6:** Steganalysis Engine (Entropy, LSB, Chi-Square, Histogram, Pixel Statistics)
- [x] **Feature 7:** Forensics & Evidence Collection Engine (`crypta info`, SHA-256, PNG IHDR, Metadata)
- [x] **Feature 8:** Steganalysis Risk Engine (0–100 Risk Score & Explainable Assessment)
- [x] **Feature 9:** Forensic Report Generation Engine (Standalone HTML & Machine-Readable JSON)

---

## Disclaimer & Responsible Use

> [!IMPORTANT]
> **Heuristic Assessment Disclaimer:**
> The Crypta risk score is a heuristic statistical assessment. A high risk score indicates that observed statistical characteristics are consistent with steganographic modification, but it does **not** constitute absolute proof of hidden data.

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
