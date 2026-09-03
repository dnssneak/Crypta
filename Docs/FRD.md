# Functional Requirements Document (FRD)

## Crypta — Steganography, Cryptography & Steganalysis Toolkit

**Version:** 1.0  
**Project Type:** Cybersecurity / Digital Forensics  
**Technology:** Python 3  
**Primary Interface:** Command Line Interface (CLI)  
**Primary Platform:** Kali Linux  
**Supported Platforms:** Linux & Windows  
**Development Scope:** Two-Day MVP  

---

# 1. Introduction

## 1.1 Purpose

**Crypta** is a Python-based cybersecurity toolkit designed to provide secure data hiding, extraction, encryption, integrity verification, and steganalysis through a command-line interface.

The system combines three major cybersecurity concepts:

* **Steganography** — hiding information inside digital images.
* **Cryptography** — encrypting hidden information before embedding it.
* **Steganalysis** — analyzing images for statistical characteristics that may indicate the presence of hidden information.

Crypta is intended as an educational and practical cybersecurity tool that can be operated from **Kali Linux, Windows Terminal, and other compatible Python environments**.

---

# 2. Problem Statement

Traditional steganography tools often focus only on hiding and extracting text or files. This provides limited security because the hidden information may be extracted if the steganographic method is discovered.

Additionally, users need a way to investigate suspicious images that may contain hidden information.

Crypta addresses these limitations by combining:

1. Secure encryption before embedding.
2. File-based steganography.
3. Integrity verification.
4. Image capacity analysis.
5. Statistical steganalysis.
6. Metadata and forensic analysis.
7. Automated risk assessment.
8. Report generation.

---

# 3. Project Objectives

The primary objectives of Crypta are:

1. Develop a professional Python CLI cybersecurity toolkit.
2. Allow users to hide arbitrary files inside supported images.
3. Encrypt payloads before embedding them.
4. Allow authorized users to extract and decrypt hidden files.
5. Verify recovered files using cryptographic hashes.
6. Calculate the available hiding capacity of an image.
7. Analyze images for potential steganographic manipulation.
8. Perform entropy, LSB, histogram, and chi-square analysis.
9. Generate a combined steganography risk score.
10. Extract basic image metadata and forensic information.
11. Generate machine-readable JSON and human-readable HTML reports.
12. Support both Kali Linux and Windows environments.

---

# 4. Scope

## 4.1 In Scope

### Steganography
* PNG image support.
* LSB-based data embedding.
* LSB-based data extraction.
* Binary file embedding.
* Binary file extraction.
* Capacity calculation.
* Carrier image validation.

### Cryptography
* AES-GCM encryption.
* Argon2id password-based key derivation.
* Random salt generation.
* Random nonce generation.
* Secure password input.
* Authentication/tag verification.

### Integrity
* SHA-256 hashing.
* Original payload hash storage.
* Recovered payload verification.
* Tampering detection.

### Steganalysis
* Image entropy analysis.
* LSB distribution analysis.
* Chi-square statistical analysis.
* Pixel/histogram analysis.
* Combined risk scoring.

### Digital Forensics
* Image dimensions.
* Image format.
* Color channels.
* Bit depth where available.
* File size.
* Basic metadata extraction.
* SHA-256 image hashing.

### Reporting
* HTML reports.
* JSON reports.
* Analysis summary.
* Risk score.
* Statistical results.
* Metadata information.

### CLI
* Cross-platform command-line interface.
* Help system.
* Version information.
* Error messages.
* Logging.

---

# 5. Out of Scope

The following features are **not part of the two-day MVP**:

* JPEG steganography.
* Audio steganography.
* Video steganography.
* Network-based covert channels.
* Machine-learning-based steganalysis.
* Deep-learning steganalysis.
* GUI application.
* Web dashboard.
* Cloud storage.
* Distributed processing.
* Advanced anti-forensics.
* Real-time network monitoring.
* Password recovery/cracking functionality.
* Multiple advanced steganographic algorithms.

---

# 6. Target Users

* Cybersecurity Students
* Security Researchers
* Digital Forensics Analysts
* Penetration Testing / Security Professionals

---

# 7. System Architecture

```text
                         CRYPTA
                           │
                    Command Line Interface
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
  Steganography        Cryptography       Steganalysis
      Engine               Engine             Engine
        │                  │                  │
        │                  │                  │
        ▼                  ▼                  ▼
   LSB Encoding       AES-GCM + Argon2id   Statistical
   LSB Decoding       SHA-256              Analysis
        │                  │                  │
        └──────────────────┼──────────────────┘
                           │
                           ▼
                    Forensics Engine
                           │
                           ▼
                    Reporting Engine
                           │
                           ▼
                   HTML / JSON Reports
```

---

# 8. Functional Requirements

* **FR-01 — Command Line Interface:** CLI for interacting with commands, flags, help, versioning, error logging.
* **FR-02 — Hide Data:** Embed file inside carrier image with LSB, capacity validation, encryption, payload header packaging.
* **FR-03 — Extract Data:** Detect Crypta header payload, extract, prompt password, derive key, decrypt AES-GCM, verify SHA-256 hash.
* **FR-04 — Payload Encryption:** Argon2id key derivation, AES-GCM 256-bit encryption, CSPRNG salt & nonce.
* **FR-05 — Payload Integrity:** SHA-256 calculation pre-embedding and comparison post-extraction.
* **FR-06 — Image Capacity Calculation:** Calculate max bytes image can hide via LSB without corruption.
* **FR-07 — File and Image Information:** Resolution, channels, mode, file size, SHA-256, metadata check.
* **FR-08 — Metadata Analysis:** EXIF/Image header information inspection.
* **FR-09 — Steganalysis:** Entropy, LSB distribution, Chi-Square test, Histogram analysis.
* **FR-10 — Steganography Risk Score:** Normalized 0–100 risk score (LOW, MODERATE, HIGH, VERY HIGH).
* **FR-11 — Image Analysis Command:** Comprehensive unified analysis command (`crypta analyze`).
* **FR-12 — Report Generation:** Output forensic analysis results to HTML and JSON format (`crypta report`).
* **FR-13 — Logging:** Multi-level logging (INFO, WARNING, ERROR, DEBUG) without key/password leaks.
* **FR-14 — Error Handling:** Graceful error handling for missing files, bad passwords, capacity limits, corrupted payload.

---

# 9. Payload Structure

```text
┌─────────────────────────────┐
│ Crypta Magic Header         │
├─────────────────────────────┤
│ Version                     │
├─────────────────────────────┤
│ Salt                        │
├─────────────────────────────┤
│ Nonce                       │
├─────────────────────────────┤
│ Original Filename           │
├─────────────────────────────┤
│ Original File Size          │
├─────────────────────────────┤
│ SHA-256 Hash                │
├─────────────────────────────┤
│ Encrypted Payload           │
└─────────────────────────────┘
```

---

# 10. Core Operational Workflows

### 10.1 Secure Hiding Workflow
Secret File $\rightarrow$ SHA-256 Hash $\rightarrow$ Argon2id Key Derivation $\rightarrow$ AES-GCM Encryption $\rightarrow$ Payload Packaging $\rightarrow$ Capacity Validation $\rightarrow$ LSB Encoding $\rightarrow$ Output PNG

### 10.2 Extraction Workflow
Stego Image $\rightarrow$ LSB Extraction $\rightarrow$ Magic Header Check $\rightarrow$ Payload Parsing $\rightarrow$ Password Prompt $\rightarrow$ Argon2id $\rightarrow$ AES-GCM Decrypt $\rightarrow$ SHA-256 Verification $\rightarrow$ Recovered File

### 10.3 Steganalysis Workflow
Input Image $\rightarrow$ Metadata Analysis $\rightarrow$ Entropy Analysis $\rightarrow$ LSB Analysis $\rightarrow$ Chi-Square Analysis $\rightarrow$ Histogram Analysis $\rightarrow$ Risk Engine (0–100 Score) $\rightarrow$ Assessment

---

# 11. CLI Command Specification

| Command | Purpose |
|---|---|
| `crypta --help` | Display help |
| `crypta --version` | Display version |
| `crypta hide <cover> <secret> <output>` | Hide a file |
| `crypta extract <stego>` | Extract a file |
| `crypta capacity <image>` | Calculate image capacity |
| `crypta info <image>` | Display image information |
| `crypta analyze <image>` | Perform steganalysis |
| `crypta report <image>` | Generate analysis report |

---

# 12. Non-Functional Requirements

* **NFR-01 Security:** Authenticated AES-GCM encryption, Argon2id, CSPRNG salt & nonce, hash validation, zero password logging.
* **NFR-02 Performance:** Memory-efficient image bitwise processing.
* **NFR-03 Usability:** Clean, user-friendly CLI with Rich console output and helpful diagnostics.
* **NFR-04 Maintainability:** Highly modular package structure.
* **NFR-05 Portability:** Cross-platform support (Kali Linux & Windows Terminal, Python 3.9+).

---

# 13. Proposed Project Structure

```text
Crypta/
├── crypta/
│   ├── __init__.py
│   ├── cli/
│   │   ├── commands.py
│   │   └── interface.py
│   ├── steganography/
│   │   ├── encoder.py
│   │   ├── decoder.py
│   │   ├── lsb.py
│   │   ├── capacity.py
│   │   └── payload.py
│   ├── cryptography/
│   │   ├── encryption.py
│   │   ├── decryption.py
│   │   └── key_derivation.py
│   ├── steganalysis/
│   │   ├── entropy.py
│   │   ├── lsb_analysis.py
│   │   ├── chi_square.py
│   │   ├── histogram.py
│   │   └── risk_score.py
│   ├── forensics/
│   │   ├── metadata.py
│   │   ├── hashing.py
│   │   └── file_analysis.py
│   ├── reporting/
│   │   ├── report_generator.py
│   │   └── templates/
│   └── utils/
│       ├── validators.py
│       ├── logger.py
│       └── constants.py
├── tests/
├── samples/
├── reports/
├── docs/
├── requirements.txt
├── pyproject.toml
├── README.md
└── LICENSE
```

---

# 14. Technology Stack

| Component | Technology |
|---|---|
| Programming Language | Python 3 (3.9+) |
| Primary OS | Kali Linux |
| Secondary OS | Windows (Terminal / PowerShell) |
| Interface | CLI (`argparse` / `click` / `rich`) |
| Image Processing | Pillow (`PIL`) |
| Encryption | `cryptography` (AESGCM, Argon2id) |
| Hashing | `hashlib` (SHA-256) |
| Numerical Analysis | NumPy |
| Visualization | Matplotlib |
| Testing | Pytest |
| Reporting | HTML + JSON |
