# Functional Requirements Document (FRD)

## Project: Crypta

**Project Title:** Crypta — Steganography, Cryptography & Steganalysis Toolkit  
**Version:** 1.0  
**Platform:** Kali Linux / Cross-platform Python 3  
**Language:** Python 3  
**Interface:** Command Line Interface (CLI)  
**Project Type:** Cybersecurity Tool  
**Development Duration:** 2 Days  

---

# 1. Introduction

## 1.1 Purpose

Crypta is a Python-based command-line cybersecurity toolkit designed to securely hide sensitive information inside digital images and analyze images for potential steganographic content.

The system combines **steganography, cryptography, integrity verification, statistical steganalysis, and basic digital forensics** into a single terminal-based security tool.

The primary goal is to provide a lightweight security utility that can:

* Hide sensitive files inside images.
* Encrypt payloads before embedding them.
* Extract and decrypt hidden payloads.
* Verify payload integrity.
* Analyze images for potential steganographic manipulation.
* Calculate a steganography risk score.
* Generate analysis reports.

---

# 2. Problem Statement

Traditional file-hiding techniques can protect information through encryption, but encrypted files are still visibly identifiable as sensitive data.

Steganography addresses this problem by concealing the existence of the information within an apparently normal media file.

However, a basic steganography implementation does not provide sufficient security because:

* Hidden data may be extracted.
* Plaintext payloads can be exposed.
* Payload corruption may go undetected.
* There may be no way to analyze suspicious media.
* There is usually no forensic or statistical analysis capability.

**Crypta addresses these limitations by combining encryption, steganographic embedding, integrity verification, and steganalysis within one CLI-based cybersecurity toolkit.**

---

# 3. Objectives

Crypta aims to:

1. Implement practical image-based steganography.
2. Support hiding arbitrary files rather than only text.
3. Encrypt payloads before embedding them.
4. Protect encryption keys through secure password-based key derivation.
5. Verify extracted payload integrity.
6. Analyze images using statistical steganalysis techniques.
7. Produce a risk score indicating the likelihood of suspicious characteristics.
8. Provide basic file and metadata analysis.
9. Generate machine-readable and human-readable reports.
10. Provide a professional and easy-to-use CLI interface.

---

# 4. Scope

## 4.1 In Scope

### Steganography
* PNG image support.
* BMP image support if time permits.
* LSB-based data embedding.
* LSB-based data extraction.
* Arbitrary binary file payloads.
* Capacity calculation.

### Cryptography
* AES-GCM encryption.
* Password-based key derivation using Argon2id.
* Secure random salt generation.
* Secure nonce generation.

### Integrity
* SHA-256 hashing.
* Payload integrity verification.
* Corruption detection.

### Steganalysis
* Entropy analysis.
* LSB distribution analysis.
* Chi-square statistical analysis.
* Basic histogram/pixel analysis.
* Combined risk scoring.

### Forensics
* File information.
* Image properties.
* Basic metadata extraction.
* Cryptographic hashes.

### Reporting
* HTML report.
* JSON report.
* Statistical analysis results.
* Risk score and conclusion.

### CLI
* Command-based interface.
* Help system.
* Verbose mode.
* Error handling.
* Logging.

---

## 4.2 Out of Scope for Version 1.0

To keep the project achievable within two days:

* JPEG steganography.
* Audio/video steganography.
* Machine-learning-based steganalysis.
* GUI/web interface.
* Network communication.
* Cloud storage.
* Advanced anti-forensics.
* Real-world automated threat intelligence.
* Multiple sophisticated embedding algorithms.

These can be listed as **future enhancements**.

---

# 5. Target Users

Crypta is intended for:

* Cybersecurity students.
* Security researchers.
* Digital forensics learners.
* Penetration-testing/security lab users.
* System administrators.
* Researchers studying steganography and steganalysis.

The tool should be used for **authorized security testing and educational/research purposes**.

---

# 6. System Architecture

```text
                         ┌───────────────────┐
                         │      CRYPTA       │
                         │     CLI Layer     │
                         └─────────┬─────────┘
                                   │
          ┌────────────────────────┼────────────────────────┐
          │                        │                        │
          ▼                        ▼                        ▼
 ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
 │ Steganography   │      │ Cryptography    │      │  Steganalysis   │
 │ Engine          │      │ Engine          │      │  Engine         │
 └────────┬────────┘      └────────┬────────┘      └────────┬────────┘
          │                        │                        │
          ▼                        ▼                        ▼
     LSB Encoder              AES-GCM                 Statistics
     LSB Decoder              Argon2id                Entropy
     Capacity                 Key Management           LSB Analysis
                                                      Chi-Square
          │                        │                        │
          └────────────────────────┼────────────────────────┘
                                   │
                                   ▼
                         ┌───────────────────┐
                         │ Forensic Analysis │
                         └─────────┬─────────┘
                                   │
                                   ▼
                         ┌───────────────────┐
                         │ Reporting Engine  │
                         └─────────┬─────────┘
```

---

# 7. Functional Requirements

## FR-01: CLI Interface
The system shall provide a command-line interface for interacting with all major functions.
Example: `crypta --help`

The CLI shall provide:
* Commands
* Arguments
* Options
* Help messages
* Version information
* Error messages

---

## FR-02: Hide Data
The system shall allow users to embed a file inside a supported image.
Example: `crypta hide cover.png secret.pdf output.png`

The system shall:
1. Validate the carrier image.
2. Validate the payload.
3. Calculate available capacity.
4. Verify that the payload fits.
5. Calculate payload integrity information.
6. Encrypt the payload when encryption is enabled.
7. Package the payload.
8. Embed the payload using LSB.
9. Generate the output image.

---

## FR-03: Extract Data
The system shall extract hidden Crypta payloads from a supported image.
Example: `crypta extract output.png`

The system shall:
1. Detect a Crypta payload.
2. Extract the payload.
3. Request the password when encryption is enabled.
4. Decrypt the payload.
5. Recover the original file.
6. Verify SHA-256 integrity.
7. Report the extraction status.

---

## FR-04: Payload Encryption
Crypta shall encrypt sensitive payloads before embedding them using Argon2id key derivation and AES-GCM authenticated encryption. Password shall never be stored in the carrier image. Secure random salt and nonce shall be generated.

---

## FR-05: Payload Integrity
Crypta shall calculate a SHA-256 hash for the original payload and verify it upon extraction.

---

## FR-06: Capacity Calculation
Crypta shall determine how much data a carrier image can hold and enforce limits before embedding.
Example: `crypta capacity image.png`

---

## FR-07: File Information
Crypta shall provide basic information about a file, including dimensions, color mode, channels, bit depth, hashes, etc.
Example: `crypta info image.png`

---

## FR-08: Metadata Analysis
Crypta shall inspect available image metadata and distinguish between present metadata and clean metadata.

---

## FR-09: Steganalysis
Crypta shall analyze images for steganographic manipulation using:
1. Entropy Analysis
2. LSB Analysis
3. Chi-Square Analysis
4. Histogram Analysis
Example: `crypta detect suspicious.png`

---

## FR-10: Risk Scoring
Crypta shall combine results from multiple steganalysis techniques into a normalized score from **0–100** (LOW, MODERATE, HIGH, VERY HIGH).

---

## FR-11: Analysis Command
Crypta shall provide a unified analysis command displaying file info, image stats, entropy, LSB, Chi-square, histogram, and risk score.
Example: `crypta analyze image.png`

---

## FR-12: Report Generation
Crypta shall generate structured reports in HTML and JSON formats.
Example: `crypta report suspicious.png`

---

## FR-13: Logging & Verbosity
Crypta shall provide clear logging for operations and a `--verbose` flag for diagnostic output.

---

## FR-14: Error Handling
Crypta shall handle common errors gracefully without exposing sensitive credentials or keys.

---

# 8. Non-Functional Requirements

* **NFR-01 Security:** No stored passwords, secure primitives (Argon2id, AES-GCM, SHA-256), authenticated encryption.
* **NFR-02 Performance:** Efficient PNG handling, responsive CLI execution.
* **NFR-03 Usability:** Simple, consistent command structure (`crypta hide`, `extract`, `detect`, `capacity`, `info`, `analyze`, `report`).
* **NFR-04 Maintainability:** Modular architecture (`steganography`, `cryptography`, `steganalysis`, `forensics`, `reporting`, `cli`, `utils`).
* **NFR-05 Portability:** Python 3 standard/common libraries targeting Kali Linux and cross-platform terminal environments.

---

# 9. Proposed Project Structure

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
├── requirements.txt
├── README.md
├── LICENSE
└── pyproject.toml
```

---

# 10. Core Development Scope & MVP Goal

1. **Day 1 Goal:** Hide $\rightarrow$ Encrypt $\rightarrow$ Embed $\rightarrow$ Extract $\rightarrow$ Decrypt $\rightarrow$ Integrity Check $\rightarrow$ Recover file.
2. **Day 2 Goal:** Steganalysis modules (Entropy, LSB, Chi-Square, Histogram) $\rightarrow$ Risk Scoring Engine $\rightarrow$ Forensics & HTML/JSON Report Generator $\rightarrow$ Polish, CLI UX & Testing.
