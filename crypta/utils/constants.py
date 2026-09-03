"""
Centralized constants for Crypta Toolkit.
"""

APPLICATION_NAME = "Crypta"
VERSION = "1.0.0"
DESCRIPTION = "Steganography, Cryptography & Steganalysis Toolkit"
TAGLINE = "Steganography | Cryptography | Steganalysis"

# Carrier Image Constants
SUPPORTED_IMAGE_FORMATS = [".png"]

# Status Symbols
PREFIX_SUCCESS = "[+]"
PREFIX_ERROR = "[-]"
PREFIX_INFO = "[*]"
PREFIX_WARNING = "[!]"
PREFIX_DEBUG = "[DEBUG]"

# Crypta Binary Payload Header Specification
MAGIC_BYTES = b"CRYPTA\x01"
HEADER_VERSION_LEGACY = 1
HEADER_VERSION = 2

# Argon2id Password-Based Key Derivation Parameters
ARGON2_MEMORY_COST = 65536  # KiB (64 MiB)
ARGON2_TIME_COST = 3
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32  # Bytes (256 bits)

# AES-256-GCM Cryptographic Parameters
SALT_SIZE_BYTES = 16  # 128-bit salt
NONCE_SIZE_BYTES = 12  # 96-bit AES-GCM nonce
SHA256_DIGEST_SIZE_BYTES = 32  # 256-bit SHA-256 integrity hash
AES_GCM_TAG_SIZE_BYTES = 16  # 128-bit authentication tag

# Risk Assessment Level Labels & Thresholds
RISK_LEVEL_LOW = "LOW"
RISK_LEVEL_MODERATE = "MODERATE"
RISK_LEVEL_HIGH = "HIGH"
RISK_LEVEL_VERY_HIGH = "VERY HIGH"

RISK_THRESHOLD_LOW_MAX = 29
RISK_THRESHOLD_MODERATE_MAX = 59
RISK_THRESHOLD_HIGH_MAX = 79

# Heuristic Risk Indicator Weights
RISK_WEIGHT_LSB = 0.30
RISK_WEIGHT_CHI_SQUARE = 0.30
RISK_WEIGHT_HISTOGRAM = 0.20
RISK_WEIGHT_ENTROPY = 0.10
RISK_WEIGHT_PIXEL_STATS = 0.10


