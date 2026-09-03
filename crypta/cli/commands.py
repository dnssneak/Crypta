"""
Command routing handlers for Crypta CLI commands.
Integrates AES-256-GCM + Argon2id encryption layer with LSB Steganography.
"""

import getpass
from pathlib import Path
from argparse import Namespace
from crypta.cli.styling import info, warning, success, error, heading, muted
from crypta.steganography import (
    validate_carrier_image,
    calculate_raw_capacity_bytes,
    calculate_usable_capacity_bytes,
    format_size_bytes,
    DEFAULT_PAYLOAD_OVERHEAD_BYTES,
    embed_payload,
    extract_payload,
)
from crypta.cryptography import CryptaError, AuthenticationError, DecryptionError, EncryptionError


def handle_hide(args: Namespace) -> int:
    """Handler for the 'hide' command."""
    if not hasattr(args, "carrier") or not args.carrier:
        print(error("Missing required argument: carrier image path."))
        print(muted("Usage: crypta hide <carrier_image> <secret_file> <output_image>"))
        return 1
    if not hasattr(args, "secret") or not args.secret:
        print(error("Missing required argument: secret payload file path."))
        print(muted("Usage: crypta hide <carrier_image> <secret_file> <output_image>"))
        return 1
    if not hasattr(args, "output") or not args.output:
        print(error("Missing required argument: output stego image path."))
        print(muted("Usage: crypta hide <carrier_image> <secret_file> <output_image>"))
        return 1

    carrier_path = args.carrier
    secret_path = args.secret
    output_path = args.output

    try:
        password = getpass.getpass("Enter password: ")
        confirm_password = getpass.getpass("Confirm password: ")
    except (KeyboardInterrupt, EOFError):
        print()
        print(error("Operation cancelled by user."))
        return 1

    if password != confirm_password:
        print(error("Passwords do not match."))
        return 1

    if not password:
        print(error("Password cannot be empty."))
        return 1

    print(success("Password accepted"))
    print(success("Encryption initialized"))
    print(info("Encrypting payload..."))

    try:
        out_file = embed_payload(carrier_path, secret_path, output_path, password=password)
    except FileNotFoundError as err:
        print(error(str(err)))
        return 1
    except ValueError as err:
        print(error(str(err)))
        return 1
    except EncryptionError as err:
        print(error("Encryption operation failed."))
        print(muted(f"Diagnostic error: {err}"))
        return 1
    except CryptaError as err:
        print(error(str(err)))
        return 1
    except Exception as err:
        print(error("Failed to embed steganographic payload."))
        print(muted(f"Diagnostic error: {err}"))
        return 1

    carrier_name = Path(carrier_path).name
    secret_name = Path(secret_path).name
    payload_size = Path(secret_path).stat().st_size

    print(success("Payload encrypted"))
    print(info("Embedding encrypted payload..."))
    print(success("Payload embedded successfully"))
    print()

    print(heading("----------------------------------------------------"))
    print(heading("Steganography Result"))
    print(heading("----------------------------------------------------"))
    print(f"  Carrier : {carrier_name}")
    print(f"  Payload : {secret_name}")
    print(f"  Output  : {out_file.name}")
    print(f"  Size    : {format_size_bytes(payload_size)}")
    print()

    print(success("Stego image created successfully"))
    return 0


def handle_extract(args: Namespace) -> int:
    """Handler for the 'extract' command."""
    if not hasattr(args, "image") or not args.image:
        print(error("Missing required argument: stego image path."))
        print(muted("Usage: crypta extract <stego_image> [-o <output_path>]"))
        return 1

    stego_image = args.image
    output_dest = getattr(args, "output", None)

    try:
        password = getpass.getpass("Enter password: ")
    except (KeyboardInterrupt, EOFError):
        print()
        print(error("Operation cancelled by user."))
        return 1

    if not password:
        print(error("Password cannot be empty."))
        return 1

    print(info(f"Inspecting stego image '{Path(stego_image).name}'..."))
    print(info("Extracting payload..."))

    try:
        out_path, restored_filename, payload_size = extract_payload(
            stego_image, password=password, output_destination=output_dest
        )
    except FileNotFoundError as err:
        print(error(str(err)))
        return 1
    except (AuthenticationError, DecryptionError):
        print(error("Decryption failed: invalid password or corrupted payload"))
        return 1
    except ValueError as err:
        print(error(str(err)))
        return 1
    except CryptaError as err:
        print(error(str(err)))
        return 1
    except Exception as err:
        print(error("Failed to extract hidden payload."))
        print(muted(f"Diagnostic error: {err}"))
        return 1

    print(success("Crypta payload detected"))
    print(info("Deriving encryption key..."))
    print(info("Decrypting payload..."))
    print(success("Authentication successful"))
    print(success("File integrity verified"))
    print()

    print(heading("----------------------------------------------------"))
    print(heading("Extraction Result"))
    print(heading("----------------------------------------------------"))
    print(f"  Filename : {restored_filename}")
    print(f"  Size     : {format_size_bytes(payload_size)}")
    print(f"  Output   : {out_path}")
    print()

    print(success("File recovered successfully"))
    return 0


def handle_capacity(args: Namespace) -> int:
    """Handler for the 'capacity' command."""
    if not hasattr(args, "image") or not args.image:
        print(error("Missing required argument: carrier image path."))
        print(muted("Usage: crypta capacity <carrier_image>"))
        return 1

    image_path = args.image
    print(info(f"Inspecting carrier image '{image_path}'..."))

    try:
        carrier = validate_carrier_image(image_path)
    except FileNotFoundError as err:
        print(error(f"Carrier image not found: {image_path}"))
        return 1
    except ValueError as err:
        print(error(str(err)))
        return 1
    except Exception as err:
        print(error("Unable to validate carrier image."))
        print(warning("The image may be corrupted, unreadable, or invalid."))
        print(muted(f"Diagnostic error: {err}"))
        return 1

    print(success("Carrier validated successfully"))
    print()

    print(heading("----------------------------------------------------"))
    print(heading("Carrier Information"))
    print(heading("----------------------------------------------------"))
    print(f"  File       : {carrier.path.name}")
    print(f"  Format     : {carrier.format}")
    print(f"  Dimensions : {carrier.dimensions_str}")
    print(f"  Color Mode : {carrier.mode}")
    print(f"  Channels   : {carrier.channels}")
    print(f"  File Size  : {format_size_bytes(carrier.file_size_bytes)}")
    print()

    raw_bytes = calculate_raw_capacity_bytes(carrier)
    usable_bytes = calculate_usable_capacity_bytes(carrier)

    print(heading("----------------------------------------------------"))
    print(heading("Capacity Analysis"))
    print(heading("----------------------------------------------------"))
    print(f"  Raw Capacity    : {format_size_bytes(raw_bytes)}")
    print(f"  Reserved Space  : {DEFAULT_PAYLOAD_OVERHEAD_BYTES} Bytes (Crypta Header & Digest)")
    print(f"  Usable Capacity : {format_size_bytes(usable_bytes)}")
    print()

    print(success("Carrier is suitable for Crypta LSB steganography"))
    return 0


def handle_info(args: Namespace) -> int:
    """Handler for the 'info' command."""
    print(info("Info command initialized."))
    if hasattr(args, "image") and args.image:
        print(muted(f"    Target file: {args.image}"))
    print(warning("File and metadata forensic inspection will be implemented in Feature 5."))
    return 0


def handle_analyze(args: Namespace) -> int:
    """Handler for the 'analyze' command."""
    print(info("Analyze command initialized."))
    if hasattr(args, "image") and args.image:
        print(muted(f"    Target image: {args.image}"))
    print(warning("Statistical steganalysis will be implemented in Feature 5."))
    return 0


def handle_report(args: Namespace) -> int:
    """Handler for the 'report' command."""
    print(info("Report command initialized."))
    if hasattr(args, "image") and args.image:
        print(muted(f"    Target image: {args.image}"))
    if hasattr(args, "format") and args.format:
        print(muted(f"    Report format: {args.format}"))
    print(warning("Forensic report generation will be implemented in Feature 6."))
    return 0
