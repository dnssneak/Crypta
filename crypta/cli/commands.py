"""
Command routing handlers for Crypta CLI commands.
Delegates hide and extract operations to crypta.core.pipeline orchestration layer.
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
)
from crypta.core import (
    hide_file,
    extract_file,
    CapacityError,
    CarrierValidationError,
    OutputCollisionError,
)
from crypta.cryptography import CryptaError, AuthenticationError, DecryptionError, EncryptionError
from crypta.steganalysis import analyze_image
from crypta.forensics import analyze_forensics
from crypta.reporting import build_report





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
        password = getpass.getpass("Enter encryption password: ")
        confirm_password = getpass.getpass("Confirm encryption password: ")
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

    print(info("Preparing secure steganographic operation..."))

    try:
        res = hide_file(
            carrier_path=carrier_path,
            secret_path=secret_path,
            output_path=output_path,
            password=password,
            overwrite=True,
        )
    except CapacityError as err:
        print(error("Insufficient carrier capacity."))
        print(muted(str(err)))
        return 1
    except OutputCollisionError as err:
        print(error(str(err)))
        return 1
    except CarrierValidationError as err:
        print(error(str(err)))
        return 1
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

    print(success("Carrier validated"))
    print(success("Payload file validated"))
    print(success("Capacity check passed"))
    print(info("Calculating file integrity..."))
    print(success(f"SHA-256 calculated: {res.sha256_hash[:16]}..."))
    print(info("Deriving encryption key..."))
    print(success("Encryption initialized"))
    print(info("Encrypting payload..."))
    print(success("Payload encrypted"))
    print(info("Building Crypta payload..."))
    print(success("Payload prepared"))
    print(info("Embedding payload..."))
    print(success("Payload embedded successfully"))
    print()

    print(heading("----------------------------------------------------"))
    print(heading("Steganography Result"))
    print(heading("----------------------------------------------------"))
    print(f"  Carrier       : {res.carrier_path.name}")
    print(f"  Payload       : {res.secret_path.name}")
    print(f"  Output        : {res.output_path.name}")
    print(f"  Original Size : {format_size_bytes(res.original_size_bytes)}")
    print(f"  Payload Size  : {format_size_bytes(res.serialized_size_bytes)}")
    print()

    print(success("Secure stego image created successfully"))
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
        password = getpass.getpass("Enter decryption password: ")
    except (KeyboardInterrupt, EOFError):
        print()
        print(error("Operation cancelled by user."))
        return 1

    if not password:
        print(error("Password cannot be empty."))
        return 1

    print(info(f"Inspecting stego image '{Path(stego_image).name}'..."))

    try:
        res = extract_file(
            stego_path=stego_image,
            password=password,
            output_destination=output_dest,
            overwrite=True,
        )
    except (AuthenticationError, DecryptionError):
        print(error("Decryption failed: invalid password or corrupted payload"))
        return 1
    except OutputCollisionError as err:
        print(error(str(err)))
        return 1
    except CarrierValidationError as err:
        print(error(str(err)))
        return 1
    except FileNotFoundError as err:
        print(error(str(err)))
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

    print(success("Carrier validated"))
    print(info("Extracting Crypta payload..."))
    print(success("Crypta payload detected"))
    print(info("Deriving encryption key..."))
    print(info("Decrypting payload..."))
    print(success("Authentication successful"))
    print(info("Verifying file integrity..."))
    print(success(f"SHA-256 verified: {res.sha256_hash[:16]}..."))
    print()

    print(heading("----------------------------------------------------"))
    print(heading("Extraction Result"))
    print(heading("----------------------------------------------------"))
    print(f"  Filename : {res.restored_filename}")
    print(f"  Size     : {format_size_bytes(res.recovered_size_bytes)}")
    print(f"  Output   : {res.output_path}")
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
    if not hasattr(args, "image") or not args.image:
        print(error("Missing required argument: image path to inspect."))
        print(muted("Usage: crypta info <image_path>"))
        return 1

    image_path = args.image
    print(info("Analyzing image..."))
    print()

    try:
        res = analyze_forensics(image_path)
    except FileNotFoundError as err:
        print(error(f"Target file not found: {image_path}"))
        return 1
    except ValueError as err:
        print(error(str(err)))
        return 1
    except Exception as err:
        print(error("Unable to analyze image."))
        print(muted(f"Diagnostic error: {err}"))
        return 1

    f = res.file
    fmt = res.format
    img = res.image
    png = res.png_structure
    meta = res.metadata

    print(heading("File"))
    print(heading("────────────────────────────────"))
    print(f"  Name            : {f.file_name}")
    print(f"  Format          : {fmt.detected_format}")
    match_str = "YES" if fmt.extension_match else "NO (MISMATCH DETECTED)"
    if fmt.extension_match:
        print(f"  Extension Match : {match_str}")
    else:
        print(f"  Extension Match : {warning(match_str)}")
    print(f"  Size            : {f.size_human}")

    print(f"  SHA-256         : {f.sha256_hash}")
    print(f"  Modified Time   : {f.modified_time}")
    print()

    print(heading("Image"))
    print(heading("────────────────────────────────"))
    print(f"  Dimensions      : {img.dimensions_str}")
    print(f"  Mode            : {img.mode}")
    print(f"  Channels        : {img.channels}")
    if img.bits_per_channel:
        print(f"  Bit Depth       : {img.bits_per_channel}")
    print()

    if png:
        print(heading("PNG Structure"))
        print(heading("────────────────────────────────"))
        sig_str = "Valid" if png.signature_valid else "Invalid"
        print(f"  Signature       : {sig_str}")
        print(f"  Color Type      : {png.color_type_desc}")
        print(f"  Compression     : {png.compression_method}")
        print(f"  Filter Method   : {png.filter_method}")
        print(f"  Interlace       : {png.interlace_method}")
        print()

    print(heading("Metadata"))
    print(heading("────────────────────────────────"))
    exif_str = f"Present ({len(meta.exif_tags)} tags)" if meta.exif_present else "Not present"
    print(f"  EXIF            : {exif_str}")
    text_str = f"{meta.text_entry_count} entries" if meta.text_entry_count > 0 else "None"
    print(f"  Text Metadata   : {text_str}")

    if meta.text_metadata:
        for k, v in meta.text_metadata.items():
            v_disp = v[:80] + "..." if len(v) > 80 else v
            print(f"    - {k:<14} : {v_disp}")
    print()

    if res.warnings:
        for w in res.warnings:
            print(warning(w))
        print()

    print(success("Forensic information collected successfully"))
    return 0


def handle_analyze(args: Namespace) -> int:
    """Handler for the 'analyze' command."""
    if not hasattr(args, "image") or not args.image:
        print(error("Missing required argument: image path to analyze."))
        print(muted("Usage: crypta analyze <image_path> [--visualize]"))
        return 1


    image_path = args.image
    do_visualize = getattr(args, "visualize", False)

    print(info("Starting steganalysis..."))

    try:
        res = analyze_image(image_path, visualize=do_visualize)
    except FileNotFoundError as err:
        print(error(f"Target image not found: {image_path}"))
        return 1
    except ValueError as err:
        print(error(str(err)))
        return 1
    except Exception as err:
        print(error("Stegananalysis failed."))
        print(muted(f"Diagnostic error: {err}"))
        return 1

    info_meta = res.image_info

    print(success("Carrier validated"))
    print(success("PNG image detected"))
    ch_str = ", ".join(info_meta.analyzed_channels)
    print(success(f"{ch_str} channels selected"))
    if info_meta.alpha_excluded:
        print(muted("  (Alpha channel excluded from LSB analysis)"))
    print()

    print(heading("────────────────────────────────────────"))
    print(heading("Image Analysis"))
    print(heading("────────────────────────────────────────"))
    print(f"  File       : {info_meta.file_name}")
    print(f"  Dimensions : {info_meta.dimensions_str}")
    print(f"  Mode       : {info_meta.mode}")
    print(f"  Channels   : {info_meta.channels}")
    print()

    print(heading("────────────────────────────────────────"))
    print(heading("Entropy Analysis"))
    print(heading("────────────────────────────────────────"))
    print(f"  Overall : {res.entropy.overall_entropy:.2f} / 8.00")
    for ch in info_meta.analyzed_channels:
        e_val = res.entropy.per_channel_entropy.get(ch, 0.0)
        print(f"  {ch:<7} : {e_val:.2f}")
    print()

    print(heading("────────────────────────────────────────"))
    print(heading("LSB Distribution"))
    print(heading("────────────────────────────────────────"))
    print(f"  {'Channel':<10} {'0-bit':<10} {'1-bit':<10} {'Deviation':<10}")
    for ch in info_meta.analyzed_channels:
        p0 = res.lsb_analysis.zero_percentages.get(ch, 0.0)
        p1 = res.lsb_analysis.one_percentages.get(ch, 0.0)
        dev = res.lsb_analysis.deviations.get(ch, 0.0)
        print(f"  {ch:<10} {p0:>5.1f}%     {p1:>5.1f}%     {dev:>5.1f}%")
    print()

    print(heading("────────────────────────────────────────"))
    print(heading("Chi-Square Analysis"))
    print(heading("────────────────────────────────────────"))
    print(f"  {'Channel':<10} {'Statistic':<12} {'DoF':<8} {'p-value':<10}")
    for ch in info_meta.analyzed_channels:
        stat = res.chi_square.statistics.get(ch, 0.0)
        dof = res.chi_square.degrees_of_freedom.get(ch, 0)
        pval = res.chi_square.p_values.get(ch)
        pval_str = f"{pval:.6f}" if pval is not None else "N/A"
        print(f"  {ch:<10} {stat:<12.2f} {dof:<8} {pval_str:<10}")
    print()

    print(heading("────────────────────────────────────────"))
    print(heading("Histogram / Pixel Analysis"))
    print(heading("────────────────────────────────────────"))
    print(f"  {'Channel':<8} {'Min':<6} {'Max':<6} {'Mean':<8} {'Median':<8} {'Std Dev':<8} {'Unique':<8} {'LSB Trans':<10}")
    for ch in info_meta.analyzed_channels:
        st = res.histogram.channel_stats.get(ch, {})
        u_val = res.pixel_statistics.unique_values.get(ch, 0)
        t_freq = res.pixel_statistics.lsb_transition_frequencies.get(ch, 0.0)
        print(
            f"  {ch:<8} {st.get('min', 0):<6.0f} {st.get('max', 0):<6.0f} "
            f"{st.get('mean', 0.0):<8.2f} {st.get('median', 0.0):<8.2f} "
            f"{st.get('std_dev', 0.0):<8.2f} {u_val:<8} {t_freq * 100:>5.1f}%"
        )
    print()

    if res.risk_assessment:
        ra = res.risk_assessment
        print(heading("────────────────────────────────────────"))
        print(heading("Risk Assessment"))
        print(heading("────────────────────────────────────────"))

        if ra.level == "LOW":
            lvl_str = success(ra.level)
        elif ra.level == "MODERATE":
            lvl_str = warning(ra.level)
        else:
            lvl_str = error(ra.level)

        print(f"  Risk Score       : {ra.score}/100")
        print(f"  Risk Level       : {lvl_str}")
        print()

        print(heading("Indicators"))
        print(heading("────────────────────────────────────────"))
        print(f"  Entropy          : {ra.indicator_scores.get('entropy', 0.0):>5.1f}/100 (Weight: {ra.weights.get('entropy', 0.1):.0%})")
        print(f"  LSB Distribution : {ra.indicator_scores.get('lsb', 0.0):>5.1f}/100 (Weight: {ra.weights.get('lsb', 0.3):.0%})")
        print(f"  Chi-Square       : {ra.indicator_scores.get('chi_square', 0.0):>5.1f}/100 (Weight: {ra.weights.get('chi_square', 0.3):.0%})")
        print(f"  Histogram        : {ra.indicator_scores.get('histogram', 0.0):>5.1f}/100 (Weight: {ra.weights.get('histogram', 0.2):.0%})")
        print(f"  Pixel Statistics : {ra.indicator_scores.get('pixel_statistics', 0.0):>5.1f}/100 (Weight: {ra.weights.get('pixel_statistics', 0.1):.0%})")
        print()

        if ra.observations:
            print(heading("Key Observations"))
            print(heading("────────────────────────────────────────"))
            for obs in ra.observations:
                if obs.startswith("[!] "):
                    print(f"  {warning(obs[4:])}")
                elif obs.startswith("[!]"):
                    print(f"  {warning(obs[3:])}")
                else:
                    print(f"  • {obs}")
            print()

        print(heading("Assessment"))
        print(heading("────────────────────────────────────────"))
        for line in ra.assessment.split("\n"):
            if line.startswith("[!] "):
                print(f"  {warning(line[4:])}")
            elif line.startswith("[!]"):
                print(f"  {warning(line[3:])}")
            elif line:
                print(f"  {line}")
        print()

    print(success("Analysis completed"))
    return 0




def handle_report(args: Namespace) -> int:
    """Handler for the 'report' command."""
    if not hasattr(args, "image") or not args.image:
        print(error("Missing required argument: image path for report generation."))
        print(muted("Usage: crypta report <image_path> [--format html|json|both] [--output <dir>]"))
        return 1

    image_path = args.image
    format_choice = getattr(args, "format", "both") or "both"
    output_dir = getattr(args, "output", None)

    print(info("Initializing report generator..."))
    print(info(f"Target image  : {image_path}"))
    print(info(f"Report format : {format_choice}"))
    print()

    try:
        print(info("Running forensic analysis & steganalysis..."))
        generated_files = build_report(
            image_path=image_path,
            output_dir=output_dir,
            format_choice=format_choice,
        )
    except FileNotFoundError as err:
        print(error(f"Target image not found: {image_path}"))
        return 1
    except ValueError as err:
        print(error(str(err)))
        return 1
    except Exception as err:
        print(error("Report generation failed."))
        print(muted(f"Diagnostic error: {err}"))
        return 1

    print()
    if "html" in generated_files:
        print(success(f"HTML report generated: {generated_files['html']}"))
    if "json" in generated_files:
        print(success(f"JSON report generated: {generated_files['json']}"))
    print()
    print(success("Report generation complete"))
    return 0

