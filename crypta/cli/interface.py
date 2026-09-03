"""
Main CLI Interface, Argument Parser, and Interactive REPL Shell for Crypta.
Uses Python standard argparse and shlex with custom terminal styling and routing.
"""

import os
import sys
import shlex
import argparse
from typing import List, Optional

from crypta.utils.constants import APPLICATION_NAME, VERSION, DESCRIPTION
from crypta.utils.terminal import init_terminal, set_color_enabled, colorize, Colors
from crypta.utils.logger import setup_logger
from crypta.cli.styling import banner, heading, info, error, muted, warning, success
from crypta.cli.commands import (
    handle_hide,
    handle_extract,
    handle_capacity,
    handle_info,
    handle_analyze,
    handle_report,
)


class CryptaArgumentParser(argparse.ArgumentParser):
    """Custom ArgumentParser providing styled error handling."""

    def error(self, message: str) -> None:
        print(error(f"Invalid command syntax: {message}"), file=sys.stderr)
        print(muted("Use 'crypta --help' or 'crypta <command> --help' for usage guidance."), file=sys.stderr)
        sys.exit(2)


def create_parser() -> argparse.ArgumentParser:
    """Build and configure the Crypta CLI argument parser."""
    parser = CryptaArgumentParser(
        prog="crypta",
        description=f"{APPLICATION_NAME} — {DESCRIPTION}",
        add_help=False,
    )

    # Global Options
    global_group = parser.add_argument_group("Global Options")
    global_group.add_argument(
        "-h", "--help", action="store_true", help="Show this help message and exit"
    )
    global_group.add_argument(
        "-v", "--version", action="store_true", help="Show version information and exit"
    )
    global_group.add_argument(
        "--no-color", action="store_true", help="Disable colored terminal output"
    )
    global_group.add_argument(
        "--verbose", action="store_true", help="Enable verbose diagnostic logging"
    )

    # Subcommands Parser
    subparsers = parser.add_subparsers(dest="command", title="Commands", metavar="<command>")

    # Command: HIDE
    hide_parser = subparsers.add_parser(
        "hide",
        help="Hide an encrypted file inside a carrier image",
        description="Hide an encrypted file inside a supported PNG carrier image.",
        add_help=False,
    )
    hide_parser.add_argument("carrier", nargs="?", help="Path to cover carrier PNG image")
    hide_parser.add_argument("secret", nargs="?", help="Path to secret file to hide")
    hide_parser.add_argument("output", nargs="?", help="Path to save output stego PNG image")
    hide_parser.add_argument("-h", "--help", action="store_true", help="Show help for hide command")

    # Command: EXTRACT
    extract_parser = subparsers.add_parser(
        "extract",
        help="Extract a hidden file from an image",
        description="Extract and decrypt a hidden payload from a Crypta stego PNG image.",
        add_help=False,
    )
    extract_parser.add_argument("image", nargs="?", help="Path to stego PNG image")
    extract_parser.add_argument("-o", "--output", help="Destination path for recovered file")
    extract_parser.add_argument("-h", "--help", action="store_true", help="Show help for extract command")

    # Command: CAPACITY
    capacity_parser = subparsers.add_parser(
        "capacity",
        help="Calculate image hiding capacity",
        description="Calculate maximum embeddable payload capacity of a carrier PNG image.",
        add_help=False,
    )
    capacity_parser.add_argument("image", nargs="?", help="Path to carrier PNG image")
    capacity_parser.add_argument("-h", "--help", action="store_true", help="Show help for capacity command")

    # Command: INFO
    info_parser = subparsers.add_parser(
        "info",
        help="Display image and file information",
        description="Display detailed image properties, color channels, file metadata, and SHA-256 hash.",
        add_help=False,
    )
    info_parser.add_argument("image", nargs="?", help="Path to image file")
    info_parser.add_argument("-h", "--help", action="store_true", help="Show help for info command")

    # Command: ANALYZE
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Perform steganalysis",
        description="Perform comprehensive statistical steganalysis (Entropy, LSB distribution, Chi-Square, Histogram, Pixel statistics).",
        add_help=False,
    )
    analyze_parser.add_argument("image", nargs="?", help="Path to image file to analyze")
    analyze_parser.add_argument(
        "-g", "--visualize", "--graph", action="store_true", help="Generate and save visual steganalysis charts"
    )
    analyze_parser.add_argument("-h", "--help", action="store_true", help="Show help for analyze command")


    # Command: REPORT
    report_parser = subparsers.add_parser(
        "report",
        help="Generate an analysis report",
        description="Generate machine-readable JSON and human-readable HTML forensic analysis reports.",
        add_help=False,
    )
    report_parser.add_argument("image", nargs="?", help="Path to image file to generate report for")
    report_parser.add_argument(
        "-f", "--format", choices=["html", "json", "both", "all"], default="both", help="Report format: 'html', 'json', or 'both' (default: both)"
    )
    report_parser.add_argument("-o", "--output", "--output-dir", dest="output", help="Directory path to save report output")
    report_parser.add_argument("-h", "--help", action="store_true", help="Show help for report command")


    return parser


def show_main_help(include_banner: bool = True) -> None:
    """Print the primary Crypta CLI help screen."""
    if include_banner:
        print(banner())
        print()
    print(heading("Usage:"))
    print("    crypta [COMMAND] [OPTIONS]")
    print()
    print(heading("Interactive Shell:"))
    print("    crypta                 Launch interactive Crypta shell (crypta>)")
    print()
    print(heading("Commands:"))
    print("    hide        Hide an encrypted file inside an image")
    print("    extract     Extract a hidden file from an image")
    print("    capacity    Calculate image hiding capacity")
    print("    info        Display image and file information")
    print("    analyze     Perform steganalysis")
    print("    report      Generate an analysis report")
    print()
    print(heading("Options:"))
    print("    -h, --help       Show this help message")
    print("    -v, --version    Show version information")
    print("    --no-color       Disable colored terminal output")
    print("    --verbose        Enable verbose diagnostic logging")
    print()
    print(heading("Examples:"))
    print("    crypta hide cover.png secret.pdf stego.png")
    print("    crypta extract stego.png")
    print("    crypta capacity cover.png")
    print("    crypta info image.png")
    print("    crypta analyze suspicious.png")
    print("    crypta report suspicious.png --format html")
    print()
    print(muted("Use 'crypta COMMAND --help' for command-specific options."))
    print()


def show_command_help(command: str) -> None:
    """Print command-specific help screens."""
    print(heading(f"Crypta — {command.upper()} Command"))
    print()

    if command == "hide":
        print("Description:")
        print("    Hide an encrypted payload file inside a carrier PNG image using LSB steganography.")
        print()
        print(heading("Usage:"))
        print("    crypta hide <carrier_image> <secret_file> <output_image>")
        print()
        print(heading("Arguments:"))
        print("    carrier_image    Path to the cover PNG carrier image")
        print("    secret_file      Path to the secret payload file to hide")
        print("    output_image     Path where the output stego PNG image will be saved")
        print()
        print(heading("Example:"))
        print("    crypta hide cover.png secret.pdf stego.png")

    elif command == "extract":
        print("Description:")
        print("    Extract and decrypt a hidden file from a Crypta stego PNG image.")
        print()
        print(heading("Usage:"))
        print("    crypta extract <stego_image> [-o <output_path>]")
        print()
        print(heading("Arguments:"))
        print("    stego_image      Path to the stego PNG image containing hidden payload")
        print()
        print(heading("Options:"))
        print("    -o, --output     Destination path for restored output file")
        print()
        print(heading("Example:"))
        print("    crypta extract stego.png -o recovered_secret.pdf")

    elif command == "capacity":
        print("Description:")
        print("    Calculate maximum available payload capacity for a PNG carrier image.")
        print()
        print(heading("Usage:"))
        print("    crypta capacity <carrier_image>")
        print()
        print(heading("Arguments:"))
        print("    carrier_image    Path to carrier PNG image to inspect")
        print()
        print(heading("Example:"))
        print("    crypta capacity cover.png")

    elif command == "info":
        print("Description:")
        print("    Display file specifications, image metadata, color channels, and SHA-256 digest.")
        print()
        print(heading("Usage:"))
        print("    crypta info <image_path>")
        print()
        print(heading("Arguments:"))
        print("    image_path       Path to image file to inspect")
        print()
        print(heading("Example:"))
        print("    crypta info image.png")

    elif command == "analyze":
        print("Description:")
        print("    Perform statistical steganalysis (Entropy, LSB, Chi-Square, Histogram, Pixel statistics).")
        print()
        print(heading("Usage:"))
        print("    crypta analyze <image_path> [--visualize]")
        print()
        print(heading("Arguments:"))
        print("    image_path       Path to image file to analyze")
        print()
        print(heading("Options:"))
        print("    -g, --visualize  Generate and save visual steganalysis charts PNG")
        print()
        print(heading("Example:"))
        print("    crypta analyze suspicious.png")
        print("    crypta analyze suspicious.png --visualize")


    elif command == "report":
        print("Description:")
        print("    Generate machine-readable JSON and human-readable HTML forensic analysis reports.")
        print()
        print(heading("Usage:"))
        print("    crypta report <image_path> [-f <format>] [-o <output_dir>]")
        print()
        print(heading("Arguments:"))
        print("    image_path       Path to image file to report on")
        print()
        print(heading("Options:"))
        print("    -f, --format     Report format: 'html', 'json', or 'both' (default: both)")
        print("    -o, --output     Save location directory for report files")
        print()
        print(heading("Example:"))
        print("    crypta report suspicious.png --format html")


    print()


def interactive_shell() -> None:
    """Launch the interactive REPL shell session (crypta>)."""
    print(banner())
    print()
    print(info("Interactive Crypta shell active."))
    print(muted("Type 'help' for commands, 'clear' to clear screen, 'exit' or 'quit' to exit."))
    print()

    prompt_label = colorize("crypta> ", Colors.BRIGHT_CYAN, bold=True)

    while True:
        try:
            user_input = input(prompt_label).strip()
        except (KeyboardInterrupt, EOFError):
            print()
            print(info("Exiting Crypta shell."))
            break

        if not user_input:
            continue

        clean_input = user_input.lower()

        if clean_input in ("exit", "quit", "q"):
            print(info("Exiting Crypta shell."))
            break

        if clean_input in ("clear", "cls"):
            os.system("cls" if os.name == "nt" else "clear")
            continue

        if clean_input in ("version", "--version", "-v"):
            print(f"{APPLICATION_NAME} {VERSION}")
            print()
            continue

        if clean_input in ("help", "?"):
            show_main_help(include_banner=False)
            continue

        # Parse shlex input to handle quoted paths cleanly
        try:
            cmd_args = shlex.split(user_input)
        except ValueError as err:
            print(error(f"Syntax error: {err}"))
            print()
            continue

        # Strip leading 'crypta', 'python', or 'python3' if user typed it inside shell
        if cmd_args and cmd_args[0].lower() in ("crypta", "python", "python3"):
            cmd_args = cmd_args[1:]

        if not cmd_args:
            continue

        # Execute command within interactive loop
        try:
            main(cmd_args, is_interactive=True)
        except SystemExit:
            pass
        except Exception as err:
            print(error(f"Error executing command: {err}"))
        print()


def main(args: Optional[List[str]] = None, is_interactive: bool = False) -> int:
    """Main CLI entry point."""
    init_terminal()

    if args is None:
        args = sys.argv[1:]

    # Launch interactive REPL shell if no command-line arguments are provided
    if not args and not is_interactive:
        interactive_shell()
        return 0

    # Check for --no-color flag early
    if "--no-color" in args:
        set_color_enabled(False)

    parser = create_parser()
    parsed_args, extra_args = parser.parse_known_args(args)

    # Check verbose flag
    setup_logger(verbose=parsed_args.verbose)

    # Handle Version
    if parsed_args.version:
        print(f"{APPLICATION_NAME} {VERSION}")
        return 0

    # Handle Command-level help request (e.g. `crypta hide --help`)
    if parsed_args.command and (parsed_args.help or getattr(parsed_args, "help", False)):
        show_command_help(parsed_args.command)
        return 0

    # Handle Main Help
    if parsed_args.help:
        show_main_help(include_banner=not is_interactive)
        return 0

    if not parsed_args.command:
        if is_interactive:
            show_main_help(include_banner=False)
            return 0
        else:
            interactive_shell()
            return 0

    # Dispatch to Command Handlers
    command = parsed_args.command
    if command == "hide":
        return handle_hide(parsed_args)
    elif command == "extract":
        return handle_extract(parsed_args)
    elif command == "capacity":
        return handle_capacity(parsed_args)
    elif command == "info":
        return handle_info(parsed_args)
    elif command == "analyze":
        return handle_analyze(parsed_args)
    elif command == "report":
        return handle_report(parsed_args)
    else:
        print(error(f"Unknown command '{command}'."))
        show_main_help(include_banner=not is_interactive)
        return 1


if __name__ == "__main__":
    sys.exit(main())
