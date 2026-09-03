"""
Crypta Terminal Styling & Visual Formatting System.
"""

from crypta.utils.constants import (
    APPLICATION_NAME,
    VERSION,
    TAGLINE,
    PREFIX_SUCCESS,
    PREFIX_ERROR,
    PREFIX_INFO,
    PREFIX_WARNING,
    PREFIX_DEBUG,
)
from crypta.utils.terminal import colorize, Colors, is_color_enabled


def success(message: str) -> str:
    """Format success message with [+] prefix."""
    prefix = colorize(PREFIX_SUCCESS, Colors.BRIGHT_GREEN, bold=True)
    return f"{prefix} {message}"


def error(message: str) -> str:
    """Format error message with [-] prefix."""
    prefix = colorize(PREFIX_ERROR, Colors.BRIGHT_RED, bold=True)
    return f"{prefix} {message}"


def warning(message: str) -> str:
    """Format warning message with [!] prefix."""
    prefix = colorize(PREFIX_WARNING, Colors.BRIGHT_YELLOW, bold=True)
    return f"{prefix} {message}"


def info(message: str) -> str:
    """Format informational message with [*] prefix."""
    prefix = colorize(PREFIX_INFO, Colors.BRIGHT_CYAN, bold=True)
    return f"{prefix} {message}"


def debug(message: str) -> str:
    """Format debug message with [DEBUG] prefix."""
    prefix = colorize(PREFIX_DEBUG, Colors.GRAY, bold=True)
    return f"{prefix} {message}"


def muted(text: str) -> str:
    """Format muted gray text."""
    return colorize(text, Colors.GRAY)


def heading(text: str) -> str:
    """Format a styled section heading."""
    return colorize(text, Colors.BRIGHT_CYAN, bold=True)


def banner() -> str:
    """Generate the Crypta ASCII startup banner."""
    ascii_logo = r"""
  ____                  _        
 / ___|_ __ _   _ _ __ | |_ __ _ 
| |   | '__| | | | '_ \| __/ _` |
| |___| |  | |_| | |_) | || (_| |
 \____|_|   \__, | .__/ \__\__,_|
            |___/|_|             """

    lines = []
    lines.append(colorize(ascii_logo, Colors.BRIGHT_CYAN, bold=True))
    lines.append("")
    lines.append(f"  {colorize(TAGLINE, Colors.WHITE, bold=True)}")
    divider = "-" * 52
    lines.append(colorize(divider, Colors.GRAY))
    lines.append(f"  Version {VERSION} | {APPLICATION_NAME} Cybersecurity Toolkit")
    lines.append(colorize(divider, Colors.GRAY))
    return "\n".join(lines)
