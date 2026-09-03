"""
Terminal color and formatting utility for Crypta.
Handles ANSI codes and cross-platform VT100 initialization.
"""

import os
import sys

_COLOR_ENABLED = True


def init_terminal() -> None:
    """Initialize terminal for ANSI color support across Windows and Linux."""
    global _COLOR_ENABLED

    # Respect NO_COLOR env standard (https://no-color.org)
    if "NO_COLOR" in os.environ:
        _COLOR_ENABLED = False
        return

    # Ensure stdout/stderr streams support UTF-8 encoding on Windows consoles
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    # Windows VT100 Virtual Terminal Processing Initialization
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            # STD_OUTPUT_HANDLE = -11
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            kernel32.GetConsoleMode(handle, ctypes.byref(mode))
            mode.value |= 0x0004
            kernel32.SetConsoleMode(handle, mode)
        except Exception:
            # Fall back to os.system('') which forces VT100 on modern Windows
            os.system("")

    # Disable color if stdout is redirected and not a TTY
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        _COLOR_ENABLED = False


def set_color_enabled(enabled: bool) -> None:
    """Explicitly enable or disable colored output."""
    global _COLOR_ENABLED
    _COLOR_ENABLED = enabled


def is_color_enabled() -> bool:
    """Return whether color output is currently enabled."""
    return _COLOR_ENABLED


class Colors:
    """ANSI color code definitions."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Primary Palette
    CYAN = "\033[36m"
    BRIGHT_CYAN = "\033[96m"

    # Status Colors
    GREEN = "\033[32m"
    BRIGHT_GREEN = "\033[92m"

    YELLOW = "\033[33m"
    BRIGHT_YELLOW = "\033[93m"

    RED = "\033[31m"
    BRIGHT_RED = "\033[91m"

    BLUE = "\033[34m"
    BRIGHT_BLUE = "\033[94m"

    GRAY = "\033[90m"
    WHITE = "\033[97m"


def colorize(text: str, color_code: str, bold: bool = False) -> str:
    """Wrap text in ANSI color codes if color is enabled."""
    if not _COLOR_ENABLED:
        return text
    prefix = f"{Colors.BOLD}{color_code}" if bold else color_code
    return f"{prefix}{text}{Colors.RESET}"
