"""
Centralized logging foundation for Crypta.
Utilizes Python standard logging with custom terminal styling.
"""

import logging
import sys
from crypta.cli.styling import info, warning, error, debug


class CryptaFormatter(logging.Formatter):
    """Custom logging formatter integrating Crypta CLI styling."""

    def format(self, record: logging.LogRecord) -> str:
        msg = record.getMessage()
        if record.levelno == logging.DEBUG:
            return debug(msg)
        elif record.levelno == logging.INFO:
            return info(msg)
        elif record.levelno == logging.WARNING:
            return warning(msg)
        elif record.levelno == logging.ERROR or record.levelno == logging.CRITICAL:
            return error(msg)
        return msg


def setup_logger(name: str = "crypta", verbose: bool = False) -> logging.Logger:
    """Configure and return the root Crypta logger."""
    logger = logging.getLogger(name)
    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(level)

    # Avoid duplicate handlers if setup_logger is called multiple times
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(level)
        handler.setFormatter(CryptaFormatter())
        logger.addHandler(handler)
    else:
        logger.setLevel(level)
        for h in logger.handlers:
            h.setLevel(level)

    return logger
