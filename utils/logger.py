"""
utils/logger.py
----------------
Centralized logging configuration for the OWASP Security Lab.

Security concept demonstrated:
    OWASP A09:2021 "Security Logging and Monitoring Failures" — one of the
    most common root causes of that category is that applications either
    don't log consistently, or every module configures logging its own
    way, resulting in gaps. Here we provide a single `get_logger()` used
    everywhere, so every module's log output is consistent, timestamped,
    and written to both console and a rotating log file. This also models
    good practice for the *scanner itself*: every scan action should be
    logged so a user (or auditor) can later see exactly what was checked.

    Note: this logs the application's own behavior (scans run, errors,
    etc.) - it intentionally never logs full response bodies or secrets,
    to avoid the logger itself becoming a sensitive-data leak.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOG_DIR = Path(__file__).resolve().parent.parent / "assets" / "logs"
LOG_FILE = LOG_DIR / "app.log"

_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_configured = False


def _configure_root_logger() -> None:
    """Configure the root logger once, with console + rotating file handlers."""
    global _configured
    if _configured:
        return

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)

    # Rotate at 1 MB, keep 3 backups, so logs never grow unbounded.
    file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)

    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """
    Get a module-scoped logger with consistent formatting.

    Args:
        name: Typically `__name__` of the calling module.

    Returns:
        A configured `logging.Logger` instance.
    """
    _configure_root_logger()
    return logging.getLogger(name)
