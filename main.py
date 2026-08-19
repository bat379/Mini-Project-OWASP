"""
main.py
--------
Entry point for the OWASP Top 10 Security Assessment Lab.

Security concept demonstrated:
    This file has no security logic itself, but it embodies an important
    secure-development principle: a single, predictable entry point.
    Centralizing startup (logging config, DB init, GUI launch) makes the
    application's behavior auditable — you always know exactly where
    execution begins and what gets initialized before any user code runs.
    This is the same reasoning behind OWASP's guidance on "Security
    Misconfiguration": undocumented or scattered startup logic makes it
    easy to accidentally skip a security control (e.g. forgetting to set
    up logging, or initializing the DB with unsafe defaults).

Responsibilities:
    1. Configure logging (see utils/logger.py) before anything else runs,
       so all subsequent modules can log safely.
    2. Ensure the local SQLite database and its schema exist.
    3. Launch the CustomTkinter GUI application.

Usage:
    python main.py
"""

from __future__ import annotations

import sys
import traceback

from utils.logger import get_logger

logger = get_logger(__name__)


def bootstrap_database() -> None:
    """
    Ensure the local findings database exists with the correct schema.

    We import lazily (inside the function) so that a failure to import
    GUI-only dependencies doesn't prevent database bootstrap logic from
    being testable in isolation (unit-test-friendly design).
    """
    from database.db_manager import initialize_database

    initialize_database()
    logger.info("Database initialized (or already present) at database/findings.db")


def launch_gui() -> None:
    """Create and run the main application window."""
    from gui.dashboard import SecurityLabApp

    app = SecurityLabApp()
    app.mainloop()


def main() -> int:
    """
    Application entry point.

    Returns:
        int: process exit code (0 = success, non-zero = failure).
    """
    logger.info("Starting OWASP Top 10 Security Assessment Lab")

    try:
        bootstrap_database()
    except Exception:  # noqa: BLE001 - we want to log any startup failure
        logger.exception("Fatal error during database bootstrap")
        return 1

    try:
        launch_gui()
    except Exception:  # noqa: BLE001 - top-level guard so crashes are logged
        logger.exception("Fatal error while running the GUI application")
        traceback.print_exc()
        return 1

    logger.info("Application closed normally")
    return 0


if __name__ == "__main__":
    sys.exit(main())
