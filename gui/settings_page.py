"""
gui/settings_page.py
----------------------
The 'Settings' page: appearance, scan defaults, and local data
management (clear stored scan history).

Security concept demonstrated:
    All settings are stored locally in the same single-user SQLite
    database as everything else (see database/db_manager.py's
    `settings` table) - no telemetry, no remote config, no account
    system. "Clear scan data" is a deliberate, explicit, confirmed
    action (never automatic), consistent with the rest of the app's
    philosophy that destructive or scope-widening actions should
    always require a clear, deliberate step from the user.
"""

from __future__ import annotations

import customtkinter as ctk

from database.db_manager import clear_all_history, get_all_settings, set_setting
from utils.logger import get_logger

logger = get_logger(__name__)

_DEFAULT_TIMEOUT = "10"
_DEFAULT_APPEARANCE = "dark"


class SettingsPage(ctk.CTkFrame):
    """App-wide settings, persisted to the local `settings` table."""

    def __init__(self, master: ctk.CTkBaseClass, on_appearance_changed=None) -> None:
        super().__init__(master, fg_color="transparent")
        self.on_appearance_changed = on_appearance_changed

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)

        self._build_header()
        self._build_appearance_section()
        self._build_scan_defaults_section()
        self._build_data_section()
        self._build_about_section()

        self._load_settings()

    # ------------------------------------------------------------------
    def _build_header(self) -> None:
        header = ctk.CTkLabel(self, text="Settings", font=ctk.CTkFont(size=26, weight="bold"))
        header.grid(row=0, column=0, sticky="w", pady=(0, 16))

    def _build_appearance_section(self) -> None:
        panel = self._panel("Appearance")
        panel.grid(row=1, column=0, sticky="ew", pady=(0, 12))

        ctk.CTkLabel(panel, text="Theme", font=ctk.CTkFont(size=13)).grid(
            row=1, column=0, sticky="w", padx=16, pady=(0, 14)
        )
        self.appearance_menu = ctk.CTkOptionMenu(
            panel, values=["dark", "light", "system"], command=self._on_appearance_selected
        )
        self.appearance_menu.grid(row=1, column=1, sticky="e", padx=16, pady=(0, 14))
        panel.grid_columnconfigure(1, weight=1)

    def _build_scan_defaults_section(self) -> None:
        panel = self._panel("Scan Defaults")
        panel.grid(row=2, column=0, sticky="ew", pady=(0, 12))
        panel.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(panel, text="Request timeout (seconds)", font=ctk.CTkFont(size=13)).grid(
            row=1, column=0, sticky="w", padx=16, pady=(0, 8)
        )
        self.timeout_entry = ctk.CTkEntry(panel, width=100, placeholder_text=_DEFAULT_TIMEOUT)
        self.timeout_entry.grid(row=1, column=1, sticky="e", padx=16, pady=(0, 8))

        ctk.CTkLabel(
            panel,
            text=(
                "Note: this app only ever performs passive, read-only checks. "
                "Always confirm you're authorized to scan a target before running one."
            ),
            text_color="gray60",
            font=ctk.CTkFont(size=11),
            wraplength=760,
            justify="left",
        ).grid(row=2, column=0, columnspan=2, sticky="w", padx=16, pady=(0, 14))

        save_btn = ctk.CTkButton(panel, text="Save Scan Defaults", width=170, command=self._save_scan_defaults)
        save_btn.grid(row=3, column=0, sticky="w", padx=16, pady=(0, 14))

        self.scan_defaults_status = ctk.CTkLabel(panel, text="", text_color="#2FA572", font=ctk.CTkFont(size=11))
        self.scan_defaults_status.grid(row=3, column=1, sticky="e", padx=16, pady=(0, 14))

    def _build_data_section(self) -> None:
        panel = self._panel("Data Management")
        panel.grid(row=3, column=0, sticky="ew", pady=(0, 12))
        panel.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            panel,
            text="All scan history and findings are stored locally in database/findings.db.",
            text_color="gray60",
            font=ctk.CTkFont(size=12),
        ).grid(row=1, column=0, columnspan=2, sticky="w", padx=16, pady=(0, 10))

        self._confirm_pending = False
        self.clear_btn = ctk.CTkButton(
            panel,
            text="🗑 Clear All Scan Data",
            fg_color="#D64545",
            hover_color="#B23838",
            width=200,
            command=self._on_clear_clicked,
        )
        self.clear_btn.grid(row=2, column=0, sticky="w", padx=16, pady=(0, 14))

        self.clear_status = ctk.CTkLabel(panel, text="", font=ctk.CTkFont(size=11))
        self.clear_status.grid(row=2, column=1, sticky="e", padx=16, pady=(0, 14))

    def _build_about_section(self) -> None:
        panel = self._panel("About")
        panel.grid(row=4, column=0, sticky="new")

        ctk.CTkLabel(
            panel,
            text=(
                "OWASP Top 10 Security Assessment Lab\n"
                "A local, read-only educational scanner covering the OWASP Top 10 (2021).\n"
                "Educational use only. Only scan targets you own or are explicitly authorized to test."
            ),
            text_color="gray60",
            font=ctk.CTkFont(size=12),
            justify="left",
        ).grid(row=1, column=0, sticky="w", padx=16, pady=(0, 16))

    def _panel(self, title: str) -> ctk.CTkFrame:
        panel = ctk.CTkFrame(self, corner_radius=12)
        ctk.CTkLabel(panel, text=title, font=ctk.CTkFont(size=16, weight="bold")).grid(
            row=0, column=0, sticky="w", padx=16, pady=(14, 10)
        )
        return panel

    # ------------------------------------------------------------------
    def _load_settings(self) -> None:
        try:
            settings = get_all_settings()
        except Exception:
            logger.exception("Failed to load settings")
            settings = {}

        appearance = settings.get("appearance_mode", _DEFAULT_APPEARANCE)
        self.appearance_menu.set(appearance)

        timeout = settings.get("scan_timeout", _DEFAULT_TIMEOUT)
        self.timeout_entry.delete(0, "end")
        self.timeout_entry.insert(0, timeout)

    def _on_appearance_selected(self, mode: str) -> None:
        try:
            set_setting("appearance_mode", mode)
        except Exception:
            logger.exception("Failed to save appearance setting")
        ctk.set_appearance_mode(mode)
        if self.on_appearance_changed:
            self.on_appearance_changed(mode)

    def _save_scan_defaults(self) -> None:
        value = self.timeout_entry.get().strip() or _DEFAULT_TIMEOUT
        try:
            timeout_int = int(value)
            if timeout_int <= 0:
                raise ValueError
        except ValueError:
            self.scan_defaults_status.configure(text="Enter a positive number.", text_color="#D64545")
            return

        try:
            set_setting("scan_timeout", str(timeout_int))
        except Exception:
            logger.exception("Failed to save scan timeout setting")
            self.scan_defaults_status.configure(text="Could not save.", text_color="#D64545")
            return

        self.scan_defaults_status.configure(text="Saved ✓", text_color="#2FA572")

    def _on_clear_clicked(self) -> None:
        if not self._confirm_pending:
            self._confirm_pending = True
            self.clear_btn.configure(text="⚠ Click again to confirm")
            self.clear_status.configure(text="This permanently deletes all scans and findings.", text_color="#E0A030")
            self.after(4000, self._reset_confirm_state)
            return

        self._confirm_pending = False
        try:
            clear_all_history()
        except Exception:
            logger.exception("Failed to clear scan history")
            self.clear_status.configure(text="❌ Failed to clear data.", text_color="#D64545")
        else:
            self.clear_status.configure(text="✅ All scan data cleared.", text_color="#2FA572")
        self.clear_btn.configure(text="🗑 Clear All Scan Data")

    def _reset_confirm_state(self) -> None:
        if self._confirm_pending:
            self._confirm_pending = False
            self.clear_btn.configure(text="🗑 Clear All Scan Data")
            self.clear_status.configure(text="")

    def refresh(self) -> None:
        """Called by SecurityLabApp when this page is shown."""
        self._load_settings()
