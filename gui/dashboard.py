"""
gui/dashboard.py
-----------------
Base application window and Dashboard page for the OWASP Top 10
Security Assessment Lab.

Security concept demonstrated:
    None directly (this is UI scaffolding) - but the *structure* matters:
    each page (Dashboard, Scan, Findings, Reports, Learning Center,
    Settings) is isolated in its own frame/module. This mirrors secure
    software design principles like separation of concerns and least
    privilege: the Dashboard page only ever *reads* summary data from the
    database, it never performs scans or writes findings itself. Keeping
    read paths and write/action paths in separate modules makes the code
    easier to audit later (e.g. "which code paths can modify the DB?").

This module currently defines:
    * SecurityLabApp - the main CTk window, with a sidebar for navigation.
    * DashboardFrame - the Dashboard page: summary stat cards + recent
      scans table, backed by real (currently empty) data from the DB.

Other pages (ScanPage, FindingsPage/ReportPage, LearningCenter,
Settings) are stubbed as simple placeholder frames for now and will be
built out in later steps, per the incremental development plan.
"""

from __future__ import annotations

from typing import Callable

import customtkinter as ctk

from database.db_manager import get_connection, get_setting
from gui.findings_page import FindingsPage
from gui.learning_page import LearningCenterPage
from gui.reports_page import ReportsPage
from gui.scan_page import ScanPage
from gui.settings_page import SettingsPage
from utils.logger import get_logger

logger = get_logger(__name__)

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

APP_TITLE = "OWASP Top 10 Security Assessment Lab"
WINDOW_SIZE = "1200x750"

# Sidebar navigation entries: (label, page_key)
NAV_ITEMS: list[tuple[str, str]] = [
    ("📊  Dashboard", "dashboard"),
    ("🔍  Scan", "scan"),
    ("📋  Findings", "findings"),
    ("📄  Reports", "reports"),
    ("📚  Learning Center", "learning"),
    ("⚙️  Settings", "settings"),
]


class SecurityLabApp(ctk.CTk):
    """
    Main application window.

    Provides a persistent sidebar for navigation and a content area that
    swaps between page frames. Only the Dashboard page is fully built in
    this step; other nav items show a "coming soon" placeholder so the
    app is runnable end-to-end from step one.
    """

    def __init__(self) -> None:
        super().__init__()

        try:
            saved_mode = get_setting("appearance_mode", "dark")
        except Exception:
            saved_mode = "dark"
        ctk.set_appearance_mode(saved_mode)

        self.title(APP_TITLE)
        self.geometry(WINDOW_SIZE)
        self.minsize(1000, 650)

        # Layout: column 0 = sidebar (fixed), column 1 = content (expands)
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._pages: dict[str, ctk.CTkFrame] = {}
        self._nav_buttons: dict[str, ctk.CTkButton] = {}

        self._build_sidebar()
        self._build_content_area()

        self.show_page("dashboard")

    # ------------------------------------------------------------------
    # Sidebar
    # ------------------------------------------------------------------
    def _build_sidebar(self) -> None:
        sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        sidebar.grid(row=0, column=0, sticky="nsw")
        sidebar.grid_rowconfigure(len(NAV_ITEMS) + 1, weight=1)  # spacer

        logo = ctk.CTkLabel(
            sidebar,
            text="🛡️  OWASP Lab",
            font=ctk.CTkFont(size=20, weight="bold"),
        )
        logo.grid(row=0, column=0, padx=20, pady=(24, 30), sticky="w")

        for idx, (label, key) in enumerate(NAV_ITEMS, start=1):
            btn = ctk.CTkButton(
                sidebar,
                text=label,
                anchor="w",
                fg_color="transparent",
                text_color=("gray10", "gray90"),
                hover_color=("gray75", "gray25"),
                command=self._make_nav_callback(key),
            )
            btn.grid(row=idx, column=0, padx=12, pady=4, sticky="ew")
            self._nav_buttons[key] = btn

        disclaimer = ctk.CTkLabel(
            sidebar,
            text="Educational use only.\nAuthorized targets only.",
            font=ctk.CTkFont(size=11),
            text_color="gray60",
            justify="left",
        )
        disclaimer.grid(row=len(NAV_ITEMS) + 2, column=0, padx=16, pady=16, sticky="sw")

    def _make_nav_callback(self, page_key: str) -> Callable[[], None]:
        return lambda: self.show_page(page_key)

    # ------------------------------------------------------------------
    # Content area / page routing
    # ------------------------------------------------------------------
    def _build_content_area(self) -> None:
        self.content_container = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.content_container.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.content_container.grid_rowconfigure(0, weight=1)
        self.content_container.grid_columnconfigure(0, weight=1)

        self._pages["dashboard"] = DashboardFrame(self.content_container)
        self._pages["scan"] = ScanPage(self.content_container, on_scan_saved=self._on_scan_saved)
        self._pages["findings"] = FindingsPage(self.content_container)
        self._pages["reports"] = ReportsPage(self.content_container)
        self._pages["learning"] = LearningCenterPage(self.content_container)
        self._pages["settings"] = SettingsPage(
            self.content_container, on_appearance_changed=self._on_appearance_changed
        )

        for _, key in NAV_ITEMS:
            if key in self._pages:
                continue
            self._pages[key] = PlaceholderFrame(self.content_container, page_key=key)

        for page in self._pages.values():
            page.grid(row=0, column=0, sticky="nsew")

    def show_page(self, page_key: str) -> None:
        """Raise the requested page frame to the top and refresh it."""
        page = self._pages.get(page_key)
        if page is None:
            logger.warning("Requested unknown page: %s", page_key)
            return

        if hasattr(page, "refresh"):
            page.refresh()

        page.tkraise()
        self._highlight_active_nav(page_key)

    def _on_scan_saved(self) -> None:
        """Called by ScanPage after a scan is saved, so other pages that
        cache DB-derived state pick up the new data next time they're shown."""
        for key in ("dashboard", "findings", "reports", "learning"):
            page = self._pages.get(key)
            if page is not None and hasattr(page, "refresh"):
                page.refresh()

    def _on_appearance_changed(self, _mode: str) -> None:
        """Called by SettingsPage when the user changes the theme."""
        logger.info("Appearance mode changed to %s", _mode)

    def _highlight_active_nav(self, active_key: str) -> None:
        for key, btn in self._nav_buttons.items():
            if key == active_key:
                btn.configure(fg_color=("gray75", "gray25"))
            else:
                btn.configure(fg_color="transparent")


class StatCard(ctk.CTkFrame):
    """A single summary statistic card (e.g. 'High Risk Findings: 3')."""

    def __init__(
        self,
        master: ctk.CTkBaseClass,
        title: str,
        value: str,
        accent_color: str = "#3B8ED0",
    ) -> None:
        super().__init__(master, corner_radius=12)

        self.grid_columnconfigure(0, weight=1)

        accent = ctk.CTkFrame(self, width=6, corner_radius=3, fg_color=accent_color)
        accent.grid(row=0, column=0, rowspan=2, sticky="ns", padx=(0, 12), pady=12)

        self.value_label = ctk.CTkLabel(
            self, text=value, font=ctk.CTkFont(size=28, weight="bold")
        )
        self.value_label.grid(row=0, column=1, sticky="w", padx=(0, 16), pady=(14, 0))

        self.title_label = ctk.CTkLabel(
            self, text=title, font=ctk.CTkFont(size=13), text_color="gray60"
        )
        self.title_label.grid(row=1, column=1, sticky="w", padx=(0, 16), pady=(0, 14))

    def set_value(self, value: str) -> None:
        self.value_label.configure(text=value)


class DashboardFrame(ctk.CTkFrame):
    """
    The Dashboard page.

    Shows high-level stats pulled from the database:
        - Total scans run
        - Overall/most-recent security score
        - Count of High / Medium / Low risk findings
        - A table of recent scans

    All values default to zero/empty state gracefully when the database
    has no scans yet (e.g. on first run), since the Scan module hasn't
    been built yet at this step.
    """

    def __init__(self, master: ctk.CTkBaseClass) -> None:
        super().__init__(master, fg_color="transparent")

        self.grid_columnconfigure((0, 1, 2, 3), weight=1)
        self.grid_rowconfigure(2, weight=1)

        header = ctk.CTkLabel(
            self, text="Dashboard", font=ctk.CTkFont(size=26, weight="bold")
        )
        header.grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 16))

        # --- Stat cards row ---
        self.total_scans_card = StatCard(self, "Total Scans", "0", "#3B8ED0")
        self.total_scans_card.grid(row=1, column=0, sticky="nsew", padx=6, pady=6)

        self.security_score_card = StatCard(self, "Avg. Security Score", "N/A", "#2FA572")
        self.security_score_card.grid(row=1, column=1, sticky="nsew", padx=6, pady=6)

        self.high_risk_card = StatCard(self, "High Risk Findings", "0", "#D64545")
        self.high_risk_card.grid(row=1, column=2, sticky="nsew", padx=6, pady=6)

        self.medium_low_card = StatCard(self, "Medium / Low Findings", "0 / 0", "#E0A030")
        self.medium_low_card.grid(row=1, column=3, sticky="nsew", padx=6, pady=6)

        # --- Recent scans panel ---
        recent_panel = ctk.CTkFrame(self, corner_radius=12)
        recent_panel.grid(row=2, column=0, columnspan=4, sticky="nsew", padx=6, pady=(12, 6))
        recent_panel.grid_columnconfigure(0, weight=1)
        recent_panel.grid_rowconfigure(1, weight=1)

        recent_title = ctk.CTkLabel(
            recent_panel,
            text="Recent Scans",
            font=ctk.CTkFont(size=16, weight="bold"),
        )
        recent_title.grid(row=0, column=0, sticky="w", padx=16, pady=(14, 8))

        self.recent_scrollable = ctk.CTkScrollableFrame(recent_panel, fg_color="transparent")
        self.recent_scrollable.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 12))
        self.recent_scrollable.grid_columnconfigure(0, weight=1)

        self.empty_state_label = ctk.CTkLabel(
            self.recent_scrollable,
            text="No scans yet. Run your first scan from the 'Scan' tab to see results here.",
            text_color="gray60",
        )

        self.refresh()

    def refresh(self) -> None:
        """Reload stats and recent scans from the database."""
        try:
            stats, recent_scans = self._load_dashboard_data()
        except Exception:
            logger.exception("Failed to load dashboard data")
            stats = {"total": 0, "avg_score": None, "high": 0, "medium": 0, "low": 0}
            recent_scans = []

        self.total_scans_card.set_value(str(stats["total"]))
        avg_score_text = "N/A" if stats["avg_score"] is None else f"{stats['avg_score']}%"
        self.security_score_card.set_value(avg_score_text)
        self.high_risk_card.set_value(str(stats["high"]))
        self.medium_low_card.set_value(f"{stats['medium']} / {stats['low']}")

        self._render_recent_scans(recent_scans)

    def _load_dashboard_data(self) -> tuple[dict, list]:
        """Query aggregate stats and the most recent scans from SQLite."""
        with get_connection() as conn:
            totals_row = conn.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    AVG(security_score) AS avg_score,
                    COALESCE(SUM(high_count), 0) AS high,
                    COALESCE(SUM(medium_count), 0) AS medium,
                    COALESCE(SUM(low_count), 0) AS low
                FROM scans
                """
            ).fetchone()

            recent_rows = conn.execute(
                """
                SELECT target_url, scan_date, security_score,
                       high_count, medium_count, low_count
                FROM scans
                ORDER BY scan_date DESC
                LIMIT 10
                """
            ).fetchall()

        avg_score = totals_row["avg_score"]
        stats = {
            "total": totals_row["total"] or 0,
            "avg_score": round(avg_score) if avg_score is not None else None,
            "high": totals_row["high"] or 0,
            "medium": totals_row["medium"] or 0,
            "low": totals_row["low"] or 0,
        }
        return stats, list(recent_rows)

    def _render_recent_scans(self, recent_scans: list) -> None:
        for child in self.recent_scrollable.winfo_children():
            child.destroy()

        if not recent_scans:
            self.empty_state_label = ctk.CTkLabel(
                self.recent_scrollable,
                text="No scans yet. Run your first scan from the 'Scan' tab to see results here.",
                text_color="gray60",
            )
            self.empty_state_label.grid(row=0, column=0, sticky="w", padx=8, pady=12)
            return

        headers = ["Target", "Date", "Score", "High", "Med", "Low"]
        for col, text in enumerate(headers):
            ctk.CTkLabel(
                self.recent_scrollable, text=text, font=ctk.CTkFont(weight="bold"), text_color="gray60"
            ).grid(row=0, column=col, sticky="w", padx=8, pady=(0, 6))

        for row_idx, scan in enumerate(recent_scans, start=1):
            ctk.CTkLabel(self.recent_scrollable, text=scan["target_url"]).grid(
                row=row_idx, column=0, sticky="w", padx=8, pady=3
            )
            ctk.CTkLabel(self.recent_scrollable, text=scan["scan_date"]).grid(
                row=row_idx, column=1, sticky="w", padx=8, pady=3
            )
            ctk.CTkLabel(self.recent_scrollable, text=f"{scan['security_score']}%").grid(
                row=row_idx, column=2, sticky="w", padx=8, pady=3
            )
            ctk.CTkLabel(self.recent_scrollable, text=str(scan["high_count"])).grid(
                row=row_idx, column=3, sticky="w", padx=8, pady=3
            )
            ctk.CTkLabel(self.recent_scrollable, text=str(scan["medium_count"])).grid(
                row=row_idx, column=4, sticky="w", padx=8, pady=3
            )
            ctk.CTkLabel(self.recent_scrollable, text=str(scan["low_count"])).grid(
                row=row_idx, column=5, sticky="w", padx=8, pady=3
            )


class PlaceholderFrame(ctk.CTkFrame):
    """
    Temporary placeholder page shown for nav items not yet built
    (Scan, Findings, Reports, Learning Center, Settings).

    Replaced module-by-module in upcoming steps.
    """

    def __init__(self, master: ctk.CTkBaseClass, page_key: str) -> None:
        super().__init__(master, fg_color="transparent")
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        label = ctk.CTkLabel(
            self,
            text=f"'{page_key.title()}' page coming in a later step 🚧",
            font=ctk.CTkFont(size=18),
            text_color="gray60",
        )
        label.grid(row=0, column=0)
