"""
gui/findings_page.py
----------------------
The 'Findings' page: browse, search, and filter every finding stored
across all past scans.

Security concept demonstrated:
    Separating "run a scan" (scan_page.py, a write path) from "review
    findings" (this file, a read-only path) again reflects least
    privilege / separation of concerns in the UI layer - this page never
    touches the network and only ever runs SELECT queries.
"""

from __future__ import annotations

import customtkinter as ctk

from database.db_manager import get_all_findings
from utils.logger import get_logger

logger = get_logger(__name__)

_RISK_COLORS = {"High": "#D64545", "Medium": "#E0A030", "Low": "#3B8ED0"}
_RISK_OPTIONS = ["All", "High", "Medium", "Low"]


class FindingsPage(ctk.CTkFrame):
    """Browsable, filterable list of all findings ever recorded."""

    def __init__(self, master: ctk.CTkBaseClass) -> None:
        super().__init__(master, fg_color="transparent")

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self._build_header_and_filters()
        self._build_list_area()

        self.refresh()

    # ------------------------------------------------------------------
    def _build_header_and_filters(self) -> None:
        header = ctk.CTkLabel(self, text="Findings", font=ctk.CTkFont(size=26, weight="bold"))
        header.grid(row=0, column=0, sticky="w", pady=(0, 12))

        filter_row = ctk.CTkFrame(self, fg_color="transparent")
        filter_row.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        filter_row.grid_columnconfigure(0, weight=1)

        self.search_entry = ctk.CTkEntry(filter_row, placeholder_text="Search findings by title...")
        self.search_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self.search_entry.bind("<Return>", lambda _e: self.refresh())

        self.risk_filter = ctk.CTkOptionMenu(filter_row, values=_RISK_OPTIONS, command=lambda _v: self.refresh())
        self.risk_filter.set("All")
        self.risk_filter.grid(row=0, column=1, padx=(0, 10))

        search_btn = ctk.CTkButton(filter_row, text="Search", width=90, command=self.refresh)
        search_btn.grid(row=0, column=2)

        self.summary_label = ctk.CTkLabel(self, text="", text_color="gray60", font=ctk.CTkFont(size=12))
        self.summary_label.grid(row=2, column=0, sticky="w")
        # (summary sits just above the scrollable list; row indices adjusted below)

    def _build_list_area(self) -> None:
        self.list_container = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.list_container.grid(row=3, column=0, sticky="nsew", pady=(6, 0))
        self.list_container.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

    # ------------------------------------------------------------------
    def refresh(self) -> None:
        """Reload findings from the database based on current filters."""
        risk = self.risk_filter.get()
        search = self.search_entry.get().strip()

        try:
            findings = get_all_findings(risk_level=risk, search=search or None)
        except Exception:
            logger.exception("Failed to load findings")
            findings = []

        self.summary_label.configure(text=f"{len(findings)} finding(s)")
        self._render_findings(findings)

    def _render_findings(self, findings: list) -> None:
        for child in self.list_container.winfo_children():
            child.destroy()

        if not findings:
            ctk.CTkLabel(
                self.list_container,
                text="No findings match your filters yet. Run a scan from the 'Scan' tab.",
                text_color="gray60",
            ).grid(row=0, column=0, sticky="w", pady=12)
            return

        for row, finding in enumerate(findings):
            card = self._build_finding_row(self.list_container, finding)
            card.grid(row=row, column=0, sticky="ew", pady=5, padx=2)

    def _build_finding_row(self, master: ctk.CTkBaseClass, finding) -> ctk.CTkFrame:
        card = ctk.CTkFrame(master, corner_radius=10)
        card.grid_columnconfigure(1, weight=1)

        color = _RISK_COLORS.get(finding["risk_level"], "#888888")
        badge = ctk.CTkLabel(
            card,
            text=finding["risk_level"].upper(),
            fg_color=color,
            text_color="white",
            corner_radius=6,
            width=70,
            height=22,
            font=ctk.CTkFont(size=11, weight="bold"),
        )
        badge.grid(row=0, column=0, padx=(12, 10), pady=(10, 0), sticky="nw")

        title = ctk.CTkLabel(
            card, text=finding["title"], font=ctk.CTkFont(size=13, weight="bold"), anchor="w"
        )
        title.grid(row=0, column=1, sticky="w", pady=(10, 0))

        meta = ctk.CTkLabel(
            card,
            text=f"{finding['owasp_category']}  •  {finding['target_url']}  •  {finding['scan_date']}",
            text_color="gray60",
            font=ctk.CTkFont(size=11),
            anchor="w",
        )
        meta.grid(row=1, column=1, sticky="w", pady=(0, 10))

        return card
