"""
gui/learning_page.py
----------------------
The 'Learning Center' page: a colorful OWASP Top 10 (2021) matrix
explaining, for every category, what it is, what attack it enables,
and how to protect against it - plus a personalized panel that
highlights which of these apply to the user's own most recent scan.

Security concept demonstrated:
    Read-only, offline, and educational: this page never contacts a
    network target. The "personalized" section works entirely from
    findings already stored locally by a previous scan, reusing the
    same threat_intel knowledge base as the Reports page so the
    Learning Center and Reports never disagree about what a finding
    means.
"""

from __future__ import annotations

import customtkinter as ctk

from database.db_manager import get_findings_for_scan, get_latest_scan_id
from scanner.models import OwaspCategory
from utils.logger import get_logger
from utils.threat_intel import CATEGORY_INFO, assess_scan

logger = get_logger(__name__)

_MATRIX_COLUMNS = 2


class LearningCenterPage(ctk.CTkFrame):
    """Colorful OWASP Top 10 matrix + personalized findings-based guidance."""

    def __init__(self, master: ctk.CTkBaseClass) -> None:
        super().__init__(master, fg_color="transparent")

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self._build_header()
        self._build_scroll_area()

        self.refresh()

    # ------------------------------------------------------------------
    def _build_header(self) -> None:
        header = ctk.CTkLabel(
            self, text="Learning Center", font=ctk.CTkFont(size=26, weight="bold")
        )
        header.grid(row=0, column=0, sticky="w", pady=(0, 4))

        subtitle = ctk.CTkLabel(
            self,
            text=(
                "The OWASP Top 10 (2021), color-coded: what each risk means, "
                "an attack it enables, and how to close it."
            ),
            text_color="gray60",
            font=ctk.CTkFont(size=12),
        )
        subtitle.grid(row=1, column=0, sticky="w", pady=(0, 10))

    def _build_scroll_area(self) -> None:
        self.scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.scroll.grid(row=2, column=0, sticky="nsew")
        self.scroll.grid_columnconfigure(tuple(range(_MATRIX_COLUMNS)), weight=1)

    # ------------------------------------------------------------------
    def refresh(self) -> None:
        for child in self.scroll.winfo_children():
            child.destroy()

        next_row = self._render_personalized_section(self.scroll, start_row=0)
        self._render_matrix(self.scroll, start_row=next_row)

    # ------------------------------------------------------------------
    # Personalized section: "based on your latest scan"
    # ------------------------------------------------------------------
    def _render_personalized_section(self, master, start_row: int) -> int:
        try:
            latest_scan_id = get_latest_scan_id()
            findings = get_findings_for_scan(latest_scan_id) if latest_scan_id else []
        except Exception:
            logger.exception("Failed to load latest scan for Learning Center")
            findings = []

        section_title = ctk.CTkLabel(
            master,
            text="🎯  Attacks Relevant To Your Latest Scan",
            font=ctk.CTkFont(size=17, weight="bold"),
        )
        section_title.grid(row=start_row, column=0, columnspan=_MATRIX_COLUMNS, sticky="w", pady=(4, 8))
        row = start_row + 1

        if not findings:
            ctk.CTkLabel(
                master,
                text="Run a scan from the 'Scan' tab to see which attacks are most relevant to your target here.",
                text_color="gray60",
            ).grid(row=row, column=0, columnspan=_MATRIX_COLUMNS, sticky="w", pady=(0, 16))
            return row + 1

        assessment = assess_scan(findings)
        # Show only the top few most-exploitable, most-relevant items so this
        # stays a highlights panel rather than duplicating the Reports page.
        top_items = assessment["assessed_findings"][:4]

        for item in top_items:
            card = ctk.CTkFrame(master, corner_radius=10, border_width=2, border_color=item["color"])
            card.grid_columnconfigure(1, weight=1)

            badge = ctk.CTkLabel(
                card,
                text=item["exploitability"].value.upper(),
                fg_color=item["color"],
                text_color="white",
                corner_radius=6,
                width=150,
                height=22,
                font=ctk.CTkFont(size=11, weight="bold"),
            )
            badge.grid(row=0, column=0, padx=(12, 10), pady=(12, 6), sticky="nw")

            title = ctk.CTkLabel(
                card,
                text=f"{item['attack_name']}  (from: {item['title']})",
                font=ctk.CTkFont(size=13, weight="bold"),
                anchor="w",
                justify="left",
                wraplength=800,
            )
            title.grid(row=0, column=1, sticky="w", pady=(12, 0))

            body = ctk.CTkLabel(
                card,
                text=f"{item['how_it_works']}\n\nProtect: {item['protection']}",
                anchor="w",
                justify="left",
                wraplength=800,
                font=ctk.CTkFont(size=12),
            )
            body.grid(row=1, column=1, sticky="w", padx=(0, 12), pady=(0, 12))

            card.grid(row=row, column=0, columnspan=_MATRIX_COLUMNS, sticky="ew", pady=5)
            row += 1

        divider = ctk.CTkFrame(master, height=2, fg_color="gray30")
        divider.grid(row=row, column=0, columnspan=_MATRIX_COLUMNS, sticky="ew", pady=(10, 16))
        row += 1

        return row

    # ------------------------------------------------------------------
    # Full OWASP Top 10 matrix
    # ------------------------------------------------------------------
    def _render_matrix(self, master, start_row: int) -> None:
        matrix_title = ctk.CTkLabel(
            master, text="📚  The Full OWASP Top 10 (2021)", font=ctk.CTkFont(size=17, weight="bold")
        )
        matrix_title.grid(row=start_row, column=0, columnspan=_MATRIX_COLUMNS, sticky="w", pady=(0, 8))

        categories = list(OwaspCategory)
        for idx, category in enumerate(categories):
            info = CATEGORY_INFO.get(category)
            if info is None:
                continue
            row = start_row + 1 + idx // _MATRIX_COLUMNS
            col = idx % _MATRIX_COLUMNS
            tile = self._build_category_tile(master, category, info)
            tile.grid(row=row, column=col, sticky="nsew", padx=6, pady=6)

    def _build_category_tile(self, master, category: OwaspCategory, info) -> ctk.CTkFrame:
        tile = ctk.CTkFrame(master, corner_radius=14, fg_color=info.color)
        tile.grid_columnconfigure(0, weight=1)

        header = ctk.CTkLabel(
            tile,
            text=f"{info.icon}  {category.value}",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="white",
            anchor="w",
            justify="left",
            wraplength=460,
        )
        header.grid(row=0, column=0, sticky="w", padx=14, pady=(14, 6))

        summary = ctk.CTkLabel(
            tile,
            text=info.summary,
            text_color="white",
            anchor="w",
            justify="left",
            wraplength=460,
            font=ctk.CTkFont(size=12),
        )
        summary.grid(row=1, column=0, sticky="w", padx=14, pady=(0, 10))

        inner = ctk.CTkFrame(tile, corner_radius=10, fg_color=("gray95", "gray14"))
        inner.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 14))
        inner.grid_columnconfigure(0, weight=1)

        for i, attack in enumerate(info.attacks):
            attack_label = ctk.CTkLabel(
                inner,
                text=f"⚔ {attack.attack_name}",
                font=ctk.CTkFont(size=12, weight="bold"),
                anchor="w",
                justify="left",
                wraplength=440,
            )
            attack_label.grid(row=i * 3, column=0, sticky="w", padx=10, pady=(8, 0))

            how_label = ctk.CTkLabel(
                inner,
                text=attack.how_it_works,
                anchor="w",
                justify="left",
                wraplength=440,
                font=ctk.CTkFont(size=11),
                text_color="gray60",
            )
            how_label.grid(row=i * 3 + 1, column=0, sticky="w", padx=10, pady=(2, 2))

            protect_label = ctk.CTkLabel(
                inner,
                text=f"🛡 {attack.protection}",
                anchor="w",
                justify="left",
                wraplength=440,
                font=ctk.CTkFont(size=11),
                text_color="#2FA572",
            )
            protect_label.grid(row=i * 3 + 2, column=0, sticky="w", padx=10, pady=(0, 8))

        return tile
