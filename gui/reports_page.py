"""
gui/reports_page.py
---------------------
The 'Reports' page: pick any past scan, review its automated
post-scan exploitability assessment, and export a PDF or CSV report.

Security concept demonstrated:
    Like FindingsPage, this page is strictly read-only against the
    database - it only ever runs SELECT queries and writes report files
    to disk (never to the DB, never to the network). The "automated
    assessment" it displays is produced entirely offline from data the
    scan already collected (utils/threat_intel.py); no additional
    requests are made to the original target when generating a report.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from tkinter import filedialog

import customtkinter as ctk

from database.db_manager import get_findings_for_scan, get_scan_by_id, get_scan_history
from reports.report_generator import generate_csv_report, generate_pdf_report
from utils.logger import get_logger
from utils.threat_intel import assess_scan

logger = get_logger(__name__)

_DEFAULT_EXPORT_DIR = Path.home() / "Downloads"


class ReportsPage(ctk.CTkFrame):
    """Report review + export for any previously-run scan."""

    def __init__(self, master: ctk.CTkBaseClass) -> None:
        super().__init__(master, fg_color="transparent")

        self.grid_columnconfigure(0, weight=1)

        self._scans: list = []
        self._selected_scan_id: int | None = None

        self._build_header_and_picker()
        self._build_summary_row()
        self._build_assessment_area()

        self.refresh()

    # ------------------------------------------------------------------
    def _build_header_and_picker(self) -> None:
        header = ctk.CTkLabel(self, text="Reports", font=ctk.CTkFont(size=26, weight="bold"))
        header.grid(row=0, column=0, sticky="w", pady=(0, 4))

        subtitle = ctk.CTkLabel(
            self,
            text="Review a past scan's automated exploitability assessment, or export it as a file.",
            text_color="gray60",
            font=ctk.CTkFont(size=12),
        )
        subtitle.grid(row=1, column=0, sticky="w", pady=(0, 10))

        picker_row = ctk.CTkFrame(self, fg_color="transparent")
        picker_row.grid(row=2, column=0, sticky="ew", pady=(0, 6))
        picker_row.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(picker_row, text="Scan:", font=ctk.CTkFont(size=13)).grid(
            row=0, column=0, sticky="w", padx=(0, 8)
        )

        self.scan_menu = ctk.CTkOptionMenu(
            picker_row, values=["No scans yet"], command=self._on_scan_selected, width=420
        )
        self.scan_menu.grid(row=0, column=1, sticky="w")

        self.export_pdf_btn = ctk.CTkButton(
            picker_row, text="⬇ Export PDF", width=130, command=self._export_pdf
        )
        self.export_pdf_btn.grid(row=0, column=2, padx=(10, 0))

        self.export_csv_btn = ctk.CTkButton(
            picker_row, text="⬇ Export CSV", width=130, command=self._export_csv
        )
        self.export_csv_btn.grid(row=0, column=3, padx=(10, 0))

        self.export_status = ctk.CTkLabel(self, text="", text_color="gray60", font=ctk.CTkFont(size=11))
        self.export_status.grid(row=3, column=0, sticky="w")

    def _build_summary_row(self) -> None:
        self.summary_row = ctk.CTkFrame(self, fg_color="transparent")
        self.summary_row.grid(row=4, column=0, sticky="ew", pady=(8, 6))
        self.summary_row.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.likely_card = self._make_stat(self.summary_row, "Likely Exploitable", "#D64545")
        self.likely_card.grid(row=0, column=0, sticky="nsew", padx=4)
        self.possible_card = self._make_stat(self.summary_row, "Possibly Exploitable", "#E0762F")
        self.possible_card.grid(row=0, column=1, sticky="nsew", padx=4)
        self.hardening_card = self._make_stat(self.summary_row, "Hardening Gaps", "#E0A030")
        self.hardening_card.grid(row=0, column=2, sticky="nsew", padx=4)
        self.info_card = self._make_stat(self.summary_row, "Informational", "#3B8ED0")
        self.info_card.grid(row=0, column=3, sticky="nsew", padx=4)

    def _make_stat(self, master, title: str, color: str) -> ctk.CTkFrame:
        card = ctk.CTkFrame(master, corner_radius=10)
        card.grid_columnconfigure(0, weight=1)
        value = ctk.CTkLabel(card, text="0", font=ctk.CTkFont(size=22, weight="bold"), text_color=color)
        value.grid(row=0, column=0, pady=(10, 0))
        ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=11), text_color="gray60").grid(
            row=1, column=0, pady=(0, 10)
        )
        card.value_label = value  # type: ignore[attr-defined]
        return card

    def _build_assessment_area(self) -> None:
        self.assessment_scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.assessment_scroll.grid(row=5, column=0, sticky="nsew", pady=(6, 0))
        self.assessment_scroll.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(5, weight=1)

    # ------------------------------------------------------------------
    def refresh(self) -> None:
        try:
            self._scans = get_scan_history()
        except Exception:
            logger.exception("Failed to load scan history for Reports page")
            self._scans = []

        if not self._scans:
            self.scan_menu.configure(values=["No scans yet"])
            self.scan_menu.set("No scans yet")
            self._selected_scan_id = None
            self._render_empty("Run a scan from the 'Scan' tab, then come back here to view its report.")
            return

        labels = [self._scan_label(s) for s in self._scans]
        self.scan_menu.configure(values=labels)

        # Keep the current selection if it still exists, otherwise pick the newest scan.
        if self._selected_scan_id is None or not any(s["id"] == self._selected_scan_id for s in self._scans):
            self._selected_scan_id = self._scans[0]["id"]
        self.scan_menu.set(self._scan_label_by_id(self._selected_scan_id))

        self._load_selected_report()

    def _scan_label(self, scan_row) -> str:
        return f"#{scan_row['id']}  {scan_row['target_url']}  ({scan_row['scan_date']})"

    def _scan_label_by_id(self, scan_id: int) -> str:
        for s in self._scans:
            if s["id"] == scan_id:
                return self._scan_label(s)
        return "No scans yet"

    def _on_scan_selected(self, label: str) -> None:
        try:
            scan_id = int(label.split()[0].lstrip("#"))
        except (ValueError, IndexError):
            return
        self._selected_scan_id = scan_id
        self._load_selected_report()

    def _load_selected_report(self) -> None:
        if self._selected_scan_id is None:
            return
        try:
            findings = get_findings_for_scan(self._selected_scan_id)
        except Exception:
            logger.exception("Failed to load findings for scan #%s", self._selected_scan_id)
            findings = []

        assessment = assess_scan(findings)
        counts = assessment["counts"]
        self.likely_card.value_label.configure(text=str(counts.get("Likely Exploitable", 0)))
        self.possible_card.value_label.configure(text=str(counts.get("Possibly Exploitable", 0)))
        self.hardening_card.value_label.configure(text=str(counts.get("Hardening Gap", 0)))
        self.info_card.value_label.configure(text=str(counts.get("Informational", 0)))

        self._render_assessment(assessment["assessed_findings"])
        self.export_status.configure(text="")

    def _render_empty(self, text: str) -> None:
        for child in self.assessment_scroll.winfo_children():
            child.destroy()
        ctk.CTkLabel(self.assessment_scroll, text=text, text_color="gray60").grid(
            row=0, column=0, sticky="w", pady=12
        )
        for card in (
            getattr(self, "likely_card", None),
            getattr(self, "possible_card", None),
            getattr(self, "hardening_card", None),
            getattr(self, "info_card", None),
        ):
            if card is not None:
                card.value_label.configure(text="0")

    def _render_assessment(self, assessed_findings: list) -> None:
        for child in self.assessment_scroll.winfo_children():
            child.destroy()

        if not assessed_findings:
            ctk.CTkLabel(
                self.assessment_scroll,
                text="No findings were recorded for this scan. 🎉",
                text_color="#2FA572",
            ).grid(row=0, column=0, sticky="w", pady=12)
            return

        for row, item in enumerate(assessed_findings):
            card = self._build_assessment_card(self.assessment_scroll, item)
            card.grid(row=row, column=0, sticky="ew", pady=5, padx=2)

    def _build_assessment_card(self, master, item: dict) -> ctk.CTkFrame:
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
        badge.grid(row=0, column=0, padx=(12, 10), pady=(12, 0), sticky="nw")

        title = ctk.CTkLabel(
            card, text=item["title"], font=ctk.CTkFont(size=14, weight="bold"), anchor="w", justify="left"
        )
        title.grid(row=0, column=1, sticky="w", pady=(12, 0))

        category = ctk.CTkLabel(
            card, text=item["owasp_category"], text_color="gray60", anchor="w", font=ctk.CTkFont(size=11)
        )
        category.grid(row=1, column=1, sticky="w")

        body_text = (
            f"Likely attack: {item['attack_name']}\n"
            f"{item['how_it_works']}\n\n"
            f"Protection: {item['protection']}"
        )
        body = ctk.CTkLabel(
            card, text=body_text, anchor="w", justify="left", wraplength=780, font=ctk.CTkFont(size=12)
        )
        body.grid(row=2, column=1, sticky="w", pady=(6, 12), padx=(0, 12))

        return card

    # ------------------------------------------------------------------
    def _export_pdf(self) -> None:
        self._export(kind="pdf")

    def _export_csv(self) -> None:
        self._export(kind="csv")

    def _export(self, kind: str) -> None:
        if self._selected_scan_id is None:
            self.export_status.configure(text="No scan selected.", text_color="#D64545")
            return

        scan_row = get_scan_by_id(self._selected_scan_id)
        if scan_row is None:
            self.export_status.configure(text="Selected scan no longer exists.", text_color="#D64545")
            return

        findings = get_findings_for_scan(self._selected_scan_id)

        default_name = f"owasp-report-scan{self._selected_scan_id}.{kind}"
        try:
            path = filedialog.asksaveasfilename(
                title="Save report",
                initialdir=str(_DEFAULT_EXPORT_DIR if _DEFAULT_EXPORT_DIR.exists() else Path.home()),
                initialfile=default_name,
                defaultextension=f".{kind}",
                filetypes=[(kind.upper(), f"*.{kind}")],
            )
        except Exception:
            # Some headless/test environments have no display for a file dialog.
            path = str(Path.home() / default_name)

        if not path:
            return  # user cancelled

        try:
            if kind == "pdf":
                generate_pdf_report(scan_row, findings, path)
            else:
                generate_csv_report(findings, path)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to export %s report", kind)
            self.export_status.configure(text=f"❌ Export failed: {exc}", text_color="#D64545")
            return

        self.export_status.configure(text=f"✅ Saved to {path}", text_color="#2FA572")
        self._reveal_in_file_manager(path)

    def _reveal_in_file_manager(self, path: str) -> None:
        """Best-effort: open the containing folder so the user can find the file.
        Never raises - this is a convenience, not a core feature."""
        try:
            folder = str(Path(path).parent)
            if sys.platform.startswith("darwin"):
                subprocess.Popen(["open", folder])
            elif sys.platform.startswith("win"):
                os.startfile(folder)  # type: ignore[attr-defined]
            else:
                subprocess.Popen(["xdg-open", folder])
        except Exception:
            logger.debug("Could not open file manager for %s (non-fatal)", path)
