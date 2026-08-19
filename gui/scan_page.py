"""
gui/scan_page.py
-----------------
The 'Scan' page: lets the user enter a target URL, runs the full suite
of safe OWASP Top 10 checks (scanner/scanner.py) on a background
thread, then displays and persists the results.

Security concept demonstrated:
    The scan runs on a background `threading.Thread`, not the GUI
    thread. This isn't just a UX nicety - it's what makes the "single
    controlled request path" in scanner.py meaningful: the GUI thread
    never itself makes network calls, so every request this app makes
    to a target is traceable to `scanner/scanner.py`. The page also
    enforces a basic self-check reminder ("authorized targets only")
    directly next to the input, since a GUI tool makes it easy to point
    at a target without thinking twice.
"""

from __future__ import annotations

import threading
from urllib.parse import urlparse

import customtkinter as ctk

from database.db_manager import save_scan_result
from scanner.models import RiskLevel, ScanResult
from scanner.scanner import ScanError, run_scan
from utils.logger import get_logger

logger = get_logger(__name__)

_RISK_COLORS = {
    RiskLevel.HIGH: "#D64545",
    RiskLevel.MEDIUM: "#E0A030",
    RiskLevel.LOW: "#3B8ED0",
}


class ScanPage(ctk.CTkFrame):
    """Lets the user run a scan against a single target URL."""

    def __init__(self, master: ctk.CTkBaseClass, on_scan_saved=None) -> None:
        super().__init__(master, fg_color="transparent")
        self.on_scan_saved = on_scan_saved  # callback so Dashboard/Findings can refresh

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        self._build_header_and_input()
        self._build_status_area()
        self._build_results_area()

        self._scan_thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    def _build_header_and_input(self) -> None:
        header = ctk.CTkLabel(self, text="Scan", font=ctk.CTkFont(size=26, weight="bold"))
        header.grid(row=0, column=0, sticky="w", pady=(0, 4))

        notice = ctk.CTkLabel(
            self,
            text=(
                "⚠️  Only scan targets you own or are explicitly authorized to test "
                "(e.g. your own local demo app). All checks are passive/read-only."
            ),
            text_color="#E0A030",
            font=ctk.CTkFont(size=12),
        )
        notice.grid(row=1, column=0, sticky="w", pady=(0, 12))

        input_row = ctk.CTkFrame(self, fg_color="transparent")
        input_row.grid(row=2, column=0, sticky="ew", pady=(0, 12))
        input_row.grid_columnconfigure(0, weight=1)

        self.url_entry = ctk.CTkEntry(
            input_row,
            placeholder_text="e.g. http://localhost:8080 or https://example-demo-app.local",
            height=38,
        )
        self.url_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self.url_entry.bind("<Return>", lambda _e: self._start_scan())

        self.scan_button = ctk.CTkButton(
            input_row, text="Run Scan", width=140, height=38, command=self._start_scan
        )
        self.scan_button.grid(row=0, column=1)

    def _build_status_area(self) -> None:
        self.status_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.status_frame.grid(row=3, column=0, sticky="new")
        self.status_frame.grid_columnconfigure(0, weight=1)

        self.progress_bar = ctk.CTkProgressBar(self.status_frame)
        self.progress_bar.set(0)

        self.status_label = ctk.CTkLabel(self.status_frame, text="", text_color="gray60")

    def _build_results_area(self) -> None:
        self.results_container = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.results_container.grid(row=4, column=0, sticky="nsew", pady=(12, 0))
        self.results_container.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)

    # ------------------------------------------------------------------
    def _start_scan(self) -> None:
        if self._scan_thread and self._scan_thread.is_alive():
            return  # scan already in progress

        target = self.url_entry.get().strip()
        if not target:
            self._show_status("Please enter a target URL.", is_error=True)
            return

        self._clear_results()
        self.scan_button.configure(state="disabled", text="Scanning...")
        self.progress_bar.grid(row=0, column=0, sticky="ew", pady=(4, 4))
        self.progress_bar.configure(mode="indeterminate")
        self.progress_bar.start()
        self._show_status(f"Running safe, read-only checks against {target} ...")

        self._scan_thread = threading.Thread(target=self._run_scan_worker, args=(target,), daemon=True)
        self._scan_thread.start()

    def _run_scan_worker(self, target: str) -> None:
        """Runs on a background thread - must not touch widgets directly."""
        try:
            result = run_scan(target)
            scan_id = save_scan_result(result)
            self.after(0, self._on_scan_complete, result, scan_id, None)
        except ScanError as exc:
            self.after(0, self._on_scan_complete, None, None, str(exc))
        except Exception as exc:  # noqa: BLE001
            logger.exception("Unexpected error during scan")
            self.after(0, self._on_scan_complete, None, None, f"Unexpected error: {exc}")

    def _on_scan_complete(self, result: ScanResult | None, scan_id: int | None, error: str | None) -> None:
        self.progress_bar.stop()
        self.progress_bar.grid_forget()
        self.scan_button.configure(state="normal", text="Run Scan")

        if error:
            self._show_status(f"❌ {error}", is_error=True)
            return

        self._show_status(
            f"✅ Scan complete. Score: {result.security_score}%  |  "
            f"High: {result.high_count}  Medium: {result.medium_count}  Low: {result.low_count}"
        )
        self._render_results(result)

        if self.on_scan_saved:
            self.on_scan_saved()

    # ------------------------------------------------------------------
    def _show_status(self, text: str, is_error: bool = False) -> None:
        self.status_label.configure(text=text, text_color="#D64545" if is_error else "gray70")
        self.status_label.grid(row=1, column=0, sticky="w", pady=(0, 4))

    def _clear_results(self) -> None:
        for child in self.results_container.winfo_children():
            child.destroy()

    def _render_results(self, result: ScanResult) -> None:
        self._clear_results()

        if not result.findings:
            ctk.CTkLabel(
                self.results_container,
                text="No issues detected by the current checks. 🎉",
                text_color="#2FA572",
                font=ctk.CTkFont(size=14),
            ).grid(row=0, column=0, sticky="w", pady=12)
            return

        # Sort High -> Medium -> Low for readability
        order = {RiskLevel.HIGH: 0, RiskLevel.MEDIUM: 1, RiskLevel.LOW: 2}
        sorted_findings = sorted(result.findings, key=lambda f: order[f.risk_level])

        for row, finding in enumerate(sorted_findings):
            card = self._build_finding_card(self.results_container, finding)
            card.grid(row=row, column=0, sticky="ew", pady=6, padx=2)

        if result.errors:
            note = ctk.CTkLabel(
                self.results_container,
                text=f"Note: {len(result.errors)} check(s) could not complete - see logs.",
                text_color="gray50",
                font=ctk.CTkFont(size=11),
            )
            note.grid(row=len(sorted_findings), column=0, sticky="w", pady=(8, 0))

    def _build_finding_card(self, master: ctk.CTkBaseClass, finding) -> ctk.CTkFrame:
        card = ctk.CTkFrame(master, corner_radius=10)
        card.grid_columnconfigure(1, weight=1)

        color = _RISK_COLORS[finding.risk_level]
        badge = ctk.CTkLabel(
            card,
            text=finding.risk_level.value.upper(),
            fg_color=color,
            text_color="white",
            corner_radius=6,
            width=70,
            height=22,
            font=ctk.CTkFont(size=11, weight="bold"),
        )
        badge.grid(row=0, column=0, padx=(12, 10), pady=(12, 0), sticky="nw")

        title = ctk.CTkLabel(
            card, text=finding.title, font=ctk.CTkFont(size=14, weight="bold"), anchor="w", justify="left"
        )
        title.grid(row=0, column=1, sticky="w", pady=(12, 0))

        category = ctk.CTkLabel(
            card, text=finding.owasp_category.value, text_color="gray60", anchor="w", font=ctk.CTkFont(size=11)
        )
        category.grid(row=1, column=1, sticky="w")

        body_text = (
            f"{finding.description}\n\n"
            f"Why it matters: {finding.why_it_matters}\n\n"
            f"Recommendation: {finding.recommendation}"
        )
        body = ctk.CTkLabel(
            card, text=body_text, anchor="w", justify="left", wraplength=780, font=ctk.CTkFont(size=12)
        )
        body.grid(row=2, column=1, sticky="w", pady=(6, 12), padx=(0, 12))

        return card

    def refresh(self) -> None:
        """Called by SecurityLabApp when this page is shown - no auto-reload needed."""
