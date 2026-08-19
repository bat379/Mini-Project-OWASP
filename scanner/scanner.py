"""
scanner/scanner.py
--------------------
Orchestrates all individual, read-only OWASP Top 10 checks against a
single target URL and produces a consolidated ScanResult.

Security concept demonstrated:
    This module is deliberately the *only* place that performs network
    requests to the target's main page and one benign 404 probe (the
    latter delegated to configuration.py) - every check module receives
    already-fetched data rather than making its own uncontrolled
    requests. This makes the tool's network footprint auditable in one
    place: a reviewer can see exactly how many requests a scan makes and
    to which paths, which matters for staying within "authorized target,
    read-only" boundaries.

    Each check module is wrapped in its own try/except so that one
    failing check (e.g. a parsing error) never aborts the whole scan -
    partial, honest results are better than a hard crash.
"""

from __future__ import annotations

from urllib.parse import urlparse

import requests

from scanner.authentication import check_authentication_indicators
from scanner.configuration import check_https_configuration, check_information_disclosure
from scanner.cookies import check_cookie_security
from scanner.headers import check_security_headers
from scanner.input_validation import check_forms
from scanner.models import ScanResult
from utils.logger import get_logger
from utils.risk_score import calculate_security_score

logger = get_logger(__name__)

_TIMEOUT = 10
_HEADERS = {"User-Agent": "OWASP-Security-Lab-Scanner/1.0 (Educational, read-only)"}


class ScanError(Exception):
    """Raised when the target cannot be reached at all (fatal, not a finding)."""


def normalize_url(raw_url: str) -> str:
    """Ensure the URL has a scheme; default to https:// if none given."""
    raw_url = raw_url.strip()
    if not raw_url:
        raise ScanError("Target URL cannot be empty.")
    if not urlparse(raw_url).scheme:
        raw_url = f"https://{raw_url}"
    return raw_url


def run_scan(target_url: str) -> ScanResult:
    """
    Run the full suite of safe, read-only OWASP Top 10 checks against a
    single target URL.

    Args:
        target_url: The URL to assess. Scheme is added automatically if
            missing (defaults to https://).

    Returns:
        A populated ScanResult with findings, score, and any non-fatal
        check errors.

    Raises:
        ScanError: If the target cannot be reached at all.
    """
    target_url = normalize_url(target_url)
    logger.info("Starting scan of %s", target_url)

    try:
        response = requests.get(
            target_url, timeout=_TIMEOUT, headers=_HEADERS, allow_redirects=True, verify=True
        )
    except requests.exceptions.RequestException as exc:
        logger.warning("Failed to reach target %s: %s", target_url, exc)
        raise ScanError(f"Could not reach {target_url}: {exc}") from exc

    result = ScanResult(target_url=target_url)

    _run_check(result, "HTTPS configuration", check_https_configuration, target_url)
    _run_check(result, "Security headers", check_security_headers, response)
    _run_check(result, "Cookie security", check_cookie_security, response)
    _run_check(result, "Information disclosure", check_information_disclosure, response)
    _run_check(result, "Authentication indicators", check_authentication_indicators, response)
    _run_check(result, "Form review", check_forms, response.text, response.url)

    result.security_score = calculate_security_score(result.findings)

    logger.info(
        "Scan of %s complete: score=%d, high=%d, medium=%d, low=%d",
        target_url,
        result.security_score,
        result.high_count,
        result.medium_count,
        result.low_count,
    )
    return result


def _run_check(result: ScanResult, check_name: str, check_fn, *args) -> None:
    """Run a single check function, isolating failures so one bad check
    doesn't abort the whole scan."""
    try:
        findings = check_fn(*args)
        result.findings.extend(findings)
    except Exception as exc:  # noqa: BLE001 - intentionally broad, isolates failures
        logger.exception("Check '%s' failed", check_name)
        result.errors.append(f"{check_name} check failed: {exc}")
