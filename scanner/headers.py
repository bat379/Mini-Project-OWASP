"""
scanner/headers.py
-------------------
Detects missing or weak HTTP security response headers.

Security concept demonstrated:
    OWASP A05:2021 "Security Misconfiguration". Security headers are a
    server's way of telling the browser how to behave defensively (e.g.
    "never render me in a frame", "never guess my content type"). Their
    *absence* isn't a vulnerability on its own, but it removes a layer of
    defense-in-depth, so we report it at Medium risk (Low for weaker/
    secondary headers) rather than High.

    This check is 100% read-only: a single GET request already performed
    by the orchestrator, we only *inspect* the response headers that were
    returned. No requests are crafted to trigger or exploit anything.
"""

from __future__ import annotations

import requests

from scanner.models import Finding, OwaspCategory, RiskLevel

# header_name -> (risk if missing, guidance)
_REQUIRED_HEADERS: dict[str, tuple[RiskLevel, str]] = {
    "Content-Security-Policy": (
        RiskLevel.MEDIUM,
        "Define a Content-Security-Policy restricting script/style/frame "
        "sources to trusted origins (e.g. default-src 'self').",
    ),
    "X-Frame-Options": (
        RiskLevel.MEDIUM,
        "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' (or rely on the "
        "CSP 'frame-ancestors' directive) to prevent clickjacking.",
    ),
    "X-Content-Type-Options": (
        RiskLevel.LOW,
        "Set 'X-Content-Type-Options: nosniff' to stop browsers from "
        "MIME-sniffing responses away from the declared Content-Type.",
    ),
    "Referrer-Policy": (
        RiskLevel.LOW,
        "Set a Referrer-Policy such as 'strict-origin-when-cross-origin' "
        "to limit what URL data is leaked to third-party sites.",
    ),
    "Permissions-Policy": (
        RiskLevel.LOW,
        "Set a Permissions-Policy to explicitly disable browser features "
        "(camera, microphone, geolocation, etc.) the site doesn't use.",
    ),
    "Strict-Transport-Security": (
        RiskLevel.MEDIUM,
        "Set 'Strict-Transport-Security: max-age=63072000; includeSubDomains' "
        "on HTTPS responses to force browsers to always use HTTPS.",
    ),
}


def check_security_headers(response: requests.Response) -> list[Finding]:
    """
    Inspect an already-fetched response's headers for missing/weak
    security headers.

    Args:
        response: A `requests.Response` from a prior safe GET request.

    Returns:
        List of Finding objects, one per missing or weak header.
    """
    findings: list[Finding] = []
    headers = response.headers  # case-insensitive dict-like

    for header_name, (risk, guidance) in _REQUIRED_HEADERS.items():
        value = headers.get(header_name)

        if header_name == "Strict-Transport-Security" and not response.url.startswith("https"):
            # HSTS is meaningless on plain HTTP; that's covered separately
            # by the HTTPS configuration check instead.
            continue

        if value is None:
            findings.append(
                Finding(
                    owasp_category=OwaspCategory.SECURITY_MISCONFIGURATION,
                    title=f"Missing '{header_name}' header",
                    description=(
                        f"The response did not include a '{header_name}' header."
                    ),
                    why_it_matters=(
                        "Security headers instruct the browser to enforce protections "
                        "the server can't guarantee on its own (e.g. blocking framing, "
                        "restricting script sources, enforcing HTTPS)."
                    ),
                    potential_impact=_impact_for_header(header_name),
                    recommendation=guidance,
                    risk_level=risk,
                    evidence="Header not present in response.",
                )
            )
        else:
            weak_finding = _check_header_strength(header_name, value)
            if weak_finding:
                findings.append(weak_finding)

    return findings


def _impact_for_header(header_name: str) -> str:
    impacts = {
        "Content-Security-Policy": (
            "Increases exposure to cross-site scripting (XSS) and data "
            "injection attacks, since the browser has no allow-list of "
            "trusted content sources to fall back on."
        ),
        "X-Frame-Options": (
            "The page can be embedded in a hidden iframe on an attacker's "
            "site, enabling clickjacking attacks against users."
        ),
        "X-Content-Type-Options": (
            "Browsers may MIME-sniff a response as a different content "
            "type than declared, which can enable content-based attacks."
        ),
        "Referrer-Policy": (
            "Full URLs (potentially including sensitive query parameters) "
            "may be leaked to third-party sites via the Referer header."
        ),
        "Permissions-Policy": (
            "Embedded or compromised third-party scripts may access "
            "browser features (camera, mic, geolocation) unnecessarily."
        ),
        "Strict-Transport-Security": (
            "Users may be downgraded to plain HTTP by a network attacker "
            "(SSL-stripping), exposing traffic to interception."
        ),
    }
    return impacts.get(header_name, "Reduces defense-in-depth against common browser-based attacks.")


def _check_header_strength(header_name: str, value: str) -> Finding | None:
    """Flag common weak configurations for headers that ARE present."""
    lowered = value.lower()

    if header_name == "Content-Security-Policy":
        if "unsafe-inline" in lowered or "unsafe-eval" in lowered:
            return Finding(
                owasp_category=OwaspCategory.SECURITY_MISCONFIGURATION,
                title="Weak Content-Security-Policy directive",
                description="The CSP allows 'unsafe-inline' and/or 'unsafe-eval'.",
                why_it_matters=(
                    "These directives significantly weaken CSP's ability to "
                    "prevent XSS, since they permit inline/eval'd script execution."
                ),
                potential_impact="Reduces CSP's effectiveness as an XSS mitigation.",
                recommendation=(
                    "Remove 'unsafe-inline'/'unsafe-eval'; use nonces or hashes "
                    "for any required inline scripts."
                ),
                risk_level=RiskLevel.LOW,
                evidence=f"CSP value: {value[:120]}",
            )

    if header_name == "X-Frame-Options" and lowered not in ("deny", "sameorigin"):
        return Finding(
            owasp_category=OwaspCategory.SECURITY_MISCONFIGURATION,
            title="Non-standard X-Frame-Options value",
            description=f"X-Frame-Options is set to '{value}', which is non-standard.",
            why_it_matters="Browsers may not enforce an unrecognized value consistently.",
            potential_impact="May not reliably prevent clickjacking in all browsers.",
            recommendation="Use 'DENY' or 'SAMEORIGIN'.",
            risk_level=RiskLevel.LOW,
            evidence=f"X-Frame-Options: {value}",
        )

    return None
