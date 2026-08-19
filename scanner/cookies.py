"""
scanner/cookies.py
--------------------
Inspects Set-Cookie headers for Secure, HttpOnly, and SameSite attributes.

Security concept demonstrated:
    OWASP A05:2021 (Security Misconfiguration) and A02:2021 (Cryptographic
    Failures) both relate here: a session cookie without 'Secure' can be
    sent over plain HTTP and intercepted; without 'HttpOnly' it's readable
    by JavaScript (making it a juicy target if an XSS bug exists
    elsewhere - this is why defense-in-depth matters); without 'SameSite'
    it may be sent on cross-site requests, weakening CSRF defenses.

    This module only reads cookie attributes from response headers that
    were already returned by a normal GET request - it never sets,
    submits, or manipulates cookies.
"""

from __future__ import annotations

import requests

from scanner.models import Finding, OwaspCategory, RiskLevel


def check_cookie_security(response: requests.Response) -> list[Finding]:
    """
    Inspect all Set-Cookie headers on the response for secure attributes.

    Args:
        response: A `requests.Response` from a prior safe GET request.

    Returns:
        List of Finding objects, one per missing attribute per cookie.
    """
    findings: list[Finding] = []

    raw_cookie_headers = _get_all_set_cookie_headers(response)
    is_https = response.url.startswith("https")

    for raw_cookie in raw_cookie_headers:
        cookie_name = raw_cookie.split("=", 1)[0].strip()
        lowered = raw_cookie.lower()

        if is_https and "secure" not in lowered:
            findings.append(
                Finding(
                    owasp_category=OwaspCategory.CRYPTOGRAPHIC_FAILURES,
                    title=f"Cookie '{cookie_name}' missing Secure flag",
                    description=(
                        f"The cookie '{cookie_name}' was set without the 'Secure' attribute."
                    ),
                    why_it_matters=(
                        "Without 'Secure', a browser may send this cookie over an "
                        "unencrypted HTTP connection if one is ever available, "
                        "exposing it to network interception."
                    ),
                    potential_impact="Cookie value (e.g. session token) could be intercepted in transit.",
                    recommendation="Add the 'Secure' attribute to this cookie.",
                    risk_level=RiskLevel.MEDIUM,
                    evidence=f"Set-Cookie: {cookie_name}=...",
                )
            )

        if "httponly" not in lowered:
            findings.append(
                Finding(
                    owasp_category=OwaspCategory.SECURITY_MISCONFIGURATION,
                    title=f"Cookie '{cookie_name}' missing HttpOnly flag",
                    description=(
                        f"The cookie '{cookie_name}' was set without the 'HttpOnly' attribute."
                    ),
                    why_it_matters=(
                        "Without 'HttpOnly', client-side JavaScript can read this "
                        "cookie's value. If an XSS vulnerability exists anywhere on "
                        "the site, this cookie becomes directly stealable."
                    ),
                    potential_impact="Increases severity of any XSS vulnerability by exposing cookie contents.",
                    recommendation="Add the 'HttpOnly' attribute to this cookie.",
                    risk_level=RiskLevel.MEDIUM,
                    evidence=f"Set-Cookie: {cookie_name}=...",
                )
            )

        if "samesite" not in lowered:
            findings.append(
                Finding(
                    owasp_category=OwaspCategory.SECURITY_MISCONFIGURATION,
                    title=f"Cookie '{cookie_name}' missing SameSite attribute",
                    description=(
                        f"The cookie '{cookie_name}' was set without a 'SameSite' attribute."
                    ),
                    why_it_matters=(
                        "Without 'SameSite', the cookie may be included on "
                        "cross-site requests, which weakens CSRF protections."
                    ),
                    potential_impact="Increases exposure to cross-site request forgery (CSRF).",
                    recommendation="Add 'SameSite=Lax' or 'SameSite=Strict' as appropriate.",
                    risk_level=RiskLevel.LOW,
                    evidence=f"Set-Cookie: {cookie_name}=...",
                )
            )

    return findings


def _get_all_set_cookie_headers(response: requests.Response) -> list[str]:
    """
    Return each raw Set-Cookie header value individually.

    `requests`/`urllib3` can combine multiple Set-Cookie headers if read via
    `response.headers.get(...)`; we use the underlying urllib3 HTTPHeaderDict's
    `getlist` to get each cookie's raw attributes correctly.
    """
    try:
        return response.raw.headers.getlist("Set-Cookie")
    except AttributeError:
        # Fallback for environments where raw headers aren't accessible.
        value = response.headers.get("Set-Cookie")
        return [value] if value else []
