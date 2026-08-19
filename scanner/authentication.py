"""
scanner/authentication.py
----------------------------
Passive checks related to OWASP A07:2021 (Identification and
Authentication Failures) that don't require submitting credentials or
attempting to log in anywhere.

Security concept demonstrated:
    Authentication testing in a *safe* educational tool has to stop well
    short of anything resembling credential stuffing, brute force, or
    login bypass. What's left in the "safe" zone is configuration
    review: does the session cookie reveal the backend framework (aiding
    fingerprinting), and is the session cookie itself missing the
    protections checked in cookies.py. This module focuses on the
    framework-fingerprinting angle specifically, to avoid duplicating
    cookies.py.
"""

from __future__ import annotations

import requests

from scanner.models import Finding, OwaspCategory, RiskLevel

# Cookie names -> the framework/language they reveal by default
_DEFAULT_SESSION_COOKIE_NAMES = {
    "phpsessid": "PHP",
    "jsessionid": "Java (e.g. Tomcat, Spring)",
    "asp.net_sessionid": "ASP.NET",
    "connect.sid": "Node.js (Express, default config)",
    "django_sessionid": "Django",
    "laravel_session": "Laravel",
}


def check_authentication_indicators(response: requests.Response) -> list[Finding]:
    """
    Inspect cookie names on the response for default/framework-revealing
    session cookie names.

    Args:
        response: A `requests.Response` from a prior safe GET request.

    Returns:
        List of Finding objects.
    """
    findings: list[Finding] = []

    cookie_names = {c.name.lower() for c in response.cookies}
    # also check raw Set-Cookie headers in case requests' cookie jar missed any
    try:
        for raw in response.raw.headers.getlist("Set-Cookie"):
            cookie_names.add(raw.split("=", 1)[0].strip().lower())
    except AttributeError:
        pass

    for cookie_name in cookie_names:
        framework = _DEFAULT_SESSION_COOKIE_NAMES.get(cookie_name)
        if framework:
            findings.append(
                Finding(
                    owasp_category=OwaspCategory.AUTH_FAILURES,
                    title="Default session cookie name reveals backend framework",
                    description=(
                        f"A session cookie named '{cookie_name}' was observed, "
                        f"which is the default name used by {framework}."
                    ),
                    why_it_matters=(
                        "Default cookie names make it trivial to fingerprint the "
                        "backend technology, narrowing down which known "
                        "vulnerabilities/CVEs to try against the site."
                    ),
                    potential_impact="Aids reconnaissance for targeted attacks; not exploitable on its own.",
                    recommendation=(
                        "Rename the session cookie to a non-default, non-revealing "
                        "value in the framework/server configuration."
                    ),
                    risk_level=RiskLevel.LOW,
                    evidence=f"Observed cookie name: {cookie_name}",
                )
            )

    return findings
