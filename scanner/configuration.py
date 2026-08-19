"""
scanner/configuration.py
--------------------------
Checks HTTPS usage/redirection and passive information-disclosure
indicators (server banners, framework versions, verbose errors,
directory listings).

Security concept demonstrated:
    OWASP A02:2021 (Cryptographic Failures) for the HTTPS checks, and
    A05:2021 (Security Misconfiguration) for information disclosure.
    Attackers use exposed server/framework versions to look up known
    CVEs for that exact version - this is reconnaissance, not exploitation,
    and reporting it defensively (so the owner can suppress it) is the
    same read-only technique legitimate scanners use.

    Every request here is a single, ordinary GET to either the target URL
    itself or one clearly-nonexistent path (to observe the *default* error
    page) - never a path guessed to hit an actual sensitive resource, and
    never with a payload of any kind.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlparse

import requests

from scanner.models import Finding, OwaspCategory, RiskLevel

_TIMEOUT = 8
_HEADERS = {"User-Agent": "OWASP-Security-Lab-Scanner/1.0 (Educational, read-only)"}

_VERBOSE_ERROR_MARKERS = [
    "traceback (most recent call last)",  # Python/Django/Flask debug
    "stack trace",
    "at System.",  # .NET
    "warning: mysql_",  # PHP/MySQL
    "ORA-01756",  # Oracle
    "microsoft ole db provider",
    "unhandled exception",
]

_DIRECTORY_LISTING_MARKERS = ["index of /", "<title>directory listing"]


def check_https_configuration(base_url: str) -> list[Finding]:
    """
    Check whether the site is served over HTTPS and whether plain HTTP
    redirects to HTTPS. Performs at most two extra GET requests
    (the HTTP and HTTPS variants of the same host).
    """
    findings: list[Finding] = []
    parsed = urlparse(base_url)
    host = parsed.netloc or parsed.path  # tolerate bare host input

    http_url = f"http://{host}"
    https_url = f"https://{host}"

    if parsed.scheme == "http" or not parsed.scheme:
        findings.append(
            Finding(
                owasp_category=OwaspCategory.CRYPTOGRAPHIC_FAILURES,
                title="Site accessed over plain HTTP",
                description="The target was reached over unencrypted HTTP.",
                why_it_matters=(
                    "Traffic sent over HTTP (including any form submissions, "
                    "cookies, or headers) is visible to anyone on the network path."
                ),
                potential_impact="Credentials, session tokens, or page content could be intercepted.",
                recommendation="Serve the site exclusively over HTTPS with a valid certificate.",
                risk_level=RiskLevel.HIGH,
                evidence=f"Accessed via: {http_url}",
            )
        )

    try:
        resp = requests.get(
            http_url, timeout=_TIMEOUT, headers=_HEADERS, allow_redirects=True, verify=True
        )
        final_scheme = urlparse(resp.url).scheme
        if final_scheme != "https":
            findings.append(
                Finding(
                    owasp_category=OwaspCategory.CRYPTOGRAPHIC_FAILURES,
                    title="No automatic HTTP → HTTPS redirect",
                    description=(
                        f"Requesting {http_url} did not redirect to an HTTPS URL "
                        f"(final URL scheme: '{final_scheme}')."
                    ),
                    why_it_matters=(
                        "Without a forced redirect, users who type or follow an "
                        "HTTP link will have their entire session unencrypted "
                        "unless they manually navigate to HTTPS."
                    ),
                    potential_impact="Users may unknowingly transmit data over an unencrypted connection.",
                    recommendation=(
                        "Configure the web server/load balancer to redirect all "
                        "HTTP requests to HTTPS (301), and add an HSTS header."
                    ),
                    risk_level=RiskLevel.MEDIUM,
                    evidence=f"Final URL after redirect: {resp.url}",
                )
            )
    except requests.exceptions.SSLError as exc:
        findings.append(
            Finding(
                owasp_category=OwaspCategory.CRYPTOGRAPHIC_FAILURES,
                title="TLS certificate validation failed",
                description="An SSL/TLS error occurred while validating the certificate.",
                why_it_matters=(
                    "An invalid, expired, or self-signed certificate breaks the "
                    "trust chain browsers rely on to confirm they're talking to "
                    "the genuine server."
                ),
                potential_impact="Users may be vulnerable to man-in-the-middle attacks, or simply see browser warnings.",
                recommendation="Install a valid certificate from a trusted CA and ensure it's renewed before expiry.",
                risk_level=RiskLevel.HIGH,
                evidence=str(exc)[:200],
            )
        )
    except requests.exceptions.RequestException:
        pass  # host may only serve HTTPS, or HTTP port may be closed - not a finding

    return findings


def check_information_disclosure(response: requests.Response) -> list[Finding]:
    """Check response headers/body for server banners and verbose errors."""
    findings: list[Finding] = []
    headers = response.headers

    for banner_header in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"):
        value = headers.get(banner_header)
        if value:
            findings.append(
                Finding(
                    owasp_category=OwaspCategory.SECURITY_MISCONFIGURATION,
                    title=f"'{banner_header}' header discloses software details",
                    description=f"The response includes '{banner_header}: {value}'.",
                    why_it_matters=(
                        "Disclosing exact software/framework versions helps an "
                        "attacker quickly identify known vulnerabilities (CVEs) "
                        "affecting that specific version without any active probing."
                    ),
                    potential_impact="Speeds up reconnaissance for targeted attacks against known version vulnerabilities.",
                    recommendation=(
                        f"Suppress or generalize the '{banner_header}' header at the "
                        "server/framework level (e.g. ServerTokens/expose_php settings)."
                    ),
                    risk_level=RiskLevel.LOW,
                    evidence=f"{banner_header}: {value}",
                )
            )

    findings.extend(_check_verbose_error_page(response.url))
    findings.extend(_check_directory_listing(response))

    return findings


def _check_verbose_error_page(base_url: str) -> list[Finding]:
    """Request one clearly-nonexistent path to see if default error pages leak detail."""
    findings: list[Finding] = []
    probe_url = urljoin(base_url, "this-path-should-not-exist-owasp-lab-check/")

    try:
        resp = requests.get(probe_url, timeout=_TIMEOUT, headers=_HEADERS, verify=True)
    except requests.exceptions.RequestException:
        return findings

    body_lower = resp.text.lower()[:5000]  # only inspect a bounded prefix
    for marker in _VERBOSE_ERROR_MARKERS:
        if marker in body_lower:
            findings.append(
                Finding(
                    owasp_category=OwaspCategory.SECURITY_MISCONFIGURATION,
                    title="Verbose error page exposed",
                    description=(
                        "Requesting a non-existent path returned a response that "
                        "appears to contain a debug/stack-trace style error page."
                    ),
                    why_it_matters=(
                        "Verbose errors can reveal file paths, framework internals, "
                        "database details, or source snippets to any visitor."
                    ),
                    potential_impact="Internal implementation details are exposed, aiding further attacks.",
                    recommendation=(
                        "Disable debug mode in production and configure generic "
                        "custom error pages for 404/500 responses."
                    ),
                    risk_level=RiskLevel.MEDIUM,
                    evidence=f"Marker matched on probe of a non-existent path (status {resp.status_code}).",
                )
            )
            break  # one finding is enough, no need to enumerate every marker

    return findings


def _check_directory_listing(response: requests.Response) -> list[Finding]:
    """Look for common 'Index of /' style directory listing markers on the current page."""
    findings: list[Finding] = []
    body_lower = response.text.lower()[:3000]

    if any(marker in body_lower for marker in _DIRECTORY_LISTING_MARKERS):
        findings.append(
            Finding(
                owasp_category=OwaspCategory.SECURITY_MISCONFIGURATION,
                title="Possible directory listing exposed",
                description="The page content resembles a web server's default directory listing.",
                why_it_matters=(
                    "Directory listings expose the full file structure of a "
                    "directory, potentially revealing backup files, config files, "
                    "or other unintended-to-be-public content."
                ),
                potential_impact="Sensitive or unintended files may be discovered and accessed directly.",
                recommendation="Disable directory listing/autoindex in the web server configuration.",
                risk_level=RiskLevel.MEDIUM,
                evidence="Response body matched a directory-listing pattern.",
            )
        )

    return findings
