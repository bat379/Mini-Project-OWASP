"""
utils/threat_intel.py
-----------------------
A small, static knowledge base that turns a raw `Finding` (an OWASP
category + a title + evidence) into something a non-expert user can
act on: "here is the *kind* of attack this gap makes easier, here is
how it works at a high level, and here is how to close it."

Security concept demonstrated:
    This is intentionally a *rules engine over public, well-known OWASP
    guidance* - not an exploit generator. Every "how_it_works" entry is a
    one- or two-sentence conceptual description (the same level of
    detail OWASP's own cheat sheets use), never step-by-step exploit
    instructions, payloads, or tool commands. The goal is defensive
    literacy: helping someone triage *which* of their findings deserve
    attention first, and *why*, not how to attack anything. Nothing
    here requires network access or a live target - it only reasons
    over findings that a scan already produced and stored locally.

Two things are exposed:
    1. CATEGORY_INFO - one entry per OWASP Top 10 (2021) category, used
       to render the Learning Center's colorful "risk matrix" grid.
    2. assess_finding()/assess_scan() - matches a stored finding's title
       against a small keyword table to attach a likely attack
       scenario + exploitability rating + protection summary, used by
       the Reports page's automated post-scan assessment.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from scanner.models import OwaspCategory, RiskLevel


class Exploitability(str, Enum):
    """How readily a given finding could realistically be leveraged.

    This is a *triage* signal, not a CVSS score - it answers "should a
    reader look at this one first?" rather than trying to precisely
    quantify risk.
    """

    LIKELY = "Likely Exploitable"
    POSSIBLE = "Possibly Exploitable"
    HARDENING = "Hardening Gap"
    INFORMATIONAL = "Informational"


# Sort/severity order and matrix colors, reused by both GUI pages and the
# PDF/CSV report generator so everything stays visually consistent.
EXPLOITABILITY_ORDER = {
    Exploitability.LIKELY: 0,
    Exploitability.POSSIBLE: 1,
    Exploitability.HARDENING: 2,
    Exploitability.INFORMATIONAL: 3,
}

EXPLOITABILITY_COLORS = {
    Exploitability.LIKELY: "#D64545",       # red
    Exploitability.POSSIBLE: "#E0762F",     # orange
    Exploitability.HARDENING: "#E0A030",    # amber
    Exploitability.INFORMATIONAL: "#3B8ED0",  # blue
}


@dataclass
class AttackScenario:
    """One concrete way a finding's underlying gap could be abused."""

    attack_name: str
    how_it_works: str
    protection: str
    exploitability: Exploitability


@dataclass
class CategoryInfo:
    """Learning Center entry for one OWASP Top 10 (2021) category."""

    color: str
    icon: str
    summary: str
    attacks: list[AttackScenario]


# ----------------------------------------------------------------------
# 1. Category-level knowledge base (Learning Center matrix)
# ----------------------------------------------------------------------
CATEGORY_INFO: dict[OwaspCategory, CategoryInfo] = {
    OwaspCategory.BROKEN_ACCESS_CONTROL: CategoryInfo(
        color="#D64545",
        icon="🔓",
        summary=(
            "Users can act outside their intended permissions - viewing or "
            "modifying data, pages, or accounts they shouldn't be able to reach."
        ),
        attacks=[
            AttackScenario(
                "Insecure Direct Object Reference (IDOR)",
                "An attacker changes an ID in a URL or request (e.g. account "
                "or order number) and the server returns another user's data "
                "because it never re-checks ownership.",
                "Enforce server-side authorization checks on every request, "
                "keyed to the logged-in user, not just to a valid-looking ID.",
                Exploitability.POSSIBLE,
            ),
            AttackScenario(
                "Forced Browsing",
                "An attacker requests an admin or internal URL directly, "
                "skipping the UI links that would normally hide it.",
                "Enforce access control on the server for every route, and "
                "never rely on hidden links as the only protection.",
                Exploitability.POSSIBLE,
            ),
        ],
    ),
    OwaspCategory.CRYPTOGRAPHIC_FAILURES: CategoryInfo(
        color="#8E44AD",
        icon="🔑",
        summary=(
            "Sensitive data (passwords, sessions, personal data) is exposed "
            "because it's transmitted or stored without adequate encryption."
        ),
        attacks=[
            AttackScenario(
                "SSL Stripping / Network Eavesdropping",
                "On a shared or hostile network, an attacker intercepts "
                "traffic sent over plain HTTP and reads or edits it, since "
                "nothing was ever encrypted.",
                "Serve the entire site over HTTPS, redirect all HTTP to "
                "HTTPS, and send a Strict-Transport-Security header so "
                "browsers refuse to fall back to plain HTTP.",
                Exploitability.LIKELY,
            ),
            AttackScenario(
                "Man-in-the-Middle via Certificate Spoofing",
                "If certificate validation is broken or ignored, an "
                "attacker positioned on the network path can present a "
                "fake certificate and quietly relay/alter traffic.",
                "Always validate TLS certificates in full (never disable "
                "verification) and keep certificates current.",
                Exploitability.LIKELY,
            ),
        ],
    ),
    OwaspCategory.INJECTION: CategoryInfo(
        color="#C0392B",
        icon="💉",
        summary=(
            "Untrusted input is interpreted as commands or code (SQL, HTML/"
            "JS, OS commands) instead of being treated as plain data."
        ),
        attacks=[
            AttackScenario(
                "Cross-Site Scripting (XSS)",
                "Without a strong Content-Security-Policy and output "
                "encoding, an attacker-supplied script embedded in a page "
                "runs in other users' browsers, letting it read cookies or "
                "act as that user.",
                "Set a strict Content-Security-Policy, encode all output "
                "by context, and use frameworks that auto-escape by default.",
                Exploitability.POSSIBLE,
            ),
            AttackScenario(
                "SQL Injection",
                "Untrusted input concatenated into a database query lets an "
                "attacker alter the query's meaning to read or modify data "
                "they shouldn't access.",
                "Use parameterized queries / prepared statements exclusively; "
                "never build SQL via string concatenation.",
                Exploitability.POSSIBLE,
            ),
        ],
    ),
    OwaspCategory.INSECURE_DESIGN: CategoryInfo(
        color="#B9770E",
        icon="🏗️",
        summary=(
            "A missing security control in the design itself - not a bug to "
            "patch, but a threat that was never modeled or planned for."
        ),
        attacks=[
            AttackScenario(
                "Business-Logic Abuse",
                "An attacker uses the application exactly as built, but in "
                "an unintended sequence or volume (e.g. no rate limit on "
                "password reset), because the design never considered abuse.",
                "Threat-model each flow (what happens if this step is "
                "skipped, repeated, or automated?) and add explicit limits.",
                Exploitability.HARDENING,
            ),
        ],
    ),
    OwaspCategory.SECURITY_MISCONFIGURATION: CategoryInfo(
        color="#E0A030",
        icon="⚙️",
        summary=(
            "Insecure default settings, unnecessary features left enabled, "
            "or overly detailed error messages exposed to the outside world."
        ),
        attacks=[
            AttackScenario(
                "Clickjacking",
                "Without X-Frame-Options / frame-ancestors, an attacker "
                "loads your site inside an invisible frame on their own "
                "page and tricks users into clicking real buttons underneath.",
                "Send 'X-Frame-Options: DENY' (or SAMEORIGIN) and a CSP "
                "'frame-ancestors' directive.",
                Exploitability.POSSIBLE,
            ),
            AttackScenario(
                "MIME-Sniffing Attack",
                "Without X-Content-Type-Options, some browsers try to guess "
                "a file's type, which can let an uploaded file be executed "
                "as script instead of treated as harmless data.",
                "Send 'X-Content-Type-Options: nosniff' on every response.",
                Exploitability.HARDENING,
            ),
            AttackScenario(
                "Reconnaissance via Verbose Errors / Banners",
                "Detailed error pages or server/version banners tell an "
                "attacker exactly what software and version to look up "
                "known vulnerabilities for.",
                "Show generic error pages to users, log details "
                "server-side only, and suppress version banners.",
                Exploitability.INFORMATIONAL,
            ),
            AttackScenario(
                "Directory Listing Enumeration",
                "An exposed directory listing lets an attacker see every "
                "file on a path, potentially finding backups, configs, or "
                "other files that were never meant to be public.",
                "Disable directory listing at the web server/framework "
                "level and remove unintended files from public paths.",
                Exploitability.POSSIBLE,
            ),
        ],
    ),
    OwaspCategory.VULNERABLE_COMPONENTS: CategoryInfo(
        color="#6C7A89",
        icon="📦",
        summary=(
            "Using libraries, frameworks, or server software with known, "
            "publicly documented vulnerabilities."
        ),
        attacks=[
            AttackScenario(
                "Known-CVE Exploitation",
                "Once an attacker fingerprints the exact software/version "
                "(often from a banner header), they check public "
                "vulnerability databases for a matching known exploit.",
                "Remove/obscure version banners, and keep all server "
                "software and dependencies patched on a regular cadence.",
                Exploitability.POSSIBLE,
            ),
        ],
    ),
    OwaspCategory.AUTH_FAILURES: CategoryInfo(
        color="#2E86C1",
        icon="🔐",
        summary=(
            "Weaknesses in how the app confirms identity or manages "
            "sessions after login."
        ),
        attacks=[
            AttackScenario(
                "Session Hijacking",
                "A session cookie missing the Secure or HttpOnly flag can "
                "be intercepted over an unencrypted link or read by an "
                "injected script, letting an attacker reuse it to "
                "impersonate the user.",
                "Set Secure, HttpOnly, and SameSite on every session "
                "cookie, and serve the whole session over HTTPS.",
                Exploitability.LIKELY,
            ),
            AttackScenario(
                "Cross-Site Request Forgery (CSRF)",
                "Without a CSRF token, a page on another site can silently "
                "submit a form to your app using the victim's already-"
                "logged-in session.",
                "Include a unique, unpredictable CSRF token in every "
                "state-changing form and validate it server-side.",
                Exploitability.POSSIBLE,
            ),
            AttackScenario(
                "Credential Interception",
                "A login form submitted over plain HTTP sends the "
                "username/password in the clear across the network.",
                "Serve every page that contains a login form - and the "
                "form's submission target - over HTTPS only.",
                Exploitability.LIKELY,
            ),
        ],
    ),
    OwaspCategory.INTEGRITY_FAILURES: CategoryInfo(
        color="#16A085",
        icon="🧬",
        summary=(
            "Code or data whose integrity isn't verified - e.g. auto-"
            "updates or CI/CD pipelines that trust an artifact without "
            "checking it wasn't tampered with."
        ),
        attacks=[
            AttackScenario(
                "Supply-Chain Tampering",
                "If a script, package, or update isn't integrity-checked, "
                "an attacker who compromises its source can have it served "
                "straight to end users.",
                "Verify subresource integrity (SRI) hashes for third-party "
                "scripts and sign/verify build artifacts in CI/CD.",
                Exploitability.HARDENING,
            ),
        ],
    ),
    OwaspCategory.LOGGING_FAILURES: CategoryInfo(
        color="#7F8C8D",
        icon="📝",
        summary=(
            "Insufficient logging and monitoring means breaches go "
            "undetected long enough for real damage to happen."
        ),
        attacks=[
            AttackScenario(
                "Undetected Persistence",
                "Without logging of authentication events and anomalies, "
                "an attacker who gets in once can keep operating unnoticed.",
                "Log authentication, access-control, and input-validation "
                "failures, and alert on repeated failures or anomalies.",
                Exploitability.INFORMATIONAL,
            ),
        ],
    ),
    OwaspCategory.SSRF: CategoryInfo(
        color="#AF7AC5",
        icon="🌐",
        summary=(
            "The server can be tricked into making requests to unintended "
            "destinations - including internal, normally unreachable systems."
        ),
        attacks=[
            AttackScenario(
                "Server-Side Request Forgery",
                "An attacker supplies a URL that the *server* fetches on "
                "their behalf, reaching internal services (like cloud "
                "metadata endpoints) that aren't exposed to the internet.",
                "Validate and allow-list any server-side outbound "
                "destinations; never fetch a raw, user-supplied URL.",
                Exploitability.HARDENING,
            ),
        ],
    ),
}


# ----------------------------------------------------------------------
# 2. Finding-level keyword rules (Reports automated assessment)
# ----------------------------------------------------------------------
# Each rule: substrings (matched case-insensitively against the finding's
# title) -> the attack scenario it maps to. First match wins. Falling
# through with no match still returns a sensible category-level default
# (see assess_finding below), so every finding gets *some* assessment.
_FINDING_RULES: list[tuple[tuple[str, ...], AttackScenario]] = [
    (
        ("x-frame-options",),
        CATEGORY_INFO[OwaspCategory.SECURITY_MISCONFIGURATION].attacks[0],
    ),
    (
        ("content-security-policy",),
        CATEGORY_INFO[OwaspCategory.INJECTION].attacks[0],
    ),
    (
        ("x-content-type-options",),
        CATEGORY_INFO[OwaspCategory.SECURITY_MISCONFIGURATION].attacks[1],
    ),
    (
        ("strict-transport-security",),
        CATEGORY_INFO[OwaspCategory.CRYPTOGRAPHIC_FAILURES].attacks[0],
    ),
    (
        ("plain http", "http → https", "http -> https", "certificate validation"),
        CATEGORY_INFO[OwaspCategory.CRYPTOGRAPHIC_FAILURES].attacks[0],
    ),
    (
        ("missing secure flag",),
        CATEGORY_INFO[OwaspCategory.AUTH_FAILURES].attacks[0],
    ),
    (
        ("missing httponly flag",),
        CATEGORY_INFO[OwaspCategory.AUTH_FAILURES].attacks[0],
    ),
    (
        ("missing samesite",),
        CATEGORY_INFO[OwaspCategory.AUTH_FAILURES].attacks[1],
    ),
    (
        ("csrf",),
        CATEGORY_INFO[OwaspCategory.AUTH_FAILURES].attacks[1],
    ),
    (
        ("password field served over http",),
        CATEGORY_INFO[OwaspCategory.AUTH_FAILURES].attacks[2],
    ),
    (
        ("discloses software details", "banner"),
        CATEGORY_INFO[OwaspCategory.VULNERABLE_COMPONENTS].attacks[0],
    ),
    (
        ("verbose error",),
        CATEGORY_INFO[OwaspCategory.SECURITY_MISCONFIGURATION].attacks[2],
    ),
    (
        ("directory listing",),
        CATEGORY_INFO[OwaspCategory.SECURITY_MISCONFIGURATION].attacks[3],
    ),
    (
        ("default session cookie name",),
        CATEGORY_INFO[OwaspCategory.VULNERABLE_COMPONENTS].attacks[0],
    ),
    (
        ("autocomplete guidance",),
        CATEGORY_INFO[OwaspCategory.AUTH_FAILURES].attacks[0],
    ),
]


def _category_fallback(owasp_category: OwaspCategory, risk_level: RiskLevel) -> AttackScenario:
    """Used when no keyword rule matches a finding's title: fall back to
    the first (most representative) attack scenario for its OWASP
    category, with exploitability nudged by the finding's own risk level."""
    info = CATEGORY_INFO.get(owasp_category)
    if info and info.attacks:
        base = info.attacks[0]
        exploitability = base.exploitability
        if risk_level == RiskLevel.HIGH and exploitability == Exploitability.HARDENING:
            exploitability = Exploitability.POSSIBLE
        return AttackScenario(base.attack_name, base.how_it_works, base.protection, exploitability)
    return AttackScenario(
        "General Hardening Gap",
        "This finding reflects a deviation from OWASP-recommended "
        "defensive configuration rather than one specific attack.",
        "Follow the recommendation attached to this finding.",
        Exploitability.INFORMATIONAL,
    )


def assess_finding(finding) -> dict:
    """
    Map one stored finding (an ORM-row-like object or a `Finding`
    dataclass - anything with title/owasp_category/risk_level) to an
    attack scenario + exploitability rating.

    Returns a plain dict so it's equally easy to use from Tkinter
    widgets, the PDF report builder, and CSV export.
    """
    title = (finding["title"] if hasattr(finding, "keys") else finding.title) or ""
    title_lower = title.lower()

    category_raw = finding["owasp_category"] if hasattr(finding, "keys") else finding.owasp_category.value
    risk_raw = finding["risk_level"] if hasattr(finding, "keys") else finding.risk_level.value

    try:
        owasp_category = OwaspCategory(category_raw)
    except ValueError:
        owasp_category = None
    try:
        risk_level = RiskLevel(risk_raw)
    except ValueError:
        risk_level = RiskLevel.LOW

    scenario = None
    for keywords, candidate in _FINDING_RULES:
        if any(kw in title_lower for kw in keywords):
            scenario = candidate
            break

    if scenario is None and owasp_category is not None:
        scenario = _category_fallback(owasp_category, risk_level)
    elif scenario is None:
        scenario = _category_fallback(OwaspCategory.SECURITY_MISCONFIGURATION, risk_level)

    return {
        "title": title,
        "owasp_category": category_raw,
        "risk_level": risk_raw,
        "attack_name": scenario.attack_name,
        "how_it_works": scenario.how_it_works,
        "protection": scenario.protection,
        "exploitability": scenario.exploitability,
        "color": EXPLOITABILITY_COLORS[scenario.exploitability],
    }


def assess_scan(findings: list) -> dict:
    """
    Run assess_finding() across every finding in a scan and return a
    summary suitable for the Reports page's "automated post-scan
    assessment": a sorted (most-to-least exploitable) list plus counts
    per exploitability tier.
    """
    assessed = [assess_finding(f) for f in findings]
    assessed.sort(key=lambda a: EXPLOITABILITY_ORDER[a["exploitability"]])

    counts = {level: 0 for level in Exploitability}
    for a in assessed:
        counts[a["exploitability"]] += 1

    return {
        "assessed_findings": assessed,
        "counts": {level.value: count for level, count in counts.items()},
        "likely_exploitable_count": counts[Exploitability.LIKELY],
    }
