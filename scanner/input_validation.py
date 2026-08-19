"""
scanner/input_validation.py
------------------------------
Passively reviews HTML forms for basic secure-form indicators. This
module never submits, fills, or interacts with forms - it only parses
the HTML already returned by a normal GET request.

Security concept demonstrated:
    Touches OWASP A04:2021 (Insecure Design) and A07:2021 (Identification
    and Authentication Failures). A form isn't "vulnerable" just because
    of static HTML attributes, but missing basics (password over HTTP,
    no visible CSRF token, autocomplete left on for sensitive fields) are
    useful signals for a developer doing self-review - the same way a
    linter flags code smells without proving a bug exists.
"""

from __future__ import annotations

from bs4 import BeautifulSoup

from scanner.models import Finding, OwaspCategory, RiskLevel


def check_forms(html: str, page_url: str) -> list[Finding]:
    """
    Parse forms in the given HTML and flag basic insecure patterns.

    Args:
        html: Raw HTML body of an already-fetched page.
        page_url: URL the HTML was fetched from (for HTTPS context).

    Returns:
        List of Finding objects.
    """
    findings: list[Finding] = []
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")
    page_is_https = page_url.startswith("https")

    for idx, form in enumerate(forms, start=1):
        password_fields = form.find_all("input", {"type": "password"})
        if not password_fields:
            continue  # only forms with a password field are in scope here

        form_label = f"Form #{idx}" + (f" (action='{form.get('action')}')" if form.get("action") else "")

        if not page_is_https:
            findings.append(
                Finding(
                    owasp_category=OwaspCategory.AUTH_FAILURES,
                    title=f"Password field served over HTTP - {form_label}",
                    description=(
                        f"{form_label} contains a password input but the page "
                        "was not loaded over HTTPS."
                    ),
                    why_it_matters=(
                        "Credentials typed into this form would be transmitted "
                        "in plaintext over the network."
                    ),
                    potential_impact="Usernames/passwords could be intercepted in transit.",
                    recommendation="Serve any page containing a login/password form exclusively over HTTPS.",
                    risk_level=RiskLevel.HIGH,
                    evidence=form_label,
                )
            )

        for pw_field in password_fields:
            autocomplete = (pw_field.get("autocomplete") or "").lower()
            if autocomplete not in ("off", "new-password", "current-password"):
                findings.append(
                    Finding(
                        owasp_category=OwaspCategory.INSECURE_DESIGN,
                        title=f"Password field missing explicit autocomplete guidance - {form_label}",
                        description=(
                            f"A password field in {form_label} has no explicit "
                            "'autocomplete' attribute (e.g. 'current-password' or "
                            "'new-password')."
                        ),
                        why_it_matters=(
                            "Explicit autocomplete hints help password managers "
                            "behave correctly and can reduce credential exposure "
                            "on shared devices when intentionally disabled."
                        ),
                        potential_impact="Minor - mainly affects credential handling on shared/public devices.",
                        recommendation=(
                            "Add autocomplete='current-password' (login forms) or "
                            "'new-password' (signup/reset forms) as appropriate."
                        ),
                        risk_level=RiskLevel.LOW,
                        evidence=f"{form_label}, password field autocomplete='{autocomplete or 'unset'}'",
                    )
                )

        csrf_like_field = form.find(
            "input",
            attrs={"type": "hidden", "name": lambda n: bool(n) and "csrf" in n.lower()},
        )
        if not csrf_like_field and (form.get("method") or "get").lower() == "post":
            findings.append(
                Finding(
                    owasp_category=OwaspCategory.INSECURE_DESIGN,
                    title=f"No visible CSRF token field - {form_label}",
                    description=(
                        f"{form_label} submits via POST but no hidden field with "
                        "a CSRF-like name was found in the static HTML."
                    ),
                    why_it_matters=(
                        "This is a heuristic, static-HTML check only - CSRF "
                        "protection may still be implemented via cookies/headers "
                        "not visible in the form markup. It's a prompt to verify, "
                        "not proof of a missing control."
                    ),
                    potential_impact="If genuinely absent, the form could be vulnerable to cross-site request forgery.",
                    recommendation=(
                        "Confirm the framework's CSRF protection is active for this "
                        "form (e.g. synchronizer token, double-submit cookie, or "
                        "SameSite cookies) and visible in a code review."
                    ),
                    risk_level=RiskLevel.LOW,
                    evidence=f"{form_label}, method=POST, no hidden *csrf* field detected in HTML.",
                )
            )

    return findings
