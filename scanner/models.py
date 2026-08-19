"""
scanner/models.py
------------------
Shared data structures used across all scanner check modules.

Security concept demonstrated:
    Every check module (headers, cookies, configuration, input_validation,
    authentication) returns a list of `Finding` objects with the *same*
    shape. This consistency is what makes risk scoring, DB storage, and
    PDF reporting possible without special-casing each check type. It
    also makes each finding self-documenting: a user should never see a
    raw "missing header" flag without also seeing why it matters and how
    to fix it - that's the difference between a scanner and a teaching
    tool.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class RiskLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class OwaspCategory(str, Enum):
    BROKEN_ACCESS_CONTROL = "A01:2021 - Broken Access Control"
    CRYPTOGRAPHIC_FAILURES = "A02:2021 - Cryptographic Failures"
    INJECTION = "A03:2021 - Injection"
    INSECURE_DESIGN = "A04:2021 - Insecure Design"
    SECURITY_MISCONFIGURATION = "A05:2021 - Security Misconfiguration"
    VULNERABLE_COMPONENTS = "A06:2021 - Vulnerable and Outdated Components"
    AUTH_FAILURES = "A07:2021 - Identification and Authentication Failures"
    INTEGRITY_FAILURES = "A08:2021 - Software and Data Integrity Failures"
    LOGGING_FAILURES = "A09:2021 - Security Logging and Monitoring Failures"
    SSRF = "A10:2021 - Server-Side Request Forgery"


@dataclass
class Finding:
    """A single, self-contained security observation."""

    owasp_category: OwaspCategory
    title: str
    description: str
    why_it_matters: str
    potential_impact: str
    recommendation: str
    risk_level: RiskLevel
    evidence: str = ""  # short, non-sensitive technical detail (e.g. header value seen)

    def to_dict(self) -> dict:
        return {
            "owasp_category": self.owasp_category.value,
            "title": self.title,
            "description": self.description,
            "why_it_matters": self.why_it_matters,
            "potential_impact": self.potential_impact,
            "recommendation": self.recommendation,
            "risk_level": self.risk_level.value,
            "evidence": self.evidence,
        }


@dataclass
class ScanResult:
    """Aggregate result of running all checks against a target."""

    target_url: str
    findings: list[Finding] = field(default_factory=list)
    security_score: int = 100
    errors: list[str] = field(default_factory=list)  # non-fatal check failures

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.risk_level == RiskLevel.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.risk_level == RiskLevel.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.risk_level == RiskLevel.LOW)
