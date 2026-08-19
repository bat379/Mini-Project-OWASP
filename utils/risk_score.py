"""
utils/risk_score.py
---------------------
Converts a list of findings into a single 0-100 security score.

Security concept demonstrated:
    A simple, transparent, weighted-deduction model. High findings cost
    more than Medium, which cost more than Low - and the score is
    floored at 0 so a very insecure target doesn't produce a confusing
    negative number. Being transparent about the formula (rather than a
    black-box ML score) is deliberate: in an educational tool, the user
    should be able to see exactly *why* their score is what it is.
"""

from __future__ import annotations

from scanner.models import Finding, RiskLevel

_DEDUCTIONS = {
    RiskLevel.HIGH: 15,
    RiskLevel.MEDIUM: 7,
    RiskLevel.LOW: 3,
}


def calculate_security_score(findings: list[Finding]) -> int:
    """
    Calculate an overall security score out of 100.

    Args:
        findings: All findings from a completed scan.

    Returns:
        Integer score between 0 and 100 (100 = no findings at all).
    """
    score = 100
    for finding in findings:
        score -= _DEDUCTIONS.get(finding.risk_level, 0)
    return max(0, min(100, score))
