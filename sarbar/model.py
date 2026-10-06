"""Unified finding model. This is OUR layer — no scanner exposes this directly."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")
SEVERITY_ORDER = {s: i for i, s in enumerate(["UNKNOWN", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])}

# Alias table for every severity dialect the adapters can hand us.
#
# Sources that motivated each entry:
#   trivy  : UNKNOWN/LOW/MEDIUM/HIGH/CRITICAL            (already canonical)
#   grype  : Negligible/Low/Medium/High/Critical         (Negligible -> INFO)
#   dockle : INFO/WARN/ERROR                            (ERROR -> HIGH, WARN -> MEDIUM)
#   falco  : Emergency/Alert/Critical/Error/Warning/Notice/Informational
#
# Falco is the reason this table is exhaustive: before it was, Emergency, Alert
# and Notice all collapsed to UNKNOWN, and UNKNOWN carries zero risk weight, so
# a third of Falco's alerts silently contributed nothing to the score.
SEVERITY_ALIASES = {
    # generic shorthands
    "CRIT": "CRITICAL",
    "SEVERE": "CRITICAL",
    "IMPORTANT": "HIGH",
    "MODERATE": "MEDIUM",
    "TRIVIAL": "LOW",
    # trivy / dockle
    "ERROR": "HIGH",
    "WARN": "MEDIUM",
    "WARNING": "MEDIUM",
    "NEGLIGIBLE": "INFO",
    "NONE": "INFO",
    # falco priorities
    "EMERGENCY": "CRITICAL",
    "ALERT": "CRITICAL",
    "NOTICE": "LOW",
    "INFORMATIONAL": "INFO",
    "DEBUG": "INFO",
}


def normalize_severity(raw: str) -> str:
    s = (raw or "UNKNOWN").strip().upper()
    s = SEVERITY_ALIASES.get(s, s)
    return s if s in SEVERITIES else "UNKNOWN"


@dataclass
class Finding:
    """Single normalized finding from any engine or cast-check."""

    check_id: str          # e.g. CVE-2023-1234, DOCKLE-DKL-DI-001, CAST-SECRET-001
    title: str
    severity: str
    target: str = ""
    package: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    cvss: float = 0.0
    description: str = ""
    engine: str = ""       # trivy | grype | dockle | falco
    category: str = ""     # vuln | misconfig | secret | runtime | ...
    references: list = field(default_factory=list)
    engines_seen: list = field(default_factory=list)
    # One rule can fire in many places (a secret pattern in 40 files, a Dockerfile
    # rule in several steps). `locations` keeps every hit so the report can state
    # "N occurrences" instead of collapsing to one arbitrary file.
    locations: list = field(default_factory=list)

    def __post_init__(self):
        self.severity = normalize_severity(self.severity)
        if not self.engines_seen and self.engine:
            self.engines_seen = [self.engine]

    @property
    def fingerprint(self) -> str:
        """Stable dedup key: same flaw in same component of same target.

        `target` is part of the key so that aggregating findings from several
        targets in one run can never merge two unrelated findings.
        """
        base = f"{self.check_id}|{self.package}|{self.installed_version}|{self.category}|{self.target}"
        return hashlib.sha256(base.encode()).hexdigest()[:16]

    @property
    def occurrences(self) -> int:
        """How many distinct places this finding was observed."""
        return max(1, len(self.locations))

    def add_location(self, where: str) -> None:
        if where and where not in self.locations:
            self.locations.append(where)

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity,
            "target": self.target,
            "package": self.package,
            "installed_version": self.installed_version,
            "fixed_version": self.fixed_version,
            "cvss": self.cvss,
            "description": self.description,
            "engine": self.engine,
            "engines_seen": self.engines_seen,
            "category": self.category,
            "references": self.references,
            "locations": self.locations,
            "occurrences": self.occurrences,
            "fingerprint": self.fingerprint,
        }