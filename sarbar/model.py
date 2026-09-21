"""Unified finding model. This is OUR layer — no scanner exposes this directly."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")
SEVERITY_ORDER = {s: i for i, s in enumerate(["UNKNOWN", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])}


def normalize_severity(raw: str) -> str:
    s = (raw or "UNKNOWN").strip().upper()
    aliases = {
        "CRIT": "CRITICAL", "ERROR": "HIGH", "WARN": "MEDIUM",
        "WARNING": "MEDIUM", "MODERATE": "MEDIUM", "NEGLIGIBLE": "INFO",
        "NONE": "INFO",
    }
    s = aliases.get(s, s)
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
    engine: str = ""       # trivy | grype | dockle | cast-checks | ...
    category: str = ""     # vuln | misconfig | secret | runtime | ...
    references: list = field(default_factory=list)
    engines_seen: list = field(default_factory=list)

    def __post_init__(self):
        self.severity = normalize_severity(self.severity)
        if not self.engines_seen and self.engine:
            self.engines_seen = [self.engine]

    @property
    def fingerprint(self) -> str:
        """Stable dedup key: same flaw in same component = same finding."""
        base = f"{self.check_id}|{self.package}|{self.installed_version}|{self.category}"
        return hashlib.sha256(base.encode()).hexdigest()[:16]

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
            "fingerprint": self.fingerprint,
        }


@dataclass
class ScanResult:
    target: str
    target_kind: str
    profile: str
    engines_used: list
    findings: list  # list[Finding]
    risk: dict = field(default_factory=dict)
    verdict: str = "pass"
    offline: bool = False
