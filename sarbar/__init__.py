"""SARBAR — Security Analysis and Reporting: Barely Armored Resources.

Name origin: Old Norse 'sár' (wound/vulnerability) + 'barr' (bare/exposed)
→ 'sarbar' = 'exposed vulnerability'

CAST — Container Automated Security Testing
Orchestrator + policy + report over existing scanners (trivy, falco, grype, dockle).

See SPEC.md for the specification, the invariants this code must uphold, and the
changelog.
"""
from sarbar.model import Finding, normalize_severity
from sarbar.normalize import correlate, dedup, normalize_all
from sarbar.orchestrator import TargetError, plan_scan, run_scan, validate_target
from sarbar.policy import BUILTIN_PROFILES, Policy, load_profile
from sarbar.risk import RiskScore, apply_policy, score_findings
from sarbar.target import Target, TargetKind, detect_target

__all__ = [
    "Finding", "normalize_severity",
    "Target", "TargetKind", "detect_target",
    "plan_scan", "run_scan", "validate_target", "TargetError",
    "dedup", "correlate", "normalize_all",
    "RiskScore", "score_findings", "apply_policy",
    "Policy", "BUILTIN_PROFILES", "load_profile",
]

__version__ = "0.4.1"