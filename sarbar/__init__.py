"""SARBAR — Security Analysis and Reporting: Barely Armored Resources.

Name origin: Old Norse 'sár' (wound/vulnerability) + 'barr' (bare/exposed)
→ 'sarbar' = 'exposed vulnerability'

CAST — Container Automated Security Testing
Orchestrator + policy + report over existing scanners (trivy, falco, grype, dockle).

The version is read from the installed package metadata rather than hard-coded.
Two copies of the number existed and had already drifted: the wheel said one
thing and `sarbar -v` another, so a bug report could not be matched to a release.
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

def _detect_version() -> str:
    try:
        from importlib.metadata import version as _v
        return _v("sarbar")
    except Exception:
        # Running from a source checkout without an install.
        import pathlib
        here = pathlib.Path(__file__).resolve().parent.parent
        for candidate in (here / "pyproject.toml", here / ".." / "pyproject.toml"):
            try:
                for line in candidate.read_text().splitlines():
                    if line.startswith("version ="):
                        return line.split("=", 1)[1].strip().strip('"\'')
            except OSError:
                continue
        return "0.0.0+unknown"


__version__ = _detect_version()