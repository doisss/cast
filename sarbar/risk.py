"""Composite risk score — OUR methodology, the part to defend at the viva.

score = min(100, severity_points + cvss_lift + category_penalty)

severity_points: CRITICAL=25, HIGH=10, MEDIUM=3, LOW=1, INFO/UNKNOWN=0
  (counted with diminishing returns: n-th finding of same severity
   counts 1/sqrt(n) — one critical is bad, twenty criticals is not 20x worse)
cvss_lift: max_cvss * 1.5 capped at 15
category_penalty: +5 if any secret leaked, +5 if privileged runtime issue.
"""
from __future__ import annotations

import math
from dataclasses import dataclass


WEIGHTS = {"CRITICAL": 25.0, "HIGH": 10.0, "MEDIUM": 3.0, "LOW": 1.0, "INFO": 0.0, "UNKNOWN": 0.0}


@dataclass
class RiskScore:
    score: float
    level: str
    counts: dict
    max_cvss: float
    reasons: list


def level_of(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    if score >= 5:
        return "low"
    return "ok"


def score_findings(findings: list) -> RiskScore:
    counts: dict[str, int] = {}
    per_sev: dict[str, list] = {}
    max_cvss = 0.0
    cats = set()
    for f in findings:
        sev = getattr(f, "severity", "UNKNOWN")
        counts[sev] = counts.get(sev, 0) + 1
        per_sev.setdefault(sev, []).append(f)
        try:
            max_cvss = max(max_cvss, float(getattr(f, "cvss", 0.0) or 0.0))
        except (TypeError, ValueError):
            pass
        cats.add(getattr(f, "category", ""))

    points = 0.0
    reasons: list[str] = []
    for sev, items in per_sev.items():
        w = WEIGHTS.get(sev, 0.0)
        if w <= 0:
            continue
        # diminishing returns: sum_{i=1..n} w/sqrt(i)
        sub = sum(w / math.sqrt(i + 1) for i in range(len(items)))
        # cap contribution per severity so one class can't saturate alone
        sub = min(sub, {"CRITICAL": 60.0, "HIGH": 40.0, "MEDIUM": 25.0, "LOW": 10.0}.get(sev, sub))
        points += sub
        reasons.append(f"{sev}:{len(items)}x -> +{sub:.1f}")

    cvss_lift = min(15.0, max_cvss * 1.5)
    if cvss_lift > 0:
        reasons.append(f"max CVSS {max_cvss:.1f} -> +{cvss_lift:.1f}")
    points += cvss_lift

    penalty = 0.0
    if "secret" in cats:
        penalty += 5.0
        reasons.append("leaked secret -> +5.0")
    if "runtime" in cats:
        penalty += 5.0
        reasons.append("runtime misconfig -> +5.0")
    points += penalty

    score = round(min(100.0, points), 1)
    return RiskScore(score=score, level=level_of(score), counts=counts,
                     max_cvss=max_cvss, reasons=reasons)


def apply_policy(findings: list, risk: RiskScore, policy) -> tuple[str, list]:
    """Returns (verdict, reasons). verdict in {pass, fail}."""
    counts = risk.counts
    crit = counts.get("CRITICAL", 0)
    high = counts.get("HIGH", 0)
    reasons: list[str] = []
    verdict = "pass"
    fc = getattr(policy, "fail_on_critical", 1)
    fh = getattr(policy, "fail_on_high", -1)
    fs = getattr(policy, "fail_score", 80.0)
    if fc is not None and fc >= 0 and crit >= fc:
        verdict = "fail"
        reasons.append(f"critical findings {crit} >= threshold {fc}")
    if fh is not None and fh >= 0 and high >= fh:
        verdict = "fail"
        reasons.append(f"high findings {high} >= threshold {fh}")
    if fs is not None and fs >= 0 and risk.score >= fs:
        verdict = "fail"
        reasons.append(f"risk score {risk.score} >= threshold {fs}")
    if verdict == "pass":
        reasons.append("within policy thresholds")
    return verdict, reasons
