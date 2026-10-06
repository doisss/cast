"""Composite risk score — OUR methodology, the part to defend at the viva.

score = min(100, severity_points + cvss_lift + category_penalty)

severity_points: CRITICAL=25, HIGH=10, MEDIUM=3, LOW=1, INFO/UNKNOWN=0
  counted with diminishing returns: the n-th finding of a severity counts
  w/sqrt(n) — one critical is bad, twenty criticals is not 20x worse.
  Each severity class is additionally capped so no single class can saturate
  the score on its own.
cvss_lift: max_cvss * 1.5 capped at 15
category_penalty: +5 if any secret leaked, +5 if any runtime misconfiguration.

Known limitation (documented, not hidden)
-----------------------------------------
The per-class caps make the score saturate quickly: 5 CRITICALs already reach
the 60-point cap and 10 HIGHs reach the 40-point cap. Between roughly 5 and 200
findings of one class the score stops discriminating. This is deliberate — the
score is meant to answer "how bad is this target", not "how many findings are
there" — but it means counts, not the score, carry the detail in that range.
`reasons` always lists the per-class contribution so the number is explainable.
"""
from __future__ import annotations

import math
from dataclasses import dataclass


WEIGHTS = {"CRITICAL": 25.0, "HIGH": 10.0, "MEDIUM": 3.0, "LOW": 1.0,
           "INFO": 0.0, "UNKNOWN": 0.0}

CLASS_CAPS = {"CRITICAL": 60.0, "HIGH": 40.0, "MEDIUM": 25.0, "LOW": 10.0}

LEVELS = ((80.0, "critical"), (60.0, "high"), (30.0, "medium"), (5.0, "low"))


@dataclass
class RiskScore:
    score: float
    level: str
    counts: dict
    max_cvss: float
    reasons: list


def level_of(score: float) -> str:
    for threshold, name in LEVELS:
        if score >= threshold:
            return name
    return "ok"


def score_findings(findings: list) -> RiskScore:
    counts: dict[str, int] = {}
    per_sev: dict[str, list] = {}
    max_cvss = 0.0
    cats = set()
    secrets = 0
    for f in findings:
        sev = getattr(f, "severity", "UNKNOWN")
        counts[sev] = counts.get(sev, 0) + 1
        per_sev.setdefault(sev, []).append(f)
        try:
            max_cvss = max(max_cvss, float(getattr(f, "cvss", 0.0) or 0.0))
        except (TypeError, ValueError):
            pass
        cat = getattr(f, "category", "")
        cats.add(cat)
        if cat == "secret":
            secrets += 1

    points = 0.0
    reasons: list[str] = []
    for sev in sorted(per_sev, key=lambda s: -WEIGHTS.get(s, 0.0)):
        items = per_sev[sev]
        w = WEIGHTS.get(sev, 0.0)
        if w <= 0:
            continue
        sub = sum(w / math.sqrt(i + 1) for i in range(len(items)))
        cap = CLASS_CAPS.get(sev)
        if cap is not None and sub > cap:
            sub = cap
            reasons.append(f"{sev}:{len(items)}x -> +{sub:.1f} (class cap)")
        else:
            reasons.append(f"{sev}:{len(items)}x -> +{sub:.1f}")
        points += sub

    cvss_lift = min(15.0, max_cvss * 1.5)
    if cvss_lift > 0:
        reasons.append(f"max CVSS {max_cvss:.1f} -> +{cvss_lift:.1f}")
    points += cvss_lift

    penalty = 0.0
    if "secret" in cats:
        penalty += 5.0
        reasons.append(f"leaked secret ({secrets}) -> +5.0")
    if "runtime" in cats:
        penalty += 5.0
        reasons.append("runtime misconfig -> +5.0")
    points += penalty

    score = round(min(100.0, points), 1)
    return RiskScore(score=score, level=level_of(score), counts=counts,
                     max_cvss=max_cvss, reasons=reasons)


def _threshold(policy, attr: str, default):
    value = getattr(policy, attr, default)
    return default if value is None else value


def apply_policy(findings: list, risk: RiskScore, policy) -> tuple[str, list]:
    """Return (verdict, reasons). verdict in {pass, fail}."""
    counts = risk.counts
    crit = counts.get("CRITICAL", 0)
    high = counts.get("HIGH", 0)
    secrets = sum(1 for f in findings if getattr(f, "category", "") == "secret")

    reasons: list[str] = []
    verdict = "pass"

    fc = _threshold(policy, "fail_on_critical", 1)
    fh = _threshold(policy, "fail_on_high", -1)
    fs = _threshold(policy, "fail_on_secret", 1)
    sc = _threshold(policy, "fail_score", 80.0)

    def check(value, threshold, label, unit="findings"):
        nonlocal verdict
        if threshold is None or threshold < 0:
            return
        if value >= threshold:
            verdict = "fail"
            reasons.append(f"{label} {value} >= threshold {threshold} {unit}")

    check(crit, fc, "critical findings")
    check(high, fh, "high findings")
    check(secrets, fs, "leaked secret findings")
    if sc is not None and sc >= 0 and risk.score >= sc:
        verdict = "fail"
        reasons.append(f"risk score {risk.score} >= threshold {sc}")

    if verdict == "pass":
        reasons.append("within policy thresholds")
    return verdict, reasons