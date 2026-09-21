"""Normalization / dedup / correlation — core OUR logic.

- normalize: severity already normalized in Finding; here we sort + strip empties.
- dedup: same fingerprint -> one finding, engines_seen merged, max cvss kept.
- correlate: link runtime findings to image findings (same package) so
  `scan <container>` shows the image->runtime chain instead of two lists.
"""
from __future__ import annotations

from sarbar.model import SEVERITY_ORDER, Finding


def dedup(findings: list[Finding]) -> list[Finding]:
    merged: dict[str, Finding] = {}
    for f in findings:
        key = f.fingerprint
        if key not in merged:
            merged[key] = f
            continue
        cur = merged[key]
        # merge engines
        for e in f.engines_seen:
            if e not in cur.engines_seen:
                cur.engines_seen.append(e)
        # keep worst severity / highest cvss
        if SEVERITY_ORDER.get(f.severity, 0) > SEVERITY_ORDER.get(cur.severity, 0):
            cur.severity = f.severity
        try:
            if float(f.cvss or 0) > float(cur.cvss or 0):
                cur.cvss = f.cvss
        except (TypeError, ValueError):
            pass
        if f.fixed_version and not cur.fixed_version:
            cur.fixed_version = f.fixed_version
        cur.references = list(dict.fromkeys([*cur.references, *f.references]))
    out = list(merged.values())
    out.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 0), f.cvss or 0.0), reverse=True)
    return out


def correlate(findings: list[Finding]) -> list[Finding]:
    """Annotate runtime findings that confirm an image vuln.

    If a runtime finding (category=runtime) names the same package as a
    vuln finding, append a note to its description. Pure annotation —
    no findings added or removed, so counts stay audit-friendly.
    """
    vuln_pkgs = {(f.package, f.installed_version) for f in findings if f.category == "vuln" and f.package}
    vuln_names = {f.package for f in findings if f.category == "vuln" and f.package}
    for f in findings:
        if f.category == "runtime" and f.package:
            if (f.package, f.installed_version) in vuln_pkgs:
                f.description += " [correlated: same package+version as image vuln]"
            elif f.package in vuln_names:
                f.description += " [correlated: package also vulnerable in image]"
    return findings


def normalize_all(findings: list[Finding]) -> list[Finding]:
    findings = [f for f in findings if f.check_id]
    findings = dedup(findings)
    findings = correlate(findings)
    return findings
