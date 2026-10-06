"""Normalization / dedup / correlation — core OUR logic.

- normalize: severity is normalized inside Finding; here we drop empty rows,
  dedup by fingerprint and correlate image findings with runtime findings.
- dedup: same fingerprint -> one finding, engines_seen merged, worst severity
  and highest CVSS kept.
- correlate: link runtime findings to vuln findings that name the same package,
  so `scan <container>` shows the image->runtime chain rather than two lists.
"""
from __future__ import annotations

from sarbar.model import SEVERITY_ORDER, Finding


def dedup(findings: list[Finding]) -> list[Finding]:
    merged: dict[str, Finding] = {}
    for f in findings:
        key = f.fingerprint
        cur = merged.get(key)
        if cur is None:
            merged[key] = f
            continue
        for e in f.engines_seen:
            if e not in cur.engines_seen:
                cur.engines_seen.append(e)
        if SEVERITY_ORDER.get(f.severity, 0) > SEVERITY_ORDER.get(cur.severity, 0):
            cur.severity = f.severity
            cur.title = cur.title or f.title
        try:
            if float(f.cvss or 0) > float(cur.cvss or 0):
                cur.cvss = f.cvss
        except (TypeError, ValueError):
            pass
        if f.fixed_version and not cur.fixed_version:
            cur.fixed_version = f.fixed_version
        if f.description and not cur.description:
            cur.description = f.description
        for loc in f.locations:
            cur.add_location(loc)
        cur.references = list(dict.fromkeys([*cur.references, *f.references]))
    out = list(merged.values())
    out.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 0), f.cvss or 0.0),
             reverse=True)
    return out


def correlate(findings: list[Finding]) -> list[Finding]:
    """Annotate runtime findings that confirm a package vulnerability.

    Pure annotation: no findings added or removed, so counts stay audit-friendly.
    Matches on package name, or — when the runtime finding carries no package
    (Falco alerts do not) — on a package named in the finding text, which is how
    Falco's rendered alert lines mention the executable involved.
    """
    vuln_pkgs = {(f.package, f.installed_version)
                 for f in findings if f.category == "vuln" and f.package}
    vuln_names = {f.package for f in findings if f.category == "vuln" and f.package}
    if not vuln_names:
        return findings
    for f in findings:
        if f.category != "runtime":
            continue
        if f.package:
            if (f.package, f.installed_version) in vuln_pkgs:
                f.description += " [correlated: same package+version as image vuln]"
            elif f.package in vuln_names:
                f.description += " [correlated: package also vulnerable in image]"
        else:
            hit = next((p for p in vuln_names if p and p in f.title), None)
            if hit:
                f.description += f" [correlated: mentions vulnerable package {hit}]"
    return findings


def normalize_all(findings: list[Finding]) -> list[Finding]:
    findings = [f for f in findings if f.check_id]
    findings = dedup(findings)
    findings = correlate(findings)
    return findings