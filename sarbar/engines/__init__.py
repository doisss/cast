"""Engine adapters. Each wraps an EXISTING scanner binary (Trivy/Grype/Dockle).

Contract: run(target) -> list[Finding] (already normalized).
If the binary is missing or --offline is set, the engine reports
unavailable and the orchestrator falls back to mock demo data /
cast-checks only — the run is then flagged offline=True.
"""
from __future__ import annotations

import json
import shutil
import subprocess

from sarbar.model import Finding, normalize_severity


class Engine:
    name = "base"

    def is_available(self) -> bool:
        return False

    def run(self, target: str, kind: str) -> list[Finding]:
        raise NotImplementedError


def _run_cmd(cmd: list[str], timeout: int = 300) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return 127, ""
    except subprocess.TimeoutExpired:
        return 124, ""


def _cvss_of(obj: dict) -> float:
    for key in ("CVSS", "cvss", "metrics"):
        v = obj.get(key)
        if isinstance(v, dict):
            for sub in ("V3Score", "v3Score", "V2Score", "score", "baseScore"):
                try:
                    if sub in v and float(v[sub]) > 0:
                        return float(v[sub])
                except (TypeError, ValueError):
                    pass
            # nvd-style nested
            for nested in v.values():
                if isinstance(nested, dict):
                    for sub in ("V3Score", "V2Score", "baseScore", "score"):
                        try:
                            if sub in nested and float(nested[sub]) > 0:
                                return float(nested[sub])
                        except (TypeError, ValueError):
                            pass
    for key in ("cvssScore", "score", "baseScore", "V3Score"):
        try:
            if key in obj and float(obj[key]) > 0:
                return float(obj[key])
        except (TypeError, ValueError):
            pass
    return 0.0


class TrivyEngine(Engine):
    name = "trivy"

    def is_available(self) -> bool:
        return shutil.which("trivy") is not None

    def run(self, target: str, kind: str) -> list[Finding]:
        if kind in ("image",):
            cmd = ["trivy", "image", "--quiet", "--format", "json", "--scanners", "vuln,misconfig,secret", target]
        elif kind in ("fs",):
            cmd = ["trivy", "fs", "--quiet", "--format", "json", "--scanners", "vuln,misconfig,secret", target]
        elif kind in ("dockerfile",):
            cmd = ["trivy", "config", "--quiet", "--format", "json", target]
        else:  # container -> resolve image via docker inspect outside; scan as image
            cmd = ["trivy", "image", "--quiet", "--format", "json", target]
        code, out = _run_cmd(cmd)
        start = out.find("{")
        if start < 0:
            return []
        try:
            data = json.loads(out[start:])
        except json.JSONDecodeError:
            return []
        return self.parse(data, target)

    def parse(self, data: dict, target: str) -> list[Finding]:
        out: list[Finding] = []
        for res in data.get("Results", []) or []:
            for v in res.get("Vulnerabilities", []) or []:
                out.append(Finding(
                    check_id=v.get("VulnerabilityID", "UNKNOWN"),
                    title=v.get("Title", v.get("VulnerabilityID", "")),
                    severity=normalize_severity(v.get("Severity", "UNKNOWN")),
                    target=target,
                    package=v.get("PkgName", ""),
                    installed_version=v.get("InstalledVersion", ""),
                    fixed_version=v.get("FixedVersion", ""),
                    cvss=_cvss_of(v),
                    description=(v.get("Description", "") or "")[:500],
                    engine="trivy",
                    category="vuln",
                    references=[v.get("PrimaryURL", "")] if v.get("PrimaryURL") else [],
                ))
            for m in res.get("Misconfigurations", []) or []:
                out.append(Finding(
                    check_id=m.get("ID", "MISCONFIG"),
                    title=m.get("Title", m.get("ID", "")),
                    severity=normalize_severity(m.get("Severity", "MEDIUM")),
                    target=target,
                    description=(m.get("Description", "") or "")[:500],
                    engine="trivy", category="misconfig",
                    references=[m.get("PrimaryURL", "")] if m.get("PrimaryURL") else [],
                ))
            for s in res.get("Secrets", []) or []:
                out.append(Finding(
                    check_id=s.get("RuleID", "SECRET"),
                    title=s.get("Title", "Embedded secret"),
                    severity="HIGH", target=target,
                    description=f"Secret in {s.get('Target', '')}",
                    engine="trivy", category="secret",
                ))
        return out


class GrypeEngine(Engine):
    name = "grype"

    def is_available(self) -> bool:
        return shutil.which("grype") is not None

    def run(self, target: str, kind: str) -> list[Finding]:
        if kind in ("dockerfile",):
            return []
        cmd = ["grype", "-o", "json", target]
        if kind == "fs":
            cmd = ["grype", "-o", "json", f"dir:{target}"]
        code, out = _run_cmd(cmd)
        start = out.find("{")
        if start < 0:
            return []
        try:
            data = json.loads(out[start:])
        except json.JSONDecodeError:
            return []
        return self.parse(data, target)

    def parse(self, data: dict, target: str) -> list[Finding]:
        out: list[Finding] = []
        for m in data.get("matches", []) or []:
            vuln = m.get("vulnerability", {}) or {}
            art = m.get("artifact", {}) or {}
            out.append(Finding(
                check_id=vuln.get("id", "UNKNOWN"),
                title=vuln.get("description", vuln.get("id", ""))[:200],
                severity=normalize_severity(vuln.get("severity", "UNKNOWN")),
                target=target,
                package=art.get("name", ""),
                installed_version=art.get("version", ""),
                fixed_version=(vuln.get("fix", {}) or {}).get("versions", [""])[0]
                if isinstance((vuln.get("fix", {}) or {}).get("versions"), list) and
                (vuln.get("fix", {}) or {}).get("versions") else "",
                cvss=_cvss_of(vuln),
                description=(vuln.get("description", "") or "")[:500],
                engine="grype", category="vuln",
                references=vuln.get("urls", []) or [],
            ))
        return out


class DockleEngine(Engine):
    name = "dockle"

    def is_available(self) -> bool:
        return shutil.which("dockle") is not None

    def run(self, target: str, kind: str) -> list[Finding]:
        if kind not in ("image", "dockerfile"):
            return []
        cmd = ["dockle", "-f", "json", target]
        code, out = _run_cmd(cmd)
        start = out.find("{")
        if start < 0:
            return []
        try:
            data = json.loads(out[start:])
        except json.JSONDecodeError:
            return []
        return self.parse(data, target)

    def parse(self, data: dict, target: str) -> list[Finding]:
        out: list[Finding] = []
        for s in data.get("summary", []) if isinstance(data.get("summary"), list) else []:
            pass
        details = data.get("details", []) or data.get("assessments", []) or []
        for d in details:
            code_ = d.get("code", "DOCKLE")
            out.append(Finding(
                check_id=str(code_),
                title=d.get("title", str(code_)),
                severity=normalize_severity(d.get("level", "MEDIUM")),
                target=target, engine="dockle", category="misconfig",
                description=(d.get("desc", "") or "")[:500],
            ))
        return out


ENGINES: dict[str, Engine] = {
    "trivy": TrivyEngine(),
    "grype": GrypeEngine(),
    "dockle": DockleEngine(),
}


def get_engine(name: str) -> Engine | None:
    return ENGINES.get(name)
