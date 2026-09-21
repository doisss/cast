"""Orchestrator: intelligent engine selection + run. THE diploma core.

auto mode:
  image      -> vuln engines (trivy/grype per profile) + dockle misconfig + cast-checks
  container  -> resolve image via `docker inspect`, scan image + runtime cast-checks
  dockerfile -> dockle (if present) + OUR dockerfile lint (always, offline-capable)
  fs         -> trivy fs/grype dir + OUR secret scan (always)

aggregator mode (--engine X): run exactly that engine, but normalization,
dedup, cast-checks (unless --no-cast-checks), risk score, policy and report
stay OURS.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess

from sarbar import policy as policy_mod
from sarbar.checks import check_dockerfile, check_fs_secrets, check_inspect
from sarbar.engines import ENGINES
from sarbar.engines.mock import MockEngine
from sarbar.model import Finding
from sarbar.normalize import normalize_all
from sarbar.policy import Policy
from sarbar.risk import apply_policy, score_findings
from sarbar.target import Target, TargetKind


def list_docker_ids() -> set:
    if shutil.which("docker") is None:
        return set()
    try:
        p = subprocess.run(["docker", "ps", "--format", "{{.ID}} {{.Names}}"],
                           capture_output=True, text=True, timeout=15)
        ids: set[str] = set()
        for line in (p.stdout or "").splitlines():
            for tok in line.split():
                ids.add(tok)
        return ids
    except Exception:
        return set()


def docker_inspect(container: str) -> dict | None:
    if shutil.which("docker") is None:
        return None
    try:
        p = subprocess.run(["docker", "inspect", container],
                           capture_output=True, text=True, timeout=30)
        if p.returncode != 0:
            return None
        data = json.loads(p.stdout or "[]")
        return data[0] if data else None
    except Exception:
        return None


def plan_scan(target: Target, pol: Policy, forced_engine: str | None = None) -> dict:
    """Explainable plan: which engines and why. Shown with --explain."""
    if forced_engine:
        engines = [forced_engine]
        why = f"aggregator mode: user forced --engine {forced_engine}"
    else:
        engines = policy_mod.engines_for(pol, target.kind.value)
        why = f"auto mode: profile '{pol.name}' selects {engines or ['(none — cast-checks only)']} for {target.kind.value}"
    checks: list[str] = []
    if pol.run_cast_checks:
        checks = {
            "image": ["image-labels"],
            "container": ["runtime-inspect"],
            "dockerfile": ["dockerfile-lint"],
            "fs": ["secret-scan", "dockerfile-lint(if present)"],
        }[target.kind.value]
    return {"engines": engines, "cast_checks": checks, "why": why,
            "profile": pol.name, "target": target.raw, "kind": target.kind.value}


def _run_engine(name: str, scan_ref: str, kind: str, offline: bool) -> tuple[list[Finding], bool]:
    """Returns (findings, used_fallback)."""
    eng = ENGINES.get(name)
    if offline or eng is None or not eng.is_available():
        return [], True
    try:
        return eng.run(scan_ref, kind), False
    except Exception:
        return [], True


def run_scan(target: Target, pol: Policy, forced_engine: str | None = None,
             offline: bool = False, use_mock_fallback: bool = True,
             no_cast_checks: bool = False) -> dict:
    plan = plan_scan(target, pol, forced_engine)
    findings: list[Finding] = []
    engines_used: list[str] = []
    fallback = False
    kind = target.kind.value
    scan_ref = target.raw

    image_ref = None
    inspect = None
    if target.kind == TargetKind.CONTAINER:
        inspect = docker_inspect(target.raw)
        if inspect:
            try:
                image_ref = inspect.get("Config", {}).get("Image")
            except Exception:
                image_ref = None
        if image_ref:
            scan_ref = image_ref

    for name in plan["engines"]:
        got, fb = _run_engine(name, scan_ref, "image" if target.kind == TargetKind.CONTAINER else kind, offline)
        fallback = fallback or fb
        if not fb:
            engines_used.append(name)
            findings.extend(got)

    # mock fallback keeps demo alive when no binaries/network (flagged offline)
    if (offline or (not engines_used and use_mock_fallback)) and forced_engine != "none":
        if target.kind in (TargetKind.IMAGE, TargetKind.CONTAINER, TargetKind.FS, TargetKind.DOCKERFILE):
            findings.extend(MockEngine().run(scan_ref, kind))
            engines_used.append("mock")
            fallback = True

    # OUR checks (always local, work offline)
    if pol.run_cast_checks and not no_cast_checks:
        engines_used.append("cast-checks")
        if target.kind == TargetKind.DOCKERFILE:
            findings.extend(check_dockerfile(target.raw, target.raw))
        elif target.kind == TargetKind.FS:
            findings.extend(check_fs_secrets(target.raw, target.raw))
            df = os.path.join(target.raw, "Dockerfile")
            if os.path.isfile(df):
                findings.extend(check_dockerfile(df, target.raw))
            elif os.path.isfile(os.path.join(target.raw, "dockerfile")):
                findings.extend(check_dockerfile(os.path.join(target.raw, "dockerfile"), target.raw))
        elif target.kind == TargetKind.CONTAINER and inspect:
            findings.extend(check_inspect(inspect, target.raw))
        if target.kind == TargetKind.IMAGE and os.path.isfile(str(target.raw)):
            pass  # archive: engines handle it

    findings = normalize_all(findings)
    risk = score_findings(findings)
    verdict, reasons = apply_policy(findings, risk, pol)
    return {
        "target": target.raw,
        "target_kind": kind,
        "image_ref": image_ref,
        "profile": pol.name,
        "plan": plan,
        "engines_used": engines_used,
        "findings": findings,
        "risk": {"score": risk.score, "level": risk.level,
                 "counts": risk.counts, "max_cvss": risk.max_cvss,
                 "reasons": risk.reasons},
        "verdict": verdict,
        "policy_reasons": reasons,
        "offline": bool(offline or fallback),
    }
