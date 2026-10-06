"""Orchestrator: scanner selection, execution, and honest degradation.

auto mode (scanners chosen by the profile):
  image      -> vulnerability scanners (trivy / grype) for the image
  container  -> resolve the image via `docker inspect` and scan that image,
               plus falco for live behaviour when the profile asks for it
  dockerfile -> trivy config; dockle only as a second opinion in `strict`,
               and its absence is a diagnostic, not a degradation, because
               trivy config already covers the ground
  fs         -> trivy fs / grype dir (vulnerabilities + misconfig + secrets)

aggregator mode (--engine X): run exactly that scanner; normalisation, dedup,
risk score, policy and report stay ours.

There are no checks of our own. Every finding in a report comes from a scanner.
That is a deliberate decision: trivy already lints Dockerfiles and searches for
secrets, and duplicating those rules in Python only creates a second opinion
that can disagree with the first.

Design rules enforced here (SPEC.md section 3):
  I-1  A scanner that did not succeed must never contribute to a PASS verdict.
  I-4  A scanner binary is executed by absolute path.
  I-5  An unresolvable target is an error, not an empty passing report.
  I-12 Every skipped or failed step is recorded in `diagnostics`.
  I-13 No fabricated data ever reaches a report.
  I-15 A scanner is not invoked against a target that does not exist.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess

from sarbar import policy as policy_mod
from sarbar.engines import (ENGINES, STATUS_UNSUPPORTED, EngineResult,
                            FalcoEngine, TrivyEngine)
from sarbar.model import Finding
from sarbar.normalize import normalize_all
from sarbar.policy import Policy
from sarbar.risk import apply_policy, score_findings
from sarbar.target import Target, TargetKind


class TargetError(RuntimeError):
    """Target cannot be resolved. Must surface as a CLI error, never as a PASS."""


# --------------------------------------------------------------------------
# docker
# --------------------------------------------------------------------------

def list_docker_ids() -> set:
    if shutil.which("docker") is None:
        return set()
    try:
        p = subprocess.run(["docker", "ps", "--format", "{{.ID}} {{.Names}}"],
                           capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return set()
    if p.returncode != 0:
        return set()
    ids: set[str] = set()
    for line in (p.stdout or "").splitlines():
        ids.update(line.split())
    return ids


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        p = subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"],
                           capture_output=True, text=True, timeout=20)
        return p.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


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
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None


# --------------------------------------------------------------------------
# target resolution (I-5)
# --------------------------------------------------------------------------

def resolve_container(name_or_id: str) -> tuple[dict | None, str | None]:
    """Return (inspect_dict, image_ref). Raises TargetError when unresolvable."""
    if not docker_available():
        raise TargetError(
            f"cannot resolve container '{name_or_id}': docker is not usable "
            "(binary missing or the daemon socket is not accessible). Scan the "
            "image reference directly instead, e.g. `sarbar scan <image>`.")
    inspect = docker_inspect(name_or_id)
    if not inspect:
        raise TargetError(
            f"container '{name_or_id}' not found. `docker ps` shows nothing with "
            "this id or name; runtime checks need a running container.")
    image_ref = (inspect.get("Config") or {}).get("Image")
    return inspect, image_ref


def validate_target(target: Target) -> None:
    """Raise TargetError when the target provably does not exist."""
    raw = target.raw
    if target.kind in (TargetKind.FS, TargetKind.DOCKERFILE):
        if _looks_like_path(raw) and not _path_exists(raw):
            raise TargetError(f"path does not exist: {raw}")
    elif target.kind == TargetKind.CONTAINER:
        if ":" not in raw and "/" not in raw and not _path_exists(raw):
            return  # confirmed against docker during the scan


def _looks_like_path(raw: str) -> bool:
    return raw.startswith(("./", "../", "/", "~/")) or "." in raw


def _path_exists(raw: str) -> bool:
    return os.path.exists(os.path.expanduser(raw))


# --------------------------------------------------------------------------
# plan
# --------------------------------------------------------------------------

def plan_scan(target: Target, pol: Policy, forced_engine: str | None = None) -> dict:
    """Explainable plan: which scanners and why. Shown with -ex/--explain."""
    if forced_engine and forced_engine != "none":
        engines = [forced_engine]
        why = f"aggregator mode: --engine {forced_engine}"
    elif forced_engine == "none":
        engines = []
        why = "no scanner requested (--engine none)"
    else:
        engines = policy_mod.engines_for(pol, target.kind.value)
        why = (f"auto mode: profile '{pol.name}' selects "
               f"{engines or ['(none)']} for {target.kind.value}")
    return {"engines": engines, "why": why, "profile": pol.name,
            "target": target.raw, "kind": target.kind.value,
            "offline": bool(pol.offline)}


# --------------------------------------------------------------------------
# execution
# --------------------------------------------------------------------------

def _run_engine(name: str, scan_ref: str, kind: str, offline: bool,
                allow_sudo: bool = True) -> EngineResult:
    eng = ENGINES.get(name)
    if eng is None:
        return EngineResult(status="unsupported", detail=f"unknown scanner '{name}'")
    if not eng.supports or kind not in eng.supports:
        return EngineResult(status=STATUS_UNSUPPORTED, detail=f"{name} has no {kind} mode")
    if offline and not getattr(eng, "supports_offline", True):
        return EngineResult(status="unavailable",
                            detail=f"{name} cannot work without network")
    try:
        try:
            if isinstance(eng, FalcoEngine):
                return eng.run(scan_ref, kind, offline=offline,
                               allow_sudo=allow_sudo)
            return eng.run(scan_ref, kind, offline=offline)
        except TypeError:
            return eng.run(scan_ref, kind)
    except Exception as ex:  # an adapter must never break the scan
        return EngineResult(status="failed",
                            detail=f"{name} raised {type(ex).__name__}: {ex}")


def _ensure_offline_database(diagnostics: list) -> bool:
    """Make sure a local vulnerability database exists before scanning offline.

    Without this, `sarbar offline` on a fresh machine either fails with an
    obscure scanner error or, worse, silently reports nothing. Downloading the
    database is the one network operation offline mode is allowed to do.
    """
    trivy = ENGINES.get("trivy")
    if trivy is None:
        return False
    if TrivyEngine.db_present():
        return True
    diagnostics.append("no local vulnerability database found; fetching it now")
    ok, detail = trivy.download_db()
    diagnostics.append(f"database: {detail}")
    return ok


def run_scan(target: Target, pol: Policy, forced_engine: str | None = None,
             offline: bool = False, allow_sudo: bool = True,
             target_error: str | None = None) -> dict:
    plan = plan_scan(target, pol, forced_engine)
    findings: list[Finding] = []
    scanners_used: list[str] = []
    diagnostics: list[str] = []
    scanner_status: dict[str, str] = {}
    kind = target.kind.value
    scan_ref = target.raw

    if target_error:
        diagnostics.append(target_error)

    # ---- container resolution (I-5) -------------------------------------
    image_ref = None
    if target.kind == TargetKind.CONTAINER and not target_error:
        inspect, image_ref = resolve_container(target.raw)
        if image_ref:
            scan_ref = image_ref
            diagnostics.append(f"container resolved to image {image_ref}")

    # ---- offline pre-flight: the database must exist locally ------------
    if offline and not target_error and "trivy" in plan["engines"]:
        _ensure_offline_database(diagnostics)

    # ---- scanners --------------------------------------------------------
    scan_kind = "image" if target.kind == TargetKind.CONTAINER else kind
    for name in ([] if target_error else plan["engines"]):
        # For a container, falco watches the container; the rest scan the image
        ref = target.raw if (target.kind == TargetKind.CONTAINER and name == "falco") \
            else scan_ref
        res = _run_engine(name, ref, scan_kind, offline, allow_sudo)
        scanner_status[name] = res.status
        if res.ok:
            scanners_used.append(name)
            findings.extend(res.findings)
            if res.detail:
                diagnostics.append(f"{name}: {res.detail}")
        else:
            diagnostics.append(f"{name} not used [{res.status}]: {res.detail}")

    # ---- normalise, score, policy ---------------------------------------
    findings = normalize_all(findings)
    risk = score_findings(findings)
    verdict, reasons = apply_policy(findings, risk, pol)

    # ---- degraded verdict (I-1) -----------------------------------------
    degraded = not scanners_used
    if degraded:
        causes = [d for d in diagnostics
                  if any(k in d for k in ("not used", "cannot work without network"))]
        reasons = list(reasons)
        if target_error:
            # Nothing was analysed because the target does not exist. Reporting
            # "pass" here would mean a typo turns a build green.
            verdict = "fail"
            reasons.append("target could not be resolved, so nothing was analysed")
        elif getattr(pol, "fail_on_degraded", False):
            # Unconditional on purpose. An earlier version also required `causes`
            # to be non-empty, which let `-e none` through as PASS: with no
            # scanner requested, none is attempted, so no diagnostic is produced
            # and `causes` stayed empty. Asking for zero scanners is not a reason
            # to hand out a green light. The profile that legitimately wants no
            # gates is `report`, which sets fail_on_degraded to false.
            verdict = "fail"
            if causes:
                reasons.append("no scanner produced results and the policy "
                               "requires at least one working scanner")
            else:
                reasons.append("no scanner was requested, so nothing was "
                               "analysed")
        if causes or target_error or not scanners_used:
            reasons.append("DEGRADED: no scanner produced results")

    warnings: list[str] = []
    if "falco" in plan["engines"] and scanner_status.get("falco") != "ok":
        warnings.append(
            "falco observed nothing. It reads kernel events through an eBPF "
            "driver, which must be installed once: sudo sarbar setup --driver. "
            "Until then nothing about the container's behaviour is known — "
            "which is not the same as the container being clean.")
    if degraded and not target_error:
        warnings.append("no scanner ran at all: nothing was actually analysed")

    return {
        "target": target.raw,
        "target_kind": kind,
        "image_ref": image_ref,
        "profile": pol.name,
        "plan": plan,
        "scanners_used": scanners_used,
        "scanner_status": scanner_status,
        "findings": findings,
        "risk": {"score": risk.score, "level": risk.level,
                 "counts": risk.counts, "max_cvss": risk.max_cvss,
                 "reasons": risk.reasons},
        "verdict": verdict,
        "policy_reasons": reasons,
        "offline": bool(offline),
        "degraded": degraded,
        "diagnostics": diagnostics,
        "warnings": warnings,
    }