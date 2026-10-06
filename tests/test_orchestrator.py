"""Orchestrator invariants. These are the tests that must never be deleted.

Each test names the SPEC.md invariant it protects.

Two things changed in 0.3.0 and the tests follow the new design rather than
defending the old one:

  * there is no mock engine any more — demo data in a security report is
    indistinguishable from a real finding once it is written down;
  * sarbar's own checks are opt-in (`--our-checks`). sarbar is a wrapper over
    scanners, and the scanners already cover Dockerfile lint and secret search.
    The invariant that survived is the important one: when they are switched on,
    nothing may silently switch them off.
"""
from __future__ import annotations

import pathlib

import pytest

from sarbar import orchestrator as orch
from sarbar.engines import (STATUS_FAILED, STATUS_OK, STATUS_UNAVAILABLE,
                            STATUS_UNSUPPORTED, EngineResult)
from sarbar.policy import load_profile
from sarbar.target import Target, TargetKind


def _policy(profile="default"):
    return load_profile(profile)


def _stub(monkeypatch, name, findings=(), status=STATUS_OK, detail=""):
    """Install a fake scanner so the test never shells out."""
    from sarbar.engines import ENGINES

    class Stub:
        supports = ("image", "fs", "dockerfile", "container")
        needs_root = False
        supports_offline = True

        def resolve(self):
            return "/usr/bin/true"

        def is_available(self):
            return status == STATUS_OK

        def run(self, target, kind):
            if status != STATUS_OK:
                return EngineResult(status=status, detail=detail or "stub failure")
            return EngineResult(findings=list(findings), status=STATUS_OK)

    monkeypatch.setitem(ENGINES, name, Stub())


def _vuln(cid="CVE-1", pkg="openssl", ver="1.0", sev="LOW"):
    from sarbar.model import Finding
    return Finding(cid, "t", sev, target="x", engine="trivy", category="vuln",
                   package=pkg, installed_version=ver)


DF_DIRTY = ("FROM ubuntu:latest\n"
            "ADD app.tar.gz /app\n"
            "ENV API_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456\n")
DF_CLEAN = "FROM alpine:3.19\nUSER app\nHEALTHCHECK CMD true\n"


# ---------------------------------------------------------------- I-1

def test_failed_scanner_cannot_yield_a_pass(tmp_path, monkeypatch):
    df = tmp_path / "Dockerfile"
    df.write_text(DF_CLEAN)
    _stub(monkeypatch, "trivy", status=STATUS_FAILED,
          detail="exit 1, no JSON report")
    res = orch.run_scan(Target(str(df), TargetKind.DOCKERFILE), _policy("default"))
    assert res["degraded"] is True
    assert res["verdict"] == "fail", "a run with no working scanner must not pass"
    assert "trivy" not in res["scanners_used"]
    assert any("trivy" in d and STATUS_FAILED in d for d in res["diagnostics"])


def test_degraded_is_explained_in_the_policy_reasons(tmp_path, monkeypatch):
    df = tmp_path / "Dockerfile"
    df.write_text(DF_CLEAN)
    _stub(monkeypatch, "trivy", status=STATUS_FAILED, detail="boom")
    res = orch.run_scan(Target(str(df), TargetKind.DOCKERFILE), _policy("default"))
    joined = " ".join(res["policy_reasons"])
    assert "DEGRADED" in joined
    assert "at least one working scanner" in joined


def test_report_profile_may_pass_while_degraded(tmp_path, monkeypatch):
    df = tmp_path / "Dockerfile"
    df.write_text(DF_CLEAN)
    _stub(monkeypatch, "trivy", status=STATUS_FAILED, detail="boom")
    res = orch.run_scan(Target(str(df), TargetKind.DOCKERFILE), _policy("report"))
    assert res["degraded"] is True
    assert res["verdict"] == "pass"


def test_working_scanner_is_not_degraded(tmp_path, monkeypatch):
    df = tmp_path / "Dockerfile"
    df.write_text(DF_CLEAN)
    _stub(monkeypatch, "trivy", findings=[_vuln()])
    res = orch.run_scan(Target(str(df), TargetKind.DOCKERFILE), _policy("default"))
    assert res["degraded"] is False
    assert res["scanners_used"] == ["trivy"]
    assert res["scanner_status"]["trivy"] == STATUS_OK


def test_unsupported_scanner_is_diagnosed(tmp_path, monkeypatch):
    df = tmp_path / "Dockerfile"
    df.write_text(DF_CLEAN)
    _stub(monkeypatch, "trivy", findings=[_vuln()])
    pol = _policy("default")
    pol.engines_dockerfile = ["grype", "trivy"]
    res = orch.run_scan(Target(str(df), TargetKind.DOCKERFILE), pol)
    assert res["scanner_status"]["grype"] == STATUS_UNSUPPORTED
    assert res["degraded"] is False


def test_falco_gap_produces_a_warning(monkeypatch):
    """falco has no event source without root; the report must say so."""
    _stub(monkeypatch, "trivy", findings=[_vuln()])
    _stub(monkeypatch, "falco", status=STATUS_UNAVAILABLE, detail="no driver")
    pol = _policy("default")
    pol.engines_image = ["trivy", "falco"]
    res = orch.run_scan(Target("alpine:3.19", TargetKind.IMAGE), pol)
    joined = " ".join(res["warnings"])
    assert "setup --driver" in joined
    assert "trivy" in res["scanners_used"]


def test_warning_when_nothing_scanned_at_all(tmp_path, monkeypatch):
    df = tmp_path / "Dockerfile"
    df.write_text(DF_CLEAN)
    _stub(monkeypatch, "trivy", status=STATUS_FAILED, detail="boom")
    res = orch.run_scan(Target(str(df), TargetKind.DOCKERFILE), _policy("report"))
    assert res["degraded"] is True
    assert any("nothing was actually analysed" in w for w in res["warnings"])


# ---------------------------------------------------------------- I-5

def test_missing_path_is_an_error_not_a_pass(tmp_path):
    missing = str(tmp_path / "nope")
    with pytest.raises(orch.TargetError):
        orch.validate_target(Target(missing, TargetKind.FS))


def test_missing_dockerfile_is_detected(tmp_path):
    with pytest.raises(orch.TargetError):
        orch.validate_target(Target(str(tmp_path / "Dockerfile"), TargetKind.DOCKERFILE))


def test_target_error_stops_the_scan(tmp_path):
    missing = str(tmp_path / "nope")
    res = orch.run_scan(Target(missing, TargetKind.FS), _policy("default"),
                        target_error=f"path does not exist: {missing}")
    assert res["verdict"] == "fail"
    assert res["scanners_used"] == [], "no scanner may run against a missing target"
    assert any("does not exist" in d for d in res["diagnostics"])


def test_unresolvable_container_raises():
    with pytest.raises(orch.TargetError):
        orch.resolve_container("definitely-not-running")


# ---------------------------------------------------------------- no own checks

def test_there_is_no_checks_package():
    """sarbar has no checks of its own: every finding comes from a scanner."""
    import importlib
    try:
        importlib.import_module("sarbar.checks")
        raise AssertionError("sarbar.checks must stay deleted")
    except ModuleNotFoundError:
        pass


def test_orchestrator_does_not_import_checks():
    source = (pathlib.Path(__file__).parents[1] / "sarbar" / "orchestrator.py").read_text()
    assert "sarbar.checks" not in source
    assert "our_checks" not in source


def test_run_scan_rejects_our_checks_argument():
    import inspect as _inspect
    from sarbar import orchestrator as o
    assert "our_checks" not in _inspect.signature(o.run_scan).parameters


def test_findings_come_only_from_scanners(tmp_path, monkeypatch):
    df = tmp_path / "Dockerfile"
    df.write_text(DF_DIRTY)
    _stub(monkeypatch, "trivy", findings=[_vuln()])
    res = orch.run_scan(Target(str(df), TargetKind.DOCKERFILE), _policy("default"))
    assert res["scanners_used"] == ["trivy"]
    assert {f.engine for f in res["findings"]} == {"trivy"}


# ---------------------------------------------------------------- plan

def test_plan_has_no_our_checks_key():
    plan = orch.plan_scan(Target("./Dockerfile", TargetKind.DOCKERFILE), _policy("ci"))
    assert "our_checks" not in plan


def test_plan_per_kind():
    pol = _policy("ci")
    p = orch.plan_scan(Target("alpine:3.19", TargetKind.IMAGE), pol)
    assert "trivy" in p["engines"] and "grype" in p["engines"]
    p2 = orch.plan_scan(Target("Dockerfile", TargetKind.DOCKERFILE), pol)
    # trivy config is always present; dockle is the optional second opinion
    assert p2["engines"][0] == "trivy"


def test_plan_forced_engine_and_none():
    pol = _policy("default")
    assert orch.plan_scan(Target("x", TargetKind.IMAGE), pol,
                          forced_engine="trivy")["engines"] == ["trivy"]
    assert orch.plan_scan(Target("x", TargetKind.IMAGE), pol,
                          forced_engine="none")["engines"] == []


# ---------------------------------------------------------------- no mock

def test_there_is_no_mock_engine():
    import importlib
    try:
        importlib.import_module("sarbar.engines.mock")
        raise AssertionError("the mock engine must stay deleted")
    except ModuleNotFoundError:
        pass


def test_result_has_no_mock_key(tmp_path, monkeypatch):
    df = tmp_path / "Dockerfile"
    df.write_text(DF_DIRTY)
    _stub(monkeypatch, "trivy", findings=[_vuln()])
    res = orch.run_scan(Target(str(df), TargetKind.DOCKERFILE), _policy("default"))
    assert "mock" not in res["scanners_used"]
    assert all(f.engine != "mock" for f in res["findings"])

# ------------------------------------ I-1: a green light must mean "analysed"

def test_engine_none_cannot_produce_a_pass(tmp_path, monkeypatch):
    """`-e none` asks for zero scanners.

    An earlier version only turned DEGRADED into FAIL when a diagnostic said
    "not used" — but with no scanner requested, none is attempted, so no
    diagnostic is produced and the run slipped through as PASS with exit code 0.
    In CI that is the worst possible outcome: a green build that checked
    nothing.
    """
    from sarbar.policy import load_profile
    from sarbar.target import Target, TargetKind
    import sarbar.orchestrator as orch

    monkeypatch.setattr(orch, "_run_engine",
                        lambda *a, **k: pytest.fail("no scanner may run with -e none"))
    res = orch.run_scan(Target("t", TargetKind.DOCKERFILE, "test"),
                        load_profile("default"), forced_engine="none")
    assert res["degraded"] is True
    assert res["verdict"] == "fail"
    assert any("nothing was analysed" in r for r in res["policy_reasons"]), \
        res["policy_reasons"]


def test_report_profile_is_the_documented_way_to_ask_for_no_gates(tmp_path, monkeypatch):
    """`report` exists precisely so that a run with no gates is deliberate."""
    from sarbar.policy import load_profile
    from sarbar.target import Target, TargetKind
    import sarbar.orchestrator as orch

    monkeypatch.setattr(orch, "_run_engine",
                        lambda *a, **k: pytest.fail("no scanner may run"))
    res = orch.run_scan(Target("t", TargetKind.DOCKERFILE, "test"),
                        load_profile("report"), forced_engine="none")
    assert res["verdict"] == "pass"
    assert res["degraded"] is True, "still honest about having analysed nothing"


def test_a_scanner_that_ran_and_found_nothing_does_pass(tmp_path, monkeypatch):
    """The mirror image of I-1: a green light IS allowed here, because a scanner
    really did look and reported nothing."""
    from sarbar.policy import load_profile
    from sarbar.target import Target, TargetKind
    from sarbar.engines import EngineResult
    import sarbar.orchestrator as orch

    monkeypatch.setattr(orch, "_run_engine",
                        lambda *a, **k: EngineResult(status="ok", findings=[]))
    res = orch.run_scan(Target("t", TargetKind.DOCKERFILE, "test"),
                        load_profile("default"))
    assert res["verdict"] == "pass", res
    assert res["degraded"] is False


def test_a_scanner_that_failed_with_no_findings_must_fail(tmp_path, monkeypatch):
    """The dangerous shape: no findings at all, but nothing actually worked."""
    from sarbar.policy import load_profile
    from sarbar.target import Target, TargetKind
    from sarbar.engines import EngineResult
    import sarbar.orchestrator as orch

    monkeypatch.setattr(
        orch, "_run_engine",
        lambda *a, **k: EngineResult(status="failed", findings=[],
                                      detail="trivy exit=1, no report"))
    res = orch.run_scan(Target("t", TargetKind.DOCKERFILE, "test"),
                        load_profile("default"))
    assert res["findings"] == []
    assert res["degraded"] is True
    assert res["verdict"] == "fail", res
