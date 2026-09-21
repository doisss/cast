from sarbar.cli import build_parser, main
from sarbar.orchestrator import plan_scan
from sarbar.policy import load_profile
from sarbar.target import Target, TargetKind


def test_plan_auto_selects_per_kind():
    pol = load_profile("ci")
    p = plan_scan(Target("alpine:3.19", TargetKind.IMAGE), pol)
    assert "trivy" in p["engines"] and "grype" in p["engines"]
    p2 = plan_scan(Target("Dockerfile", TargetKind.DOCKERFILE), pol)
    assert p2["engines"] == ["dockle"]


def test_plan_forced_engine():
    pol = load_profile("default")
    p = plan_scan(Target("alpine:3.19", TargetKind.IMAGE), pol, forced_engine="trivy")
    assert p["engines"] == ["trivy"]


def test_scan_offline_no_network(tmp_path):
    # offline scan of a temp dir: only local checks + mock, no binaries needed
    rc = main(["scan", str(tmp_path), "--offline", "--no-history", "--format", "json"])
    assert rc in (0, 1)


def test_history_and_engines(capsys):
    assert main(["engines"]) == 0
    assert main(["history", "--limit", "1"]) == 0
    capsys.readouterr()
