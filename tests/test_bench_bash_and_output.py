import json
from pathlib import Path

from cast.models import Finding, Severity
from cast.pipeline import ScanResult, ScannerRun
from cast.report import console as console_report
from cast.scanners import docker_bench as db
from cast.scanners.docker_bench import DockerBenchScanner, _read_remediation
from cast.targets import Target

SWARM = """[INFO] 7 - Docker Swarm Configuration
[PASS] 7.1 - Ensure that the minimum number of manager nodes have been created in a swarm (Automated) (Swarm mode not enabled)
[PASS] 7.3 - Ensure that all Docker swarm overlay networks are encrypted (Automated)
"""


def test_swarm_checks_with_extra_note_are_counted():
    found = DockerBenchScanner()._parse(SWARM)
    assert [f.check_id for f in found] == ["7.1", "7.3"]
    assert all(f.status == "PASS" for f in found)
    assert "(Swarm" not in found[0].title


def test_remediation_section_is_not_parsed_as_checks():
    out = SWARM + "\nSection B - Remediation measures\n\n[INFO] 2.2 - Edit the file (Manual)\n"
    assert [f.check_id for f in DockerBenchScanner()._parse(out)] == ["7.1", "7.3"]


def test_remediation_read_from_json_log(tmp_path):
    log = tmp_path / "b.json"
    log.write_text(json.dumps({"tests": [
        {"id": "2.2", "result": "WARN", "remediation": "set icc false", "remediation-impact": "no inter-container"},
        {"id": "7.1", "result": "PASS"}]}))
    assert _read_remediation(log) == {"2.2": ("set icc false", "no inter-container")}
    assert _read_remediation(tmp_path / "missing.json") == {}


def test_script_is_run_with_bash_and_remediation_flag(tmp_path, monkeypatch):
    script = tmp_path / "docker-bench-security.sh"
    script.write_text("#!/bin/bash\n")
    seen = {}

    class R:
        stdout = ""
        stderr = ""
        returncode = 0

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return R()

    monkeypatch.setattr(db.subprocess, "run", fake_run)
    monkeypatch.setattr(db.shutil, "which", lambda name: "/usr/bin/bash")
    DockerBenchScanner()._run(script)
    assert seen["cmd"][0] == "/usr/bin/bash" and "-p" in seen["cmd"]


def test_container_name_is_stripped_from_details(monkeypatch):
    sc = DockerBenchScanner()
    monkeypatch.setattr(db, "locate_script", lambda: Path("/x/s.sh"))
    monkeypatch.setattr(sc, "_run", lambda script, args: "[WARN] 4.1 - Ensure user (Automated)\n[WARN]      * Running as root: web\n")
    t = Target("container", "abc", container_name="web")
    assert sc.scan_target(t)[0].details == ["Running as root"]


def _render(result):
    from io import StringIO
    from rich.console import Console
    buf = StringIO()
    console_report.render(result, console=Console(file=buf, width=200, force_terminal=False), top=25)
    return buf.getvalue()


def test_severity_table_has_versions_status_link_and_row_lines():
    f = Finding("trivy", "CVE-1", "bad thing", Severity.MEDIUM, package="requests",
                installed_version="2.25.0", fixed_version="2.31.0", fix_status="fixed",
                url="https://avd.aquasec.com/nvd/cve-1")
    f.confirmed_by = ["trivy"]
    g = Finding("trivy", "CVE-2", "other", Severity.LOW, package="idna", installed_version="1", fix_status="affected")
    g.confirmed_by = ["trivy"]
    result = ScanResult(image="x", findings=[f, g], target=Target("image", "x"),
                        runs=[ScannerRun("trivy", "image", "ok", "", 1, 1.0)])
    out = _render(result)
    for text in ("Установлена", "Исправлено в", "2.25.0", "2.31.0",
                 "https://avd.aquasec.com/nvd/cve-1", "Источник", "(trivy,"):
        assert text in out
    assert "готово, записей" not in out and "нет фикса" not in out
    assert out.lstrip().startswith("✓ Уязвимости образа x")
    assert "├" in out or "╞" in out or "┣" in out or "─┼" in out  # линии между строками


def test_remediation_found_in_nested_sections(tmp_path):
    log = tmp_path / "n.json"
    log.write_text(json.dumps({"tests": [{"id": "1", "results": [{"id": "1.1", "results": [
        {"id": "1.1.1", "result": "WARN", "remediation": "make partition"}]}]}]}))
    assert _read_remediation(log) == {"1.1.1": ("make partition", "")}


def test_check_without_number_is_not_lost():
    from cast.scanners.docker_bench import DockerBenchScanner
    raw = (
        "[WARN] 2.16 - Ensure Userland Proxy is Disabled (Scored)\n"
        "[INFO] Ensure that experimental features are not implemented in production (Scored) (Deprecated)\n"
        "[PASS] 2.18 - Ensure containers are restricted from acquiring new privileges (Scored)\n"
    )
    found = DockerBenchScanner()._parse(raw)
    assert len(found) == 3 and found[1].status == "INFO"


def test_count_matches_docker_bench_checks_line():
    """Реальный вывод Docker Bench: «Checks: 117» должно равняться числу разобранных проверок."""
    import pathlib
    from cast.scanners.docker_bench import DockerBenchScanner
    fx = pathlib.Path(__file__).parent / "fixtures" / "bench_full.txt"
    if fx.exists():
        assert len(DockerBenchScanner()._parse(fx.read_text())) == 117


def test_summary_read_from_bench_json(tmp_path):
    from cast.scanners.docker_bench import _read_summary
    p = tmp_path / "b.json"
    p.write_text('{"tests": [], "checks": 33, "score": 9}')
    assert _read_summary(p) == {"checks": 33, "score": 9}
    assert _read_summary(tmp_path / "nope.json") == {}


def test_broken_group_log_json_is_repaired(tmp_path):
    """Docker Bench при -c пишет журнал без запятой между проверкой и разделом."""
    from cast.scanners.docker_bench import _read_remediation, _read_summary
    p = tmp_path / "b.json"
    p.write_text(
        '{"tests": [{"id": "4.1", "result": "WARN", "remediation": "Add USER"}'
        ' {"id": "5", "results": [{"id": "5.3", "remediation": "SELinux"}]}],'
        ' "checks": 33, "score": 9}'
    )
    assert _read_summary(p) == {"checks": 33, "score": 9}
    assert set(_read_remediation(p)) == {"4.1", "5.3"}


def test_square_brackets_in_details_are_not_eaten_by_markup():
    from io import StringIO
    from rich.console import Console
    from cast.models import Finding, Severity
    from cast.report.console import _print_status_table
    f = Finding(source_tool="docker-bench", check_id="4.6", title="t", severity=Severity.UNKNOWN,
                status="WARN", details=["No Healthcheck found: [hello-fedora:1.0]"])
    c = Console(file=StringIO(), width=120)
    _print_status_table(c, [f], 0)
    assert "[hello-fedora:1.0]" in c.file.getvalue()
