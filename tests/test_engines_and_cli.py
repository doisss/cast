import json
import subprocess
from io import StringIO

import pytest
from rich.console import Console

from cast import cli, pipeline, state, targets
from cast.models import Finding, Severity
from cast.pipeline import EngineSelectionError, run_scan, select_scanners
from cast.report import console as console_report
from cast.report import html_report, json_report
from cast.scanners.base import Scanner, ScannerError
from cast.scanners.docker_bench import CONTAINER_GROUPS, DockerBenchScanner
from cast.scanners.trivy import TrivyScanner
from cast.targets import Target


class FakeTrivy(Scanner):
    name = "trivy"
    scope = "image"
    targets = {"image", "fs", "dockerfile", "container"}
    default_targets = {"image", "fs", "dockerfile"}
    error = None
    seen: list = []

    def is_available(self):
        return True

    def scan_target(self, target):
        FakeTrivy.seen.append(target.kind)
        if self.error:
            raise ScannerError(self.error)
        return [Finding("trivy", "CVE-1", "t", Severity.HIGH, package="zlib", pkg_type="alpine")]


class FakeBench(Scanner):
    name = "docker-bench"
    scope = "environment"
    targets = {"host", "container"}
    default_targets = {"host", "container"}
    error = None

    def is_available(self):
        return True

    def scan_target(self, target):
        if self.error:
            raise ScannerError(self.error)
        return [
            Finding("docker-bench", "4.1", "Ensure a user", Severity.UNKNOWN,
                    status="WARN", details=["Running as root: hello"]),
            Finding("docker-bench", "5.2", "Ensure SELinux", Severity.UNKNOWN, status="INFO"),
            Finding("docker-bench", "5.3", "Ensure caps", Severity.UNKNOWN, status="PASS"),
        ]


def _render(result):
    buf = StringIO()
    console_report.render(result, console=Console(file=buf, width=150, force_terminal=False))
    return buf.getvalue()


def _container():
    return Target("container", "12b1e6c27fd6", container_name="hello",
                  image_name="hello-fedora:1.0", image_ref="sha256:abc")


# --- выбор движков ----------------------------------------------------------

def test_default_engine_per_target_kind():
    engines = [FakeTrivy(), FakeBench()]
    assert [s.name for s in select_scanners("image", engines, None)] == ["trivy"]
    assert [s.name for s in select_scanners("fs", engines, None)] == ["trivy"]
    assert [s.name for s in select_scanners("host", engines, None)] == ["docker-bench"]
    # для контейнера по умолчанию ТОЛЬКО Docker Bench
    assert [s.name for s in select_scanners("container", engines, None)] == ["docker-bench"]


def test_engine_flag_adds_trivy_for_container_with_main_engine_first():
    engines = [FakeTrivy(), FakeBench()]
    chosen = select_scanners("container", engines, ["trivy", "docker-bench"])
    assert [s.name for s in chosen] == ["docker-bench", "trivy"]   # главный — первым


def test_engine_flag_rejects_wrong_or_unknown_engine():
    engines = [FakeTrivy(), FakeBench()]
    with pytest.raises(EngineSelectionError, match="не умеет"):
        select_scanners("host", engines, ["trivy"])
    with pytest.raises(EngineSelectionError, match="неизвестный"):
        select_scanners("image", engines, ["grype"])


# --- отчёты -----------------------------------------------------------------

def test_container_report_shows_statuses_details_and_trivy_hint():
    result = run_scan(_container(), scanners=[FakeTrivy(), FakeBench()])
    out = _render(result)
    assert [r.name for r in result.runs] == ["docker-bench"]
    assert "Настройки запуска контейнера hello" in out
    assert "WARN" in out and "Running as root: hello" in out
    assert "HIGH" not in out and "MEDIUM" not in out         # уровней нет
    assert "PASS: 1" in out and "5.3" in out                  # PASS тоже в таблице: показываем всё
    assert "cast scan hello-fedora:1.0" in " ".join(out.split())   # пометка про образ


def test_container_with_trivy_has_no_hint_and_runs_main_engine_first():
    result = run_scan(_container(), scanners=[FakeTrivy(), FakeBench()], engines=["trivy", "docker-bench"])
    out = _render(result)
    assert [r.name for r in result.runs] == ["docker-bench", "trivy"]
    assert out.index("Настройки запуска контейнера") < out.index("Уязвимости образа контейнера")
    assert "не проверялись" not in out


def test_failed_main_engine_gives_honest_banner_for_host():
    bench = FakeBench()
    bench.error = "нет доступа к Docker-демону"
    result = run_scan(Target("host", "host"), scanners=[FakeTrivy(), bench])
    assert result.primary_failed
    out = _render(result)
    assert "Проверка НЕ выполнена" in out and "нет доступа к Docker-демону" in out


def test_counts_ignore_docker_bench_statuses():
    result = run_scan(_container(), scanners=[FakeBench()])
    assert sum(result.counts_by_severity.values()) == 0
    assert result.counts_by_status == {"WARN": 1, "NOTE": 0, "INFO": 1, "PASS": 1}


def test_json_and_html_reports_contain_statuses(tmp_path):
    result = run_scan(_container(), scanners=[FakeBench()])
    data = json_report.to_dict(result)
    assert data["target"]["kind"] == "container"
    assert data["status_summary"]["WARN"] == 1
    assert any(f["status"] == "WARN" and f["details"] for f in data["findings"])
    html = html_report.render_html(result)       # шаблон найден и рендерится
    assert "Running as root: hello" in html and "WARN" in html


def test_html_template_is_included_in_package_data():
    import tomllib
    from pathlib import Path

    cfg = tomllib.loads((Path(__file__).parent.parent / "pyproject.toml").read_text(encoding="utf-8"))
    assert "report/templates/*.jinja" in cfg["tool"]["setuptools"]["package-data"]["cast"]


# --- скрипты движков --------------------------------------------------------

def test_docker_bench_host_and_container_arguments(monkeypatch, tmp_path):
    script = tmp_path / "docker-bench-security.sh"
    script.write_text("version='1.6.0'\n")
    monkeypatch.setattr("cast.scanners.docker_bench.locate_script", lambda: script)
    calls = []
    monkeypatch.setattr(DockerBenchScanner, "_run", lambda self, s, extra=None: calls.append(extra) or "")
    scanner = DockerBenchScanner()
    scanner.scan_target(Target("host", "host"))
    scanner.scan_target(_container())
    assert calls[0] == []   # хост = весь скрипт, как при прямом запуске
    assert calls[1] == ["-c", CONTAINER_GROUPS, "-i", "^hello$"]
    assert scanner.version() == "1.6.0"
    with pytest.raises(ScannerError):
        scanner.scan_target(Target("fs", "."))


def test_trivy_commands_for_each_target(monkeypatch, tmp_path):
    monkeypatch.setattr("cast.scanners.trivy.find_binary", lambda *a, **k: "/usr/bin/trivy")
    monkeypatch.setattr("cast.scanners.trivy._db_needs_update", lambda: False)
    cmds = []

    def fake_exec(cmd, on_line=None):
        cmds.append(cmd)
        return 0, '{"Results": []}', ""

    monkeypatch.setattr("cast.scanners.trivy._exec", fake_exec)
    scanner = TrivyScanner()
    scanner.scan_target(Target("image", "alpine:3.19"))
    scanner.scan_target(_container())
    scanner.scan_target(Target("fs", "./app"))
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM alpine")
    scanner.scan_target(Target("dockerfile", str(dockerfile)))

    assert cmds[0][:2] == ["/usr/bin/trivy", "image"] and cmds[0][-1] == "alpine:3.19"
    assert cmds[1][-1] == "sha256:abc"                         # образ контейнера по ID
    assert cmds[2][1] == "fs" and "vuln,secret,misconfig" in cmds[2]
    assert cmds[3][1] == "config"


def test_trivy_parses_misconfigurations_and_secrets():
    raw = json.dumps({"Results": [{
        "Target": "Dockerfile", "Type": "dockerfile",
        "Misconfigurations": [
            {"ID": "DS-0002", "Title": "Image user should not be 'root'", "Severity": "HIGH",
             "Status": "FAIL", "Resolution": "Add USER", "CauseMetadata": {"StartLine": 3}},
            {"ID": "DS-0001", "Title": "ok", "Severity": "LOW", "Status": "PASS"},
        ],
        "Secrets": [{"RuleID": "aws-access-key-id", "Title": "AWS key", "Severity": "CRITICAL",
                     "StartLine": 7}],
    }]})
    findings = TrivyScanner()._parse(raw)
    assert [f.check_id for f in findings] == ["DS-0002", "aws-access-key-id"]
    assert findings[0].severity == Severity.HIGH
    assert "Dockerfile:3" in findings[0].location
    assert findings[1].severity == Severity.CRITICAL


def test_same_misconfig_in_two_files_is_not_merged():
    from cast.dedup import deduplicate

    def mis(path):
        return Finding("trivy", "DS-0002", "t", Severity.HIGH, location=path)

    assert len(deduplicate([mis("a/Dockerfile"), mis("b/Dockerfile")])) == 2


# --- первый показ host ------------------------------------------------------

def test_state_marker(monkeypatch, tmp_path):
    monkeypatch.setenv("CAST_STATE_DIR", str(tmp_path / "st"))
    assert not state.host_check_done()
    state.mark_host_checked()
    assert state.host_check_done()


def _patch_engines(monkeypatch, bench_error=None):
    bench = type("B", (FakeBench,), {"error": bench_error})
    monkeypatch.setattr(pipeline, "ALL_SCANNERS", [FakeTrivy, bench])
    monkeypatch.setattr(cli, "ALL_SCANNERS", [FakeTrivy, bench])
    monkeypatch.setattr(targets, "run_docker", lambda *a: subprocess.CompletedProcess(a, 1, "", ""))


def test_host_check_is_shown_only_on_first_scan(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("CAST_STATE_DIR", str(tmp_path / "st"))
    _patch_engines(monkeypatch)
    cli.main(["scan", "alpine:3.19"])
    first = capsys.readouterr().out
    cli.main(["scan", "alpine:3.19"])
    second = capsys.readouterr().out
    assert "первый запуск" in first and "Настройки Docker-хоста" in first
    assert "первый запуск" not in second and "Настройки Docker-хоста" not in second


def test_host_check_retried_if_it_failed(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("CAST_STATE_DIR", str(tmp_path / "st"))
    _patch_engines(monkeypatch, bench_error="нет доступа к Docker-демону")
    cli.main(["scan", "alpine:3.19"])
    assert not state.host_check_done()


def test_scan_host_marks_and_returns_codes(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("CAST_STATE_DIR", str(tmp_path / "st"))
    _patch_engines(monkeypatch)
    assert cli.main(["scan", "host"]) == 0
    assert state.host_check_done()


def test_cli_errors_and_report_files(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("CAST_STATE_DIR", str(tmp_path / "st"))
    monkeypatch.chdir(tmp_path)
    _patch_engines(monkeypatch)
    assert cli.main(["scan"]) == 2
    assert cli.main(["scan", "host", "-e", "trivy"]) == 2
    assert cli.main(["scan", "alpine:3.19", "-f", "pdf"]) == 2
    assert cli.main(["scan", "alpine:3.19", "-o", "x.txt"]) == 2

    cli.main(["scan", "alpine:3.19", "-f", "json,html"])
    names = sorted(p.suffix for p in tmp_path.glob("cast-image-alpine-3.19-*"))
    assert names == [".html", ".json"]
    cli.main(["scan", "alpine:3.19", "-o", "my.html"])
    assert (tmp_path / "my.html").exists()


def test_cli_engines_and_help(capsys):
    assert cli.main(["engines"]) == 0
    out = capsys.readouterr().out
    assert "trivy" in out and "docker-bench" in out
    assert cli.main([]) == 0
    assert "КОМАНДЫ" in capsys.readouterr().out
    with pytest.raises(SystemExit) as exc:
        cli.main(["-v"])
    assert exc.value.code == 0
