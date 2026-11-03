"""Вывод после второго круга замечаний: ширина таблиц, склейка CVE, Dockerfile по строкам."""

import json
from io import StringIO

import pytest
from rich.console import Console

from cast.models import Finding, Severity
from cast.pipeline import ScanResult, ScannerRun, run_scan
from cast.report import console as console_report
from cast.scanners.trivy import TrivyScanner
from cast.targets import Target


def _vuln(cve, pkg, inst="1.2.4_git20230717-r5", fixed="1.2.4_git20230717-r6", where=None):
    f = Finding("trivy", cve, "musl libc: arbitrary code execution via stack-based memory corruption",
                Severity.HIGH, package=pkg, installed_version=inst, fixed_version=fixed,
                location=where, url=f"https://avd.aquasec.com/nvd/{cve.lower()}")
    f.confirmed_by = ["trivy"]
    return f


def _render(result, width):
    buf = StringIO()
    console_report.render(result, console=Console(file=buf, width=width, force_terminal=False))
    return buf.getvalue()


def _fs_result():
    findings = [_vuln("CVE-2026-40200", "musl", where="requirements.txt"),
                _vuln("CVE-2026-40200", "musl-utils", where="requirements.txt"),
                _vuln("CVE-2019-14234", "django", "2.2.0", "1.11.23, 2.1.11, 2.2.4", "requirements.txt")]
    return ScanResult(image=".", findings=findings, target=Target("fs", "."),
                      runs=[ScannerRun("trivy", "image", "ok", "", 3, 1.0)])


@pytest.mark.parametrize("width", [80, 100, 110, 120, 160])
def test_vuln_table_fits_window_and_keeps_all_columns(width):
    out = _render(_fs_result(), width)
    assert max(len(line) for line in out.splitlines()) <= width
    header = next(line for line in out.splitlines() if "ID" in line and "Пакет" in line)
    assert "Название" in out and "Установ" in out and "Исправ" in out
    assert header.rstrip().endswith("┃")            # правая рамка на месте, ничего не отрезано
    assert "Приоритет" not in out and "Источник" not in out
    # «Где» колонкой в широком окне, строкой под названием в узком
    assert ("Где:" in out) == (width < 110)


def test_same_cve_in_sibling_packages_is_one_row():
    out = _render(_fs_result(), 160)
    assert out.count("CVE-2026-40200") == 1 and out.count("cve-2026-40200") == 1   # одна строка таблицы
    assert "musl-utils" in out
    assert ": 3 " in out                              # счётчик в заголовке — как у Trivy


def test_different_versions_are_not_merged():
    findings = [_vuln("CVE-1", "a"), _vuln("CVE-1", "b", inst="9")]
    result = ScanResult(image="x", findings=findings, target=Target("image", "x"),
                        runs=[ScannerRun("trivy", "image", "ok", "", 2, 1.0)])
    assert _render(result, 160).count("https://avd.aquasec.com/nvd/cve-1") == 2


DOCKERFILE = json.dumps({"Results": [{"Target": "Dockerfile", "Class": "config", "Misconfigurations": [
    {"ID": "DS-0029", "Title": "'apt-get' missing '--no-install-recommends'", "Severity": "HIGH",
     "Message": "'--no-install-recommends' flag is missed: 'apt-get update && apt-get install -y curl'",
     "Resolution": "Add '--no-install-recommends' flag to 'apt-get'", "Status": "FAIL",
     "CauseMetadata": {"StartLine": 2, "EndLine": 2, "Code": {"Lines": [
         {"Number": 2, "Content": "RUN apt-get update && apt-get install -y curl", "IsCause": True}]}}},
    {"ID": "DS-0026", "Title": "No HEALTHCHECK defined", "Severity": "LOW",
     "Message": "Add HEALTHCHECK instruction in your Dockerfile",
     "Resolution": "Add HEALTHCHECK instruction in Dockerfile", "Status": "FAIL", "CauseMetadata": {}},
]}]})


class _FakeDockerfile(TrivyScanner):
    def is_available(self):
        return True

    def scan_target(self, target):
        return self._parse(DOCKERFILE)


def test_dockerfile_grouped_by_line_with_trivy_message():
    result = run_scan(Target("dockerfile", "Dockerfile"), scanners=[_FakeDockerfile()])
    out = _render(result, 140)
    assert "▌ Dockerfile:2  1 шт." in out
    assert "2 [ RUN apt-get update" in out           # одна строка-причина — как у Trivy
    assert "flag is missed" in out                   # Message Trivy: что именно не так в этом файле
    assert "▌ Dockerfile — весь файл" in out
    assert out.index("Dockerfile:2") < out.index("весь файл")
    assert "in your Dockerfile" not in out           # Message, повторяющий совет, не дублируем
    assert json.loads(json.dumps(result.findings[0].to_dict()))["message"]


def test_engines_lists_other_copies_once(tmp_path, monkeypatch):
    from cast.utils import find_all_binaries
    a, b, c = (tmp_path / n for n in ("a", "b", "c"))
    for d in (a, b, c):
        d.mkdir()
    (a / "trivy").write_text("#!/bin/sh\n")
    (a / "trivy").chmod(0o755)
    (b / "trivy").symlink_to(a / "trivy")            # ссылка на ту же программу — не копия
    (c / "trivy").write_text("#!/bin/sh\n")
    (c / "trivy").chmod(0o755)
    monkeypatch.setenv("PATH", f"{a}:{b}:{c}")
    assert find_all_binaries("trivy") == [str(a / "trivy"), str(c / "trivy")]
