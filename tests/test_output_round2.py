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


def test_whole_file_high_goes_before_line_medium():
    """Вариант А (04.11): места сортируются только по серьёзности, «весь файл» — тоже."""
    data = json.loads(DOCKERFILE)
    misc = data["Results"][0]["Misconfigurations"]
    misc[0]["Severity"] = "MEDIUM"
    misc.append({"ID": "DS-0002", "Title": "Image user should not be 'root'", "Severity": "HIGH",
                 "Message": "Specify at least 1 USER command in Dockerfile with non-root user as argument",
                 "Resolution": "Add 'USER <non root user name>' line to the Dockerfile",
                 "Status": "FAIL", "CauseMetadata": {}})
    scanner = _FakeDockerfile()
    scanner.scan_target = lambda target: scanner._parse(json.dumps(data))
    out = _render(run_scan(Target("dockerfile", "Dockerfile"), scanners=[scanner]), 140)
    assert out.index("весь файл") < out.index("Dockerfile:2")


def test_whole_file_goes_first_at_equal_severity():
    """04.11: при равной серьёзности «весь файл» — первым."""
    data = json.loads(DOCKERFILE)
    data["Results"][0]["Misconfigurations"][1]["Severity"] = "HIGH"
    scanner = _FakeDockerfile()
    scanner.scan_target = lambda target: scanner._parse(json.dumps(data))
    out = _render(run_scan(Target("dockerfile", "Dockerfile"), scanners=[scanner]), 140)
    assert out.index("весь файл") < out.index("Dockerfile:2")


def test_hint_has_no_labels_existing_dim_new_green():
    from cast.report.fix_hint import hint_lines
    fix = console_report.Text()
    console_report._append_hint(fix, hint_lines(
        "KSV-0014", "Change 'containers[].securityContext.readOnlyRootFilesystem' to 'true'.", MSG, CODE_14_17))
    assert "уже есть" not in fix.plain and "добавить" not in fix.plain
    styles = {fix.plain[span.start:span.end].strip(): span.style for span in fix.spans}
    assert styles["securityContext:"] == "dim"
    assert styles["readOnlyRootFilesystem: true"] == "green"


def test_changed_value_is_green_without_current_value_label():
    from cast.report.fix_hint import hint_lines
    fix = console_report.Text()
    console_report._append_hint(fix, hint_lines(
        "KSV-0017", "Change 'containers[].securityContext.privileged' to 'false'.", MSG, CODE_14_17))
    assert "сейчас" not in fix.plain
    styles = {fix.plain[span.start:span.end].strip(): span.style for span in fix.spans}
    assert styles["privileged: false"] == "green"


CODE_14_17 = [{"number": 14, "content": "        - name: web", "is_cause": True},
              {"number": 15, "content": "          image: nginx:1.25", "is_cause": True},
              {"number": 16, "content": "          securityContext:", "is_cause": True},
              {"number": 17, "content": "            privileged: true", "is_cause": True}]
MSG = "Container 'web' of Deployment 'web' should add 'ALL' to 'securityContext.capabilities.drop'"


def test_hint_marks_existing_and_new_lines():
    from cast.report.fix_hint import ADD, EXISTS, hint_lines
    lines = hint_lines("KSV-0003", "Add 'ALL' to containers[].securityContext.capabilities.drop.",
                       MSG, CODE_14_17)
    assert lines == [("containers:", EXISTS, None), ("  - name: web", EXISTS, None),
                     ("    securityContext:", EXISTS, None), ("      capabilities:", ADD, None),
                     ("        drop:", ADD, None), ("          - ALL", ADD, None)]


def test_hint_shows_current_value_and_placeholder():
    from cast.report.fix_hint import ADD, CHANGE, hint_lines
    priv = hint_lines("KSV-0017", "Change 'containers[].securityContext.privileged' to 'false'.",
                      MSG, CODE_14_17)
    assert priv[-1] == ("      privileged: false", CHANGE, "true")
    cpu = hint_lines("KSV-0011", "Set a limit value under 'containers[].resources.limits.cpu'.",
                     MSG, CODE_14_17)
    assert cpu[-1] == ("        cpu: <ваше значение>", ADD, None)   # значение cast не придумывает


def test_hint_without_trivy_code_has_no_marks():
    from cast.report.fix_hint import PLAIN, hint_lines
    lines = hint_lines("KSV-0003", "Add 'ALL' to containers[].securityContext.capabilities.drop.", MSG, [])
    assert {state for _, state, _ in lines} == {PLAIN}
    assert lines[1][0] == "  - name: web"                       # прочерк там же, где в файле
