"""Вывод Docker Bench по разделам CIS (вариант A): разделы, пометки, PASS строкой, Score."""
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

from rich.console import Console

from cast.models import Finding, Severity
from cast.report.console import _CONTAINER_BENCH_NOTE, _print_section, _print_status_table, _status_line
from cast.report.sections import Section, sort_status_findings
from cast.scanners.docker_bench import DockerBenchScanner

FULL = Path(__file__).parent / "fixtures" / "bench_full.txt"


def _f(check_id, status, **kw):
    return Finding(source_tool="docker-bench", check_id=check_id, title=f"check {check_id}",
                   severity=Severity.UNKNOWN, status=status, **kw)


def _out(findings, top=0, width=120):
    c = Console(file=StringIO(), width=width)
    _print_status_table(c, sort_status_findings(findings), top)
    return c.file.getvalue()


def test_parser_keeps_section_and_marks():
    raw = (
        "[INFO] 2 - Docker daemon configuration\n"
        "[NOTE] 2.1 - Run the Docker daemon as a non-root user, if possible (Manual)\n"
        "[INFO] Ensure that experimental features are not implemented in production (Scored) (Deprecated)\n"
        "[INFO] 7 - Docker Swarm Configuration\n"
        "[PASS] 7.1 - Ensure swarm managers (Automated) (Swarm mode not enabled)\n"
    )
    found = DockerBenchScanner()._parse(raw)
    assert [(f.check_id, f.section, f.marks) for f in found] == [
        ("2.1", "2", ["Manual"]),
        ("—", "2", ["Scored", "Deprecated"]),   # без номера — раздел из заголовка
        ("7.1", "7", ["Automated", "Swarm mode not enabled"]),
    ]
    assert found[1].title == "Ensure that experimental features are not implemented in production"


def test_real_output_all_checks_get_a_section():
    found = DockerBenchScanner()._parse(FULL.read_text())
    assert len(found) == 117 and all(f.section in "1234567" for f in found)


def test_sections_headers_pass_line_and_marks():
    out = _out([
        _f("1.2.1", "NOTE", section="1", marks=["Manual"]),
        _f("2.2", "WARN", section="2", marks=["Scored"], remediation="set icc false"),
        _f("—", "INFO", section="2", marks=["Scored", "Deprecated"]),
        _f("2.3", "PASS", section="2"),
        _f("7.1", "PASS", section="7"),
    ])
    assert "▌ 1. Хост" in out and "▌ 2. Настройки демона Docker" in out and "▌ 7. Docker Swarm" in out
    assert out.index("▌ 1.") < out.index("▌ 2.") < out.index("▌ 7.")
    assert "(ручная)" in out and "(устаревшая)" in out and "Scored" not in out
    assert "PASS: 2.3" in out and "PASS: 7.1" in out
    assert "check 2.3" not in out           # PASS не занимает строк таблицы
    assert "К чему относится" not in out


def test_each_object_on_its_own_line():
    out = _out([_f("4.6", "WARN", section="4", details=["No Healthcheck found: [a:1]", "No Healthcheck found: [b:2]"])])
    assert "• No Healthcheck found: [a:1]" in out and "• No Healthcheck found: [b:2]" in out
    assert ";" not in out.split("▌")[1].split("WARN —")[0]


def test_top_limits_rows_per_section_and_says_so():
    out = _out([_f(f"5.{i}", "WARN", section="5") for i in range(1, 6)], top=2)
    assert "check 5.2" in out and "check 5.3" not in out
    assert "скрыто --top: 3" in out


def test_score_is_explained_with_docker_bench_numbers():
    sec = Section(tool="docker-bench", title="t", kind="status", findings=[], seconds=1.0,
                  summary={"checks": 3, "score": 9})
    text = _status_line([_f("1", "PASS"), _f("2", "WARN"), _f("3", "INFO")], sec).plain
    assert "Score: 9" in text
    assert "+1 за каждый зачётный PASS (10)" in text and "−1 за каждый WARN (1)" in text


def test_container_scan_says_which_checks_ran():
    findings = [_f("4.1", "WARN", section="4"), _f("5.1", "PASS", section="5")]
    sec = Section(tool="docker-bench", title="t", kind="status", findings=findings, seconds=1.0,
                  summary={"checks": 2, "score": 0})
    for kind, expected in (("container", True), ("host", False)):
        c = Console(file=StringIO(), width=200)
        _print_section(c, SimpleNamespace(kind=kind), sec, 0)
        assert ("check_4_1,container_runtime" in c.file.getvalue()) is expected
    assert "4.1" in _CONTAINER_BENCH_NOTE
