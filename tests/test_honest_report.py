from io import StringIO

from rich.console import Console

from cast.models import Finding, Severity
from cast.pipeline import run_scan
from cast.report import console as console_report
from cast.scanners.base import Scanner, ScannerError
from cast.scanners.trivy import _explain_failure


class Fake(Scanner):
    def __init__(self, name, scope, findings=None, error=None):
        self.name, self.scope = name, scope
        self._f, self._e = findings or [], error

    def is_available(self):
        return True

    def scan_image(self, image):
        if self._e:
            raise ScannerError(self._e)
        return self._f


def _f(tool, cid, sev=Severity.HIGH, pkg=None):
    return Finding(source_tool=tool, check_id=cid, title="t", severity=sev, package=pkg)


def _render(result):
    buf = StringIO()
    console_report.render(result, console=Console(file=buf, width=140, force_terminal=False))
    return buf.getvalue()


def test_failed_image_engine_is_reported_honestly():
    result = run_scan("nginx", scanners=[
        Fake("trivy", "image", error="на диске закончилось место"),
        Fake("docker-bench", "environment", [_f("docker-bench", "4.1")]),
    ])
    assert result.image_scan_failed
    out = _render(result)
    assert "Сканирование образа НЕ выполнена" in out
    assert "на диске закончилось место" in out
    assert "Уязвимости образа" not in out          # никакой подмены результатов
    

def test_ok_image_engine_and_environment_are_separate_sections():
    result = run_scan("alpine:3.12", scanners=[
        Fake("trivy", "image", [_f("trivy", "CVE-1", pkg="zlib")]),
        Fake("docker-bench", "environment", [_f("docker-bench", "4.1")]),
    ])
    assert not result.image_scan_failed
    assert [f.check_id for f in result.findings_in_scope("image")] == ["CVE-1"]
    assert [f.check_id for f in result.findings_in_scope("environment")] == ["4.1"]
    out = _render(result)
    assert "Уязвимости образа alpine:3.12" in out
    assert "Настройки Docker-хоста" in out


def test_progress_callback_events():
    events = []
    run_scan("x", scanners=[Fake("a", "image"), Fake("b", "image", error="boom")],
             on_progress=lambda e, s, d="": events.append((e, s.name)))
    assert events == [("start", "a"), ("done", "a"), ("start", "b"), ("fail", "b")]


def test_explain_failure_disk_cache_and_reference():
    assert "место" in _explain_failure(1, "write x: no space left on device")
    assert "занят" in _explain_failure(1, "cache may be in use by another process: timeout")
    assert "некорректное имя" in _explain_failure(1, "could not parse reference: Dockerfile")
