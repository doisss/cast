from cast.context import ScanContext
from cast.models import Finding, Severity
from cast.pipeline import run_scan
from cast.scanners.base import Scanner, ScannerError


class FakeScanner(Scanner):
    """Тестовый двойник: не вызывает subprocess, просто отдаёт заранее
    заданный список находок — так мы проверяем оркестрацию, дедупликацию
    и скоринг в связке, не завися от того, установлен ли Trivy в CI."""

    def __init__(self, name, findings=None, available=True, error=None):
        self.name = name
        self._findings = findings or []
        self._available = available
        self._error = error

    def is_available(self) -> bool:
        return self._available

    def scan_image(self, image: str) -> list[Finding]:
        if self._error:
            raise ScannerError(self._error)
        return self._findings


def _finding(source, check_id, package, severity, pkg_type="python-pkg"):
    return Finding(
        source_tool=source,
        check_id=check_id,
        title="t",
        severity=severity,
        package=package,
        pkg_type=pkg_type,
    )


def test_run_scan_merges_findings_from_multiple_scanners():
    scanner_a = FakeScanner(
        "trivy",
        findings=[_finding("trivy", "CVE-1", "pkg-a", Severity.HIGH)],
    )
    scanner_b = FakeScanner(
        "docker-bench",
        findings=[_finding("docker-bench", "CVE-1", "pkg-a", Severity.HIGH)],
    )

    result = run_scan("myapp:1.0", scanners=[scanner_a, scanner_b])

    assert len(result.findings) == 1  # дедуплицировано
    assert set(result.findings[0].confirmed_by) == {"trivy", "docker-bench"}
    assert result.skipped_scanners == []


def test_run_scan_skips_unavailable_scanner_without_crashing():
    available = FakeScanner("trivy", findings=[_finding("trivy", "CVE-1", "pkg-a", Severity.LOW)])
    unavailable = FakeScanner("docker-bench", available=False)

    result = run_scan("myapp:1.0", scanners=[available, unavailable])

    assert len(result.findings) == 1
    assert result.skipped_scanners == [("docker-bench", "инструмент не найден в PATH")]


def test_run_scan_continues_after_scanner_error():
    broken = FakeScanner("trivy", error="trivy упал с кодом 1")
    working = FakeScanner(
        "docker-bench", findings=[_finding("docker-bench", "4.1", None, Severity.HIGH)]
    )

    result = run_scan("myapp:1.0", scanners=[broken, working])

    assert len(result.findings) == 1
    assert result.skipped_scanners == [("trivy", "trivy упал с кодом 1")]


def test_run_scan_applies_context_scoring():
    finding = _finding("trivy", "CVE-1", "requests", Severity.HIGH)
    scanner = FakeScanner("trivy", findings=[finding])
    context = ScanContext(used_packages={"requests"})

    result = run_scan("myapp:1.0", context=context, scanners=[scanner])

    assert result.findings[0].priority_score > Severity.HIGH.rank
