from cast.dedup import deduplicate
from cast.models import Finding, Severity


def _finding(source, check_id="CVE-2024-3094", package="xz-utils", severity=Severity.HIGH):
    return Finding(
        source_tool=source,
        check_id=check_id,
        title="t",
        severity=severity,
        package=package,
    )


def test_same_cve_from_two_tools_is_merged_into_one():
    findings = [
        _finding("trivy"),
        _finding("docker-bench"),
    ]
    result = deduplicate(findings)

    assert len(result) == 1
    assert set(result[0].confirmed_by) == {"trivy", "docker-bench"}


def test_different_packages_are_not_merged():
    findings = [
        _finding("trivy", package="xz-utils"),
        _finding("trivy", package="openssl"),
    ]
    result = deduplicate(findings)
    assert len(result) == 2


def test_highest_severity_wins_on_merge():
    findings = [
        _finding("trivy", severity=Severity.MEDIUM),
        _finding("docker-bench", severity=Severity.CRITICAL),
    ]
    result = deduplicate(findings)

    assert len(result) == 1
    assert result[0].severity == Severity.CRITICAL
    # confirmed_by должен сохраниться несмотря на замену записи
    assert set(result[0].confirmed_by) == {"trivy", "docker-bench"}


def test_case_insensitive_dedup_key():
    findings = [
        _finding("trivy", check_id="cve-2024-3094", package="XZ-Utils"),
        _finding("docker-bench", check_id="CVE-2024-3094", package="xz-utils"),
    ]
    result = deduplicate(findings)
    assert len(result) == 1


def test_same_scanner_findings_are_never_merged():
    # одна CVE в одном пакете в трёх файлах (и даже дважды в одном) — столько строк,
    # сколько записей вернул сканер
    def vuln(where):
        return Finding("trivy", "CVE-1", "t", Severity.HIGH, package="stdlib", location=where)

    result = deduplicate([vuln("usr/bin/a"), vuln("usr/bin/b"), vuln("usr/bin/a")])
    assert [f.location for f in result] == ["usr/bin/a", "usr/bin/b", "usr/bin/a"]
    assert all(f.confirmed_by == ["trivy"] for f in result)


def test_other_scanner_confirms_one_row_and_order_is_kept():
    findings = [_finding("trivy"), _finding("trivy"), _finding("docker-bench"),
                _finding("trivy", package="zlib")]
    result = deduplicate(findings)
    assert len(result) == 3
    assert result[0].confirmed_by == ["trivy", "docker-bench"]
    assert result[1].confirmed_by == ["trivy"]
    assert result[2].package == "zlib"
