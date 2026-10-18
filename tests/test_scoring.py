from cast.context import ScanContext
from cast.models import Finding, Severity
from cast.scoring import score_all, score_finding


def _finding(package="requests", severity=Severity.HIGH, pkg_type="python-pkg"):
    return Finding(
        source_tool="trivy",
        check_id="CVE-2024-0001",
        title="t",
        severity=severity,
        package=package,
        pkg_type=pkg_type,
    )


def test_used_package_gets_bonus():
    context = ScanContext(used_packages={"requests"})
    finding = _finding(package="requests")

    score_finding(finding, context)

    assert finding.priority_score > finding.severity.rank
    assert any("используется" in r for r in finding.priority_reasons)


def test_unused_python_package_gets_penalty_only_if_context_known():
    context = ScanContext(used_packages={"flask"})  # requests отсутствует
    finding = _finding(package="requests")

    score_finding(finding, context)

    assert finding.priority_score < finding.severity.rank


def test_no_context_means_no_penalty():
    # --requirements не передан -> used_packages пустой -> штраф не применяется,
    # потому что мы просто не знаем, используется пакет или нет
    finding = _finding(package="requests")

    score_finding(finding, ScanContext.empty())

    assert finding.priority_score == finding.severity.rank


def test_os_package_is_never_judged_by_requirements_txt():
    # Регрессия из реального прогона: perl-base/openssl/libc6 получали штраф
    # "не используется", хотя requirements.txt описывает только Python-пакеты.
    context = ScanContext(used_packages={"requests", "flask"})
    finding = _finding(package="perl-base", severity=Severity.CRITICAL, pkg_type="debian")

    score_finding(finding, context)

    assert finding.priority_score == Severity.CRITICAL.rank
    assert not any("не найден" in r for r in finding.priority_reasons)


def test_unknown_package_type_is_not_judged_either():
    context = ScanContext(used_packages={"requests"})
    finding = _finding(package="whatever", pkg_type=None)

    score_finding(finding, context)

    assert finding.priority_score == finding.severity.rank


def test_package_name_matching_follows_pep503():
    context = ScanContext(used_packages={"typing-extensions"})
    finding = _finding(package="typing_extensions")

    score_finding(finding, context)

    assert finding.priority_score > finding.severity.rank


def test_confirmed_by_multiple_tools_gets_bonus():
    finding = _finding(package=None, severity=Severity.MEDIUM, pkg_type=None)
    finding.confirmed_by = ["trivy", "docker-bench"]

    score_finding(finding, ScanContext.empty())

    assert finding.priority_score == Severity.MEDIUM.rank + 10


def test_score_all_sorts_by_priority_descending():
    low_priority = _finding(package="unused-pkg", severity=Severity.LOW)
    high_priority = _finding(package="requests", severity=Severity.CRITICAL)
    context = ScanContext(used_packages={"requests"})

    result = score_all([low_priority, high_priority], context)

    assert result[0] is high_priority
    assert result[0].priority_score >= result[1].priority_score
