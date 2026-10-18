"""
Приоритизация находок.

Это ключевая часть работы, которую не делает ни Trivy, ни Docker Bench сами
по себе: они отдают голый CVSS/статус проверки, а здесь мы пересчитываем
итоговый приоритет с учётом контекста конкретного приложения.

Формула намеренно простая и прозрачная (это MVP, не ML-модель) — каждое
изменение балла сопровождается понятной причиной в priority_reasons,
чтобы пользователь в консоли/HTML видел не только число, но и ПОЧЕМУ
оно такое.
"""

from __future__ import annotations

from cast.context import ScanContext
from cast.models import Finding

USED_PACKAGE_BONUS = 15
UNUSED_PACKAGE_PENALTY = 20
CONFIRMED_BY_MULTIPLE_BONUS = 10

# Типы пакетов (поле Type в выводе Trivy), о которых может судить requirements.txt.
# Системные пакеты (debian, alpine, ...) сюда НЕ входят: их отсутствие в
# requirements.txt ничего не говорит о том, используются они или нет.
PYTHON_PKG_TYPES = {"python-pkg", "pip", "pipenv", "poetry", "uv", "conda-pkg"}


def score_finding(finding: Finding, context: ScanContext) -> None:
    """Мутирует finding: проставляет priority_score и priority_reasons.
    Мутация, а не возврат нового объекта — осознанный выбор ради простоты
    вызова в цикле пайплайна (см. pipeline.py)."""

    if finding.status is not None:
        # Результат проверки настроек (PASS/WARN/INFO/NOTE) — не уязвимость,
        # уровни и баллы к нему не применяются.
        finding.priority_score = 0
        finding.priority_reasons = []
        return

    score = finding.severity.rank
    reasons = [f"базовая критичность {finding.severity.value} ({finding.severity.rank})"]

    if finding.package and finding.pkg_type in PYTHON_PKG_TYPES:
        if context.is_used(finding.package):
            score += USED_PACKAGE_BONUS
            reasons.append(
                f"+{USED_PACKAGE_BONUS}: пакет '{finding.package}' используется "
                "приложением (найден в зависимостях)"
            )
        elif context.used_packages:
            # контекст известен (requirements.txt передан), но пакета там нет —
            # штрафуем. Если контекст пустой (--requirements не передали), штраф
            # не применяем: мы просто не знаем, используется пакет или нет.
            score -= UNUSED_PACKAGE_PENALTY
            reasons.append(
                f"-{UNUSED_PACKAGE_PENALTY}: пакет '{finding.package}' не найден "
                "среди используемых зависимостей"
            )

    if len(finding.confirmed_by) > 1:
        score += CONFIRMED_BY_MULTIPLE_BONUS
        tools = ", ".join(finding.confirmed_by)
        reasons.append(
            f"+{CONFIRMED_BY_MULTIPLE_BONUS}: находка подтверждена несколькими "
            f"инструментами ({tools})"
        )

    finding.priority_score = max(score, 0)
    finding.priority_reasons = reasons


def score_all(findings: list[Finding], context: ScanContext) -> list[Finding]:
    for finding in findings:
        score_finding(finding, context)
    # сортировка по убыванию приоритета; при равенстве — по алфавиту check_id
    # для стабильного, воспроизводимого порядка в отчётах
    return sorted(findings, key=lambda f: (-f.priority_score, f.check_id))
