"""
Дедупликация: если одну и ту же проблему нашли два разных сканера
(например, и Trivy и ещё какой-то добавленный позже инструмент нашли
одну CVE в одном пакете), в итоговом отчёте должна остаться одна запись,
а не две. Ключ объединения — Finding.dedup_key() (см. models.py).
"""

from __future__ import annotations

from cast.models import Finding


def deduplicate(findings: list[Finding]) -> list[Finding]:
    merged: dict[tuple[str, str | None], Finding] = {}

    for finding in findings:
        key = finding.dedup_key()
        existing = merged.get(key)

        if existing is None:
            finding.confirmed_by = [finding.source_tool]
            merged[key] = finding
            continue

        # уже видели такую находку — объединяем список инструментов-подтверждений
        if finding.source_tool not in existing.confirmed_by:
            existing.confirmed_by.append(finding.source_tool)

        # если новая запись содержит более высокую критичность — берём её данные
        # (разные сканеры иногда расходятся в оценке severity одной и той же CVE)
        if finding.severity.rank > existing.severity.rank:
            confirmed_by = existing.confirmed_by
            merged[key] = finding
            merged[key].confirmed_by = confirmed_by

    return list(merged.values())
