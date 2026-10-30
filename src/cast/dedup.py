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

        # одна CVE в одном пакете, но в разных файлах (одна библиотека Go в семи
        # программах) — строка одна, но в «Где» остаются все места, ни одно не теряется
        locations = _locations(existing) + [loc for loc in _locations(finding)
                                            if loc not in _locations(existing)]

        # если новая запись содержит более высокую критичность — берём её данные
        # (разные сканеры иногда расходятся в оценке severity одной и той же CVE)
        if finding.severity.rank > existing.severity.rank:
            confirmed_by = existing.confirmed_by
            merged[key] = finding
            merged[key].confirmed_by = confirmed_by
        merged[key].location = "; ".join(locations) or None

    return list(merged.values())


def _locations(finding: Finding) -> list[str]:
    return [loc for loc in (finding.location or "").split("; ") if loc]
