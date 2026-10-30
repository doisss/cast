"""
Дедупликация: если одну и ту же проблему нашли два разных сканера
(например, и Trivy и ещё какой-то добавленный позже инструмент нашли
одну CVE в одном пакете), в итоговом отчёте должна остаться одна запись,
а не две. Ключ объединения — Finding.dedup_key() (см. models.py).
Записи ОДНОГО сканера не склеиваются никогда: отчёт показывает ровно столько
строк, сколько вернул сам сканер (одна CVE в семи файлах — семь строк).
"""

from __future__ import annotations

from cast.models import Finding


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Склеиваются только находки РАЗНЫХ сканеров. Записи одного сканера остаются
    как есть: одна CVE одной библиотеки Go в семи программах — семь строк, по строке
    на файл, ровно столько, сколько вернул сам сканер."""
    merged: dict[tuple[str, str | None], list[Finding]] = {}
    result: list[Finding] = []

    for finding in findings:
        key = finding.dedup_key()
        candidates = merged.setdefault(key, [])
        # запись другого сканера, к которой этот сканер ещё не присоединялся
        existing = next((f for f in candidates if finding.source_tool not in f.confirmed_by), None)

        if existing is None:
            finding.confirmed_by = [finding.source_tool]
            candidates.append(finding)
            result.append(finding)
            continue

        # уже видели такую находку у другого сканера — объединяем список подтверждений
        existing.confirmed_by.append(finding.source_tool)

        # если новая запись содержит более высокую критичность — берём её данные
        # (разные сканеры иногда расходятся в оценке severity одной и той же CVE)
        if finding.severity.rank > existing.severity.rank:
            finding.confirmed_by = existing.confirmed_by
            candidates[candidates.index(existing)] = finding
            result[result.index(existing)] = finding

    return result
