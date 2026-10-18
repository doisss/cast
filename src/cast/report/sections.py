"""
Общая логика для всех отчётов (консоль / JSON / HTML): из каких разделов
состоит отчёт и как они называются. Раздел = один движок, который отработал;
главный движок для цели идёт первым (так их упорядочил pipeline).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cast.models import Finding
from cast.pipeline import ScanResult

STATUS_ORDER = {"WARN": 0, "NOTE": 1, "INFO": 2, "PASS": 3}
STATUS_HELP = {
    "WARN": "нарушение рекомендации",
    "NOTE": "нужно принять решение вручную",
    "INFO": "информация / проверить вручную",
    "PASS": "в порядке",
}


@dataclass
class Section:
    tool: str
    title: str
    kind: str                  # "status" (Docker Bench) | "severity" (Trivy)
    findings: list[Finding]
    note: str = ""
    seconds: float = 0.0
    summary: dict = field(default_factory=dict)  # итог движка: checks, score
    extra: str = ""          # пометка в скобках после движка, напр. стандарт проверки


def _natural(check_id: str) -> tuple:
    return tuple(int(p) if p.isdigit() else 0 for p in check_id.split("."))


def sort_status_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (STATUS_ORDER.get(f.status or "", 9), _natural(f.check_id)))


def section_title(result: ScanResult, tool: str, scope: str) -> str:
    """Название раздела без имени движка и времени — их дописывает отчёт."""
    target = result.target
    kind = result.kind
    if scope == "environment":
        if kind == "container":
            name = target.container_name or target.value
            who = name if target.value in (name, "") else f"{name} (ID {target.value})"
            return f"Настройки запуска контейнера {who}"
        return "Настройки Docker-хоста"
    if kind == "fs":
        return f"Проблемы в папке {target.value}"
    if kind == "dockerfile":
        return f"Проверка Dockerfile {target.value}"
    if kind == "container":
        return f"Уязвимости образа контейнера {target.container_name}, образ {target.image_name}"
    return f"Уязвимости образа {target.value if target else result.image}"


def build_sections(result: ScanResult) -> list[Section]:
    sections: list[Section] = []
    for run in result.runs:
        if run.status != "ok":
            continue
        findings = result.findings_of(run.name)
        if run.scope == "environment":
            sections.append(Section(run.name, section_title(result, run.name, run.scope),
                                    "status", sort_status_findings(findings),
                                    seconds=run.seconds, extra="CIS Docker Benchmark",
                                    summary=run.summary))
        else:
            sections.append(Section(run.name, section_title(result, run.name, run.scope),
                                    "severity", findings, seconds=run.seconds))
    return sections


def container_image_note(result: ScanResult) -> str:
    """Для контейнера, проверенного только Docker Bench: честная пометка, что
    уязвимости внутри образа не проверялись."""
    if result.kind != "container":
        return ""
    if any(r.name == "trivy" and r.status == "ok" for r in result.runs):
        return ""
    image = result.target.image_name or "имя_образа"
    return (
        "Проверено только то, как запущен контейнер (Docker Bench), содержимое не смотрели. "
        "Уязвимые пакеты внутри образа не проверялись. Чтобы проверить, выполните одну из команд:\n"
        f"  cast scan {image}\n"
        f"  cast scan {result.target.value} -e trivy"
    )
