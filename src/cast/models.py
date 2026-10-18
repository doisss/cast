"""
Единая модель данных для находок.

Это и есть "нормализация": какой бы сканер ни отработал (Trivy, Docker Bench,
в будущем — ещё что-то), на выходе он обязан отдать список объектов Finding.
Весь остальной код (дедупликация, скоринг, рендер отчётов) работает только
с этой структурой и ничего не знает о том, что было "под капотом".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Единая шкала критичности. Разные сканеры называют одно и то же по-разному
    (CRITICAL/HIGH/WARN/PASS и т.д.) — здесь всё приводится к одному словарю."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        """Числовой вес для сортировки и для базового скоринга."""
        return {
            Severity.CRITICAL: 90,
            Severity.HIGH: 70,
            Severity.MEDIUM: 40,
            Severity.LOW: 10,
            Severity.UNKNOWN: 20,
        }[self]

    @classmethod
    def from_trivy(cls, value: str) -> "Severity":
        return {
            "CRITICAL": cls.CRITICAL,
            "HIGH": cls.HIGH,
            "MEDIUM": cls.MEDIUM,
            "LOW": cls.LOW,
        }.get((value or "").upper(), cls.UNKNOWN)

    @classmethod
    def from_docker_bench(cls, value: str) -> "Severity":
        # Docker Bench не оперирует CVSS-уровнями, а статусами проверок.
        # WARN считаем HIGH (это нарушение best practice), INFO — LOW, PASS не попадает
        # в находки вообще (это не проблема, а подтверждение, что всё ок).
        return {
            "WARN": cls.HIGH,
            "NOTE": cls.MEDIUM,
            "INFO": cls.LOW,
        }.get((value or "").upper(), cls.UNKNOWN)


@dataclass
class Finding:
    """Одна находка в единой схеме — то, о чём мы договаривались:
    {cve_id, severity, package, description, layer, source_tool}
    (здесь cve_id обобщён до check_id, т.к. у Docker Bench нет CVE,
    а есть номер проверки CIS, вроде "4.1")."""

    source_tool: str          # "trivy" | "docker-bench"
    check_id: str              # "CVE-2024-3094" или "4.1"
    title: str
    severity: Severity
    description: str = ""
    package: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    layer: str | None = None
    # Тип пакета по классификации сканера, напр. "python-pkg", "debian", "alpine".
    # Нужен приоритизации: requirements.txt описывает только Python-зависимости,
    # поэтому судить по нему можно лишь о Python-пакетах, но не о системных.
    pkg_type: str | None = None

    # Статус проверки у движков, которые выдают не CVE, а результат проверки
    # настроек (Docker Bench): PASS / WARN / INFO / NOTE. У находок Trivy None —
    # у них вместо статуса уровень критичности (severity).
    status: str | None = None
    # Пояснения "к чему именно относится замечание": имена контейнеров, значения и т.п.
    details: list[str] = field(default_factory=list)

    # Где найдено (файл или файл:строка) — у находок в папках, Dockerfile, секретов.
    location: str | None = None
    # Что сделать, чтобы исправить (у Trivy — Resolution, у Docker Bench — remediation).
    remediation: str | None = None
    remediation_impact: str | None = None   # чем грозит исправление (Docker Bench)
    # Страница с описанием (у Trivy — PrimaryURL).
    url: str | None = None
    # Статус исправления уязвимости у Trivy: fixed / affected / will_not_fix / ...
    # (fixed = вендор выпустил исправление, а не «у вас исправлено»).
    fix_status: str | None = None

    # сюда попадают source_tool всех инструментов, которые нашли ТУ ЖЕ находку
    # после дедупликации (например ["trivy", "docker-bench"])
    confirmed_by: list[str] = field(default_factory=list)

    # заполняется на этапе приоритизации, см. scoring.py
    priority_score: int = 0
    priority_reasons: list[str] = field(default_factory=list)

    def dedup_key(self) -> tuple[str, str | None]:
        """По этому ключу находки считаются одинаковыми: один и тот же check_id
        в одном и том же пакете, независимо от того, какой инструмент его нашёл."""
        pkg = (self.package or "").lower()
        if not pkg and self.status is None and self.location:
            # находки без пакета (ошибки конфигурации, секреты) различаем по месту,
            # иначе одно и то же правило в двух файлах слилось бы в одну запись
            pkg = self.location.lower()
        return (self.check_id.upper(), pkg)

    def to_dict(self) -> dict:
        return {
            "source_tool": self.source_tool,
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "package": self.package,
            "installed_version": self.installed_version,
            "fixed_version": self.fixed_version,
            "layer": self.layer,
            "pkg_type": self.pkg_type,
            "status": self.status,
            "details": self.details,
            "location": self.location,
            "remediation": self.remediation,
            "remediation_impact": self.remediation_impact,
            "url": self.url,
            "fix_status": self.fix_status,
            "confirmed_by": self.confirmed_by,
            "priority_score": self.priority_score,
            "priority_reasons": self.priority_reasons,
        }
