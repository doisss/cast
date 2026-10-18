"""
Сердце утилиты — оркестрация.

run_scan() не знает деталей Trivy или Docker Bench, она лишь:
1. выбирает движки, которые умеют проверять эту цель (или те, что назвал
   пользователь через -e);
2. опрашивает каждый и собирает находки (уже в единой схеме, см. models.Finding —
   нормализация происходит внутри каждого конкретного Scanner);
3. дедуплицирует (dedup.py);
4. приоритизирует (scoring.py).

Если один движок упал (не установлен, вернул мусор) — это не должно ронять
весь скан: остальные всё равно отработают, а пользователь получит понятное
предупреждение, а не трассировку стека.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field

from cast.context import ScanContext
from cast.dedup import deduplicate
from cast.models import Finding
from cast.scanners import ALL_SCANNERS, ProgressUI, Scanner, ScannerError
from cast.scoring import score_all
from cast.targets import Target


class EngineSelectionError(ValueError):
    """Пользователь выбрал движок (-e), который не существует или не умеет эту цель."""


@dataclass
class ScannerRun:
    """Итог работы одного движка — чтобы отчёт честно говорил, кто что сделал."""

    name: str
    scope: str  # "image" | "environment"
    status: str  # "ok" | "failed" | "missing"
    detail: str = ""
    findings: int = 0
    seconds: float = 0.0
    summary: dict = field(default_factory=dict)  # итог самого движка (у Docker Bench: checks, score)


ProgressCallback = Callable[[str, Scanner, str], None]
"""on_progress(событие, сканер, подробности): событие — "start" | "done" | "fail"."""


@dataclass
class ScanResult:
    image: str
    findings: list[Finding]
    skipped_scanners: list[tuple[str, str]] = field(default_factory=list)
    """[(имя_сканера, причина), ...] — инструменты, которые не отработали."""
    runs: list[ScannerRun] = field(default_factory=list)
    target: Target | None = None

    @property
    def kind(self) -> str:
        return self.target.kind if self.target else "image"

    def scope_of(self, tool: str) -> str:
        for run in self.runs:
            if run.name == tool:
                return run.scope
        return "image"

    def findings_of(self, tool: str) -> list[Finding]:
        return [f for f in self.findings if f.source_tool == tool]

    def findings_in_scope(self, scope: str) -> list[Finding]:
        return [f for f in self.findings if self.scope_of(f.source_tool) == scope]

    @property
    def primary_scope(self) -> str:
        return "environment" if self.kind in ("host", "container") else "image"

    @property
    def image_scan_failed(self) -> bool:
        """True, если НИ ОДИН из главных для этой цели движков не отработал успешно.
        Тогда в отчёте нет ничего по существу запроса (имя оставлено ради
        совместимости: исторически речь шла об образе)."""
        primary = [r for r in self.runs if r.scope == self.primary_scope]
        return bool(primary) and not any(r.status == "ok" for r in primary)

    primary_failed = image_scan_failed

    @property
    def counts_by_severity(self) -> dict[str, int]:
        """Счётчики по уровням критичности — только для находок с уровнем
        (Trivy). Результаты Docker Bench имеют статусы, а не уровни."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
        for finding in self.findings:
            if finding.status is None:
                counts[finding.severity.value] += 1
        return counts

    @property
    def counts_by_status(self) -> dict[str, int]:
        counts = {"WARN": 0, "NOTE": 0, "INFO": 0, "PASS": 0}
        for finding in self.findings:
            if finding.status in counts:
                counts[finding.status] += 1
        return counts


def select_scanners(
    kind: str,
    available: list[Scanner],
    requested: list[str] | None,
) -> list[Scanner]:
    """Какие движки запускать для цели данного типа.
    Без -e — те, у кого этот тип в default_targets; главный (первый в отчёте) —
    тот, чей default_targets содержит тип; остальные идут за ним."""
    by_name = {s.name: s for s in available}
    if requested:
        chosen: list[Scanner] = []
        for name in requested:
            scanner = by_name.get(name)
            if scanner is None:
                raise EngineSelectionError(
                    f"неизвестный движок «{name}». Доступные: {', '.join(by_name)}"
                )
            if kind not in scanner.targets:
                able = [s.name for s in available if kind in s.targets]
                raise EngineSelectionError(
                    f"движок {name} не умеет проверять цель типа «{kind}». "
                    f"Для неё подходят: {', '.join(able) or 'никто'}"
                )
            chosen.append(scanner)
    else:
        chosen = [s for s in available if kind in s.default_targets]
        if not chosen:
            chosen = [s for s in available if kind in s.targets]
    # главные (запускаемые по умолчанию для этой цели) идут первыми
    return sorted(chosen, key=lambda s: kind not in s.default_targets)


def run_scan(
    target: Target | str,
    context: ScanContext | None = None,
    scanners: list[Scanner] | None = None,
    on_progress: ProgressCallback | None = None,
    engines: list[str] | None = None,
    ui: ProgressUI | None = None,
) -> ScanResult:
    """Главная точка входа в логику приложения. CLI (cli.py) — это тонкий
    слой поверх этой функции, что позволяет при желании легко завернуть
    тот же run_scan() в веб-интерфейс (Streamlit) без переписывания логики."""

    if isinstance(target, str):
        target = Target("image", target)
    context = context or ScanContext.empty()
    available: list[Scanner] = scanners if scanners is not None else [
        cls() for cls in ALL_SCANNERS
    ]
    active = select_scanners(target.kind, available, engines)

    raw_findings: list[Finding] = []
    skipped: list[tuple[str, str]] = []
    runs: list[ScannerRun] = []

    def notify(event: str, scanner: Scanner, detail: str = "") -> None:
        if on_progress:
            on_progress(event, scanner, detail)

    for scanner in active:
        scope = getattr(scanner, "scope", "image")
        if not scanner.is_available():
            reason = "инструмент не найден в PATH"
            skipped.append((scanner.name, reason))
            runs.append(ScannerRun(scanner.name, scope, "missing", reason))
            notify("fail", scanner, reason)
            continue
        scanner.ui = ui or ProgressUI()
        notify("start", scanner)
        started = time.monotonic()
        try:
            found = scanner.scan_target(target)
        except ScannerError as exc:
            skipped.append((scanner.name, str(exc)))
            runs.append(
                ScannerRun(scanner.name, scope, "failed", str(exc),
                           seconds=time.monotonic() - started)
            )
            notify("fail", scanner, str(exc))
            continue
        raw_findings.extend(found)
        elapsed = time.monotonic() - started
        runs.append(ScannerRun(scanner.name, scope, "ok", "", len(found), elapsed,
                               dict(getattr(scanner, "summary", {}) or {})))
        notify("done", scanner, f"{len(found)}")

    deduped = deduplicate(raw_findings)
    prioritized = score_all(deduped, context)

    return ScanResult(
        image=target.label, findings=prioritized, skipped_scanners=skipped,
        runs=runs, target=target,
    )
