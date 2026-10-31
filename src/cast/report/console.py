"""
Рендер для терминала — то, что видит человек сразу после запуска cast scan.
Используем rich: цвета, таблица, не нужно руками считать отступы под юникод.

Отчёт честно разделён по движкам: у каждого свой раздел со своим названием.
Результаты Docker Bench показываются со статусами PASS/WARN/INFO/NOTE как есть
(уровней критичности у него нет), результаты Trivy — с уровнями критичности.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cast.pipeline import ScanResult
from cast.report.fix_hint import yaml_hint
from cast.report.sections import STATUS_HELP, Section, build_sections, container_image_note

_SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "white",
    "unknown": "dim",
}

_SEVERITY_ICON = {
    "critical": "\U0001F534",  # 🔴
    "high": "\U0001F7E0",      # 🟠
    "medium": "\U0001F7E1",    # 🟡
    "low": "⚪",           # ⚪
    "unknown": "❓",       # ❓
}

_STATUS_STYLE = {"WARN": "bold red", "NOTE": "yellow", "INFO": "cyan", "PASS": "green"}

# цели, где важно, в каком файле или ресурсе найдено (у образа место одно — сам образ)
_SHOW_WHERE = ("fs", "dockerfile", "config", "rootfs", "repo", "vm", "cluster")

_SCOPE_LABEL = {"image": "уязвимости и проблемы", "environment": "настройки Docker"}


def _heading(section: Section) -> Text:
    """«✓ Уязвимости образа alpine (trivy, 3 с)» — что проверено, чем и за сколько."""
    seconds = f"{section.seconds:.0f} с" if section.seconds >= 0.5 else "<1 с"
    inside = ", ".join(p for p in (section.tool, seconds, section.extra) if p)
    line = Text()
    line.append("✓ ", style="bold green")
    line.append(f"{section.title} ({inside})", style="bold")
    return line


def _severity_line(findings, section: Section) -> Text:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for f in findings:
        counts[f.severity.value] += 1
    line = _heading(section)
    line.append(f": {len(findings)}   ", style="bold")
    for sev in ("critical", "high", "medium", "low", "unknown"):
        if counts[sev]:
            line.append(
                f"{_SEVERITY_ICON[sev]} {sev.upper()}: {counts[sev]}   ",
                style=_SEVERITY_STYLE[sev],
            )
    return line


def _status_line(findings, section: Section) -> Text:
    counts = {"WARN": 0, "NOTE": 0, "INFO": 0, "PASS": 0}
    for f in findings:
        if f.status in counts:
            counts[f.status] += 1
    line = _heading(section)
    line.append("\n")
    line.append(f"Всего: {sum(counts.values())}   ", style="bold")
    for status in ("PASS", "WARN", "INFO", "NOTE"):
        line.append(f"{status}: {counts[status]}   ", style=_STATUS_STYLE[status])
    # Score считает сам Docker Bench (только зачётные проверки), берём его число из журнала
    if "score" in section.summary:
        line.append(f"Score: {section.summary['score']}", style="bold")
    return line


def _short(items: list[str], limit: int = 70) -> str:
    text = "; ".join(items)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _print_severity_table(console: Console, findings, top: int, show_where: bool) -> None:
    has_package = any(f.package for f in findings)
    has_version = any(f.installed_version for f in findings)
    table = Table(show_lines=True, expand=True)
    table.add_column("", width=2)
    table.add_column("ID", no_wrap=True)
    if has_package:
        table.add_column("Пакет", overflow="fold")
    if has_version:
        table.add_column("Установлена", overflow="fold")
        table.add_column("Исправлено в", overflow="fold")  # версия, либо статус, если исправления нет
    table.add_column("Название", ratio=4, min_width=34, overflow="fold")
    if show_where:
        table.add_column("Где", ratio=2, min_width=14, overflow="fold")
    table.add_column("Приоритет", justify="right")
    table.add_column("Источник")

    shown = findings if top <= 0 else findings[:top]
    for finding in shown:
        style = _SEVERITY_STYLE[finding.severity.value]
        row = [_SEVERITY_ICON[finding.severity.value], Text(finding.check_id, style=style)]
        if has_package:
            row.append(Text(finding.package or "—"))
        if has_version:
            row += [Text(finding.installed_version or "—"), Text(finding.fixed_version or "—")]
        title = Text(finding.title)
        if finding.remediation:
            title.append(f"\nКак исправить: {finding.remediation}", style="green")
        if finding.url:
            title.append(f"\n{finding.url}", style="dim")
        row.append(title)
        if show_where:
            row.append(Text(finding.location or "—"))
        row += [str(finding.priority_score), ", ".join(finding.confirmed_by)]
        table.add_row(*row)
    console.print(table)

    hidden = len(findings) - len(shown)
    if hidden > 0:
        console.print(
            f"[dim]… и ещё {hidden} с меньшим приоритетом. "
            "Полный список: -f json или -f html, либо --top 0[/dim]"
        )


def _group_by_place(findings) -> list[tuple[str, list]]:
    """Находки конфигов, собранные по месту в файле (файл:строки). Trivy печатает код
    у каждой находки отдельно, а на одно место их часто приходится десяток."""
    groups: dict[str, list] = {}
    for f in findings:
        groups.setdefault(f.location or "—", []).append(f)
    order = list(groups)
    return sorted(groups.items(), key=lambda kv: (
        -max(f.severity.rank for f in kv[1]), -len(kv[1]), order.index(kv[0])))


def _code_text(lines: list[dict]) -> Text:
    """Строки кода как у Trivy: номер и скобка ┌ │ └ у строк-причин."""
    causes = [i for i, line in enumerate(lines) if line["is_cause"]]
    width = len(str(max(line["number"] for line in lines)))
    text = Text(no_wrap=True, overflow="crop")
    for i, line in enumerate(lines):
        if i:
            text.append("\n")
        if not line["is_cause"]:
            mark = " "
        elif len(causes) == 1:
            mark = "▶"
        else:
            mark = "┌" if i == causes[0] else ("└" if i == causes[-1] else "│")
        text.append(f"  {line['number']:>{width}} ", style="dim")
        text.append(f"{mark} ", style="yellow")
        text.append(line["content"].rstrip(), style=None if line["is_cause"] else "dim")
    return text


def _print_config_groups(console: Console, findings, top: int) -> None:
    """Ошибки конфигурации: место в файле, его код один раз и таблица правил под ним."""
    shown = findings if top <= 0 else findings[:top]
    for place, group in _group_by_place(shown):
        head = Text()
        head.append(f"▌ {place}", style="bold cyan")
        head.append(f"  {len(group)} шт.:", style="bold")
        for sev in ("critical", "high", "medium", "low", "unknown"):
            n = sum(1 for f in group if f.severity.value == sev)
            if n:
                head.append(f"  {_SEVERITY_ICON[sev]} {sev.upper()}: {n}", style=_SEVERITY_STYLE[sev])
        console.print(head)
        code = next((f.code_lines for f in group if f.code_lines), [])
        if code:
            console.print(_code_text(code))
        else:
            console.print("  [dim](Trivy не прислал строки кода для этого места)[/dim]")

        table = Table(show_lines=True, expand=True)
        table.add_column("", width=2)
        table.add_column("ID", no_wrap=True)
        table.add_column("Что не так", ratio=1, overflow="fold")
        table.add_column("Как исправить", ratio=1, overflow="fold")
        for f in sorted(group, key=lambda f: (-f.severity.rank, f.check_id)):
            what = Text(f.title)
            if f.url:
                what.append(f"\n{f.url}", style="dim")
            fix = Text(f.remediation or "—")
            hint = yaml_hint(f.check_id, f.remediation)
            if hint:
                fix.append("\nв файле:", style="green")
                for line in hint:
                    fix.append(f"\n  {line}", style="green")
            table.add_row(_SEVERITY_ICON[f.severity.value],
                          Text(f.check_id, style=_SEVERITY_STYLE[f.severity.value]), what, fix)
        console.print(table)
        console.print()

    hidden = len(findings) - len(shown)
    if hidden > 0:
        console.print(
            f"[dim]… и ещё {hidden} с меньшим приоритетом. "
            "Полный список: -f json или -f html, либо --top 0[/dim]"
        )


def _print_status_table(console: Console, findings, top: int) -> None:
    problems = list(findings)   # показываем всё, что отдал Docker Bench, включая PASS
    if not problems:
        console.print("[yellow]Docker Bench не вернул ни одной проверки.[/yellow]")
        return
    shown = problems if top <= 0 else problems[:top]
    has_details = any(f.details for f in shown)
    has_advice = any(f.remediation for f in shown)
    table = Table(show_lines=True, expand=True)
    table.add_column("Статус")
    table.add_column("ID")
    table.add_column("Проверка")
    if has_details:
        table.add_column("К чему относится")
    if has_advice:
        table.add_column("Что сделать")

    for finding in shown:
        row = [
            Text(finding.status or "", style=_STATUS_STYLE.get(finding.status or "", "")),
            Text(finding.check_id),
            Text(finding.title),
        ]
        # Text, а не строка: в тексте бывают [квадратные скобки] (имя образа), rich принял бы их за разметку
        if has_details:
            row.append(Text("; ".join(finding.details)))
        if has_advice:
            row.append(Text(finding.remediation or ""))
        table.add_row(*row)
    console.print(table)
    hidden = len(problems) - len(shown)
    if hidden > 0:
        console.print(
            f"[dim]… и ещё {hidden}. Полный список: -f json или -f html, либо --top 0[/dim]"
        )
    legend = Text()
    for i, (status, meaning) in enumerate((
        ("WARN", "нарушение рекомендации"), ("NOTE", "решение за вами"),
        ("INFO", "информация или ручная проверка"), ("PASS", "в порядке"),
    )):
        if i:
            legend.append("; ", style="dim")
        legend.append(status, style=_STATUS_STYLE[status])
        legend.append(f" — {meaning}", style="dim")
    legend.append(".", style="dim")
    console.print(legend)


def _print_section(console: Console, result: ScanResult, section: Section, top: int) -> None:
    if section.kind == "status":
        console.print(_status_line(section.findings, section))
        _print_status_table(console, section.findings, top)
    else:
        console.print(_severity_line(section.findings, section))
        if section.findings and result.kind == "config":
            _print_config_groups(console, section.findings, top)
        elif section.findings:
            _print_severity_table(console, section.findings, top,
                                  show_where=result.kind in _SHOW_WHERE
                                  or len({f.location for f in section.findings}) > 1)
            if any(f.severity.value == "unknown" for f in section.findings):
                console.print("[dim]❓ UNKNOWN — Trivy не указал уровень критичности "
                              "(так бывает у свежих записей и у баз вроде Debian Security Tracker).[/dim]")
        elif section.note:
            console.print(Text(section.note, style="yellow"))
        else:
            console.print("[green]Проблем не найдено.[/green]")
    console.print()


def render(result: ScanResult, console: Console | None = None, top: int = 0) -> None:
    """top — сколько строк показать в каждой таблице (0 = все, по умолчанию).

    Если главный движок не отработал, об этом говорится прямо, а не молча
    подставляются данные другого движка."""
    console = console or Console()

    console.print()  # отступ от строки с подсказкой/спиннером
    for run in result.runs:
        what = _SCOPE_LABEL.get(run.scope, run.scope)
        if run.status == "missing":
            console.print(f"[red]✗[/red] {run.name} ({what}) — [red]не установлен[/red]: {run.detail}")
        elif run.status != "ok":
            console.print(f"[red]✗[/red] {run.name} ({what}) — [red]ОШИБКА[/red]: {run.detail}")
    if any(run.status != "ok" for run in result.runs):
        console.print()

    if result.image_scan_failed:
        what = "Сканирование образа" if result.kind == "image" else "Проверка"
        console.print(
            Panel(
                f"[bold red]{what} НЕ выполнена.[/bold red]\n"
                "Главный движок для этой цели не отработал (причина указана выше), поэтому "
                "сказать что-либо о цели нельзя. Это не значит, что всё в порядке.",
                border_style="red",
            )
        )

    for section in build_sections(result):
        _print_section(console, result, section, top)

    note = container_image_note(result)
    if note:
        console.print(Text(f"ⓘ {note}", style="yellow"))
