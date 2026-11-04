"""
Рендер для терминала — то, что видит человек сразу после запуска cast scan.
Используем rich: цвета, таблица, не нужно руками считать отступы под юникод.

Отчёт честно разделён по движкам: у каждого свой раздел со своим названием.
Результаты Docker Bench показываются со статусами PASS/WARN/INFO/NOTE как есть
(уровней критичности у него нет), результаты Trivy — с уровнями критичности.
"""

from __future__ import annotations

import re
from difflib import SequenceMatcher

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cast.pipeline import ScanResult
from cast.report.fix_hint import ADD, CHANGE, EXISTS, hint_lines
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
        score = section.summary["score"]
        line.append(f"Score: {score}", style="bold")
        # формула Docker Bench (functions/output_lib.sh): +1 за зачётный PASS, −1 за WARN
        line.append(f"\nScore считает Docker Bench: +1 за каждый зачётный PASS ({score + counts['WARN']}), "
                    f"−1 за каждый WARN ({counts['WARN']}). INFO и NOTE не влияют, "
                    "и не все PASS зачётные.", style="dim")
    return line


def _short(items: list[str], limit: int = 70) -> str:
    text = "; ".join(items)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _merge_same(findings) -> list[tuple[object, list[str]]]:
    """Одна CVE в пакетах из одного исходника (musl и musl-utils) с теми же версиями —
    одна строка со списком пакетов. Счётчики в заголовке остаются как у Trivy."""
    rows: dict[tuple, tuple[object, list[str]]] = {}
    for f in findings:
        key = (f.check_id, f.title, f.installed_version, f.fixed_version, f.location) \
            if f.package else (id(f),)
        if key in rows:
            rows[key][1].append(f.package)
        else:
            rows[key] = (f, [f.package] if f.package else [])
    return list(rows.values())


def _print_severity_table(console: Console, findings, top: int, show_where: bool) -> None:
    # Приоритет и движок в терминале не показываем: приоритет здесь повторяет уровень,
    # а движок в этих разделах один. Оба поля остаются в JSON и HTML.
    has_package = any(f.package for f in findings)
    has_version = any(f.installed_version for f in findings)
    # Ширины колонок считаем от окна сами. Раньше у «Названия» был постоянный минимум 34,
    # и в окне уже ~110 символов Rich отрезал правые колонки целиком; без минимума он
    # сжимал «Название» до одной буквы. Теперь узкие колонки ограничены сверху, а
    # «Название» получает остальное.
    id_width = max(len(f.check_id) for f in findings)
    # место для текста без рамок, значка и ID (рамка — 3 символа на колонку)
    rest = console.width - 3 * (3 + 2 * has_version + has_package) - 1 - 2 - id_width
    where_column = show_where and rest >= 70      # в узком окне «Где» — строкой под названием
    if where_column:
        rest -= 3
    where_width = max(10, rest // 5) if where_column else 0
    n_narrow = 2 * has_version + has_package
    narrow = max(12 if rest >= 60 else 6, (rest - where_width - rest * 2 // 5) // max(n_narrow, 1))
    table = Table(show_lines=True, expand=True)
    table.add_column("", width=2)
    table.add_column("ID", no_wrap=True)
    if has_package:
        table.add_column("Пакет", max_width=narrow, overflow="fold")
    if has_version:
        table.add_column("Установлена", max_width=narrow, overflow="fold")
        table.add_column("Исправлено в", max_width=narrow, overflow="fold")  # версия, либо статус, если исправления нет
    table.add_column("Название", ratio=1, overflow="fold")
    if where_column:
        table.add_column("Где", max_width=where_width, overflow="fold")

    shown = findings if top <= 0 else findings[:top]
    for finding, packages in _merge_same(shown):
        style = _SEVERITY_STYLE[finding.severity.value]
        row = [_SEVERITY_ICON[finding.severity.value], Text(finding.check_id, style=style)]
        if has_package:
            row.append(Text("\n".join(packages) or "—"))
        if has_version:
            row += [Text(finding.installed_version or "—"), Text(finding.fixed_version or "—")]
        title = Text(finding.title)
        if finding.remediation:
            title.append(f"\nКак исправить: {finding.remediation}", style="green")
        if show_where and not where_column and finding.location:
            title.append(f"\nГде: {finding.location}", style="cyan")
        if finding.url:
            title.append(f"\n{finding.url}", style="dim")
        row.append(title)
        if where_column:
            row.append(Text(finding.location or "—"))
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
    # сначала самые серьёзные; «весь файл» («нет USER», «нет HEALTHCHECK») — среди них же,
    # а при равной серьёзности — после мест со строками
    return sorted(groups.items(), key=lambda kv: (
        -max(f.severity.rank for f in kv[1]), not _has_lines(kv[0]), -len(kv[1]), order.index(kv[0])))


def _has_lines(place: str) -> bool:
    return bool(re.search(r":\d+(-\d+)?$", place))


def _message_differs(f) -> bool:
    """Message Trivy показываем, только если он добавляет что-то к названию и совету."""
    if not f.message:
        return False
    norm = lambda t: re.sub(r"\W+", " ", (t or "").lower()).strip()
    msg = norm(f.message)
    return all(SequenceMatcher(None, msg, norm(other)).ratio() < 0.85
               for other in (f.title, f.remediation))


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
            mark = "["          # одна строка-причина — как у Trivy: «1 [ FROM ubuntu:latest»
        else:
            mark = "┌" if i == causes[0] else ("└" if i == causes[-1] else "│")
        text.append(f"  {line['number']:>{width}} ", style="dim")
        text.append(f"{mark} ", style="yellow")
        text.append(line["content"].rstrip(), style=None if line["is_cause"] else "dim")
    return text


def _append_hint(fix: Text, lines) -> None:
    """Кусок YAML под советом: серым — что уже есть в файле, зелёным — что дописать."""
    first_add = True
    for text, state, old in lines:
        if state == EXISTS:
            fix.append(f"\n  {text}", style="dim")
            fix.append("  (уже есть)", style="dim italic")
            continue
        fix.append(f"\n  {text}", style="green")
        if state == CHANGE:
            fix.append(f"  ← сейчас {old}", style="yellow")
        elif state == ADD and first_add:
            fix.append("  ← добавить", style="yellow")
            first_add = False


def _print_config_groups(console: Console, findings, top: int) -> None:
    """Ошибки конфигурации: место в файле, его код один раз и таблица правил под ним."""
    shown = findings if top <= 0 else findings[:top]
    visible = {id(f) for f in shown}
    # места и их счётчики — по всем находкам, --top ограничивает только строки таблиц
    for place, group in _group_by_place(findings):
        rows = [f for f in group if id(f) in visible]
        if not rows:
            continue
        head = Text()
        head.append(f"▌ {place}" if _has_lines(place) or place == "—" else f"▌ {place} — весь файл",
                    style="bold cyan")
        head.append(f"  {len(group)} шт.:", style="bold")
        for sev in ("critical", "high", "medium", "low", "unknown"):
            n = sum(1 for f in group if f.severity.value == sev)
            if n:
                head.append(f"  {_SEVERITY_ICON[sev]} {sev.upper()}: {n}", style=_SEVERITY_STYLE[sev])
        if len(rows) < len(group):
            head.append(f"  (в таблице {len(rows)}, остальные скрыты --top)", style="dim")
        console.print(head)
        code = next((f.code_lines for f in group if f.code_lines), [])
        if code:
            console.print(_code_text(code))
        elif _has_lines(place):
            console.print("  [dim](Trivy не прислал строки кода для этого места)[/dim]")

        table = Table(show_lines=True, expand=True)
        table.add_column("", width=2)
        table.add_column("ID", no_wrap=True)
        table.add_column("Что не так", ratio=1, overflow="fold")
        table.add_column("Как исправить", ratio=1, overflow="fold")
        for f in sorted(rows, key=lambda f: (-f.severity.rank, f.check_id)):
            what = Text(f.title)
            if _message_differs(f):
                what.append(f"\n{f.message}")
            if f.url:
                what.append(f"\n{f.url}", style="dim")
            fix = Text(f.remediation or "—")
            _append_hint(fix, hint_lines(f.check_id, f.remediation, f.message, f.code_lines or code))
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


# Разделы CIS Docker Benchmark: русское название (наше) и английское (как у Docker Bench).
_BENCH_SECTIONS = {
    "1": ("Хост", "Host Configuration"),
    "2": ("Настройки демона Docker", "Docker daemon configuration"),
    "3": ("Файлы настроек демона", "Docker daemon configuration files"),
    "4": ("Образы и Dockerfile", "Container Images and Build File"),
    "5": ("Запуск контейнеров", "Container Runtime"),
    "6": ("Порядок на хосте", "Docker Security Operations"),
    "7": ("Docker Swarm", "Docker Swarm Configuration"),
}
# Пометки Docker Bench, которые стоит показать (Automated/Scored ничего не говорят читателю).
_BENCH_MARKS = {"Manual": "ручная", "Deprecated": "устаревшая"}


def _bench_check_cell(finding) -> Text:
    """Номер, название, пометки и «к чему относится» — пунктами под названием."""
    cell = Text()
    if finding.check_id != "—":
        cell.append(f"{finding.check_id}  ", style="bold")
    cell.append(finding.title)
    for mark in finding.marks:
        if mark in _BENCH_MARKS:
            cell.append(f"  ({_BENCH_MARKS[mark]})", style="dim")
        elif mark not in ("Automated", "Scored", "Not Scored"):
            cell.append(f"  ({mark})", style="dim")
    for item in finding.details:
        cell.append(f"\n• {item}", style="magenta")
    return cell


def _print_status_table(console: Console, findings, top: int) -> None:
    """Docker Bench: по разделам CIS, в каждом — таблица WARN/NOTE/INFO и серые строки PASS внизу."""
    if not findings:
        console.print("[yellow]Docker Bench не вернул ни одной проверки.[/yellow]")
        return
    groups: dict[str, list] = {}
    for f in findings:   # findings уже отсортированы: WARN, NOTE, INFO, PASS, внутри по номеру
        key = f.section or (f.check_id.split(".")[0] if f.check_id[:1].isdigit() else "?")
        groups.setdefault(key, []).append(f)
    hidden = 0
    for key in sorted(groups, key=lambda k: (not k.isdigit(), int(k) if k.isdigit() else 0)):
        items = groups[key]
        ru, en = _BENCH_SECTIONS.get(key, ("Без раздела", ""))
        head = Text(f"▌ {key}. {ru}" if key.isdigit() else f"▌ {ru}", style="bold")
        if en:
            head.append(f" · {en}", style="dim")
        head.append("   ")
        for status in ("WARN", "NOTE", "INFO", "PASS"):
            n = sum(1 for f in items if f.status == status)
            if n:
                head.append(f"{status} {n}  ", style=_STATUS_STYLE[status])
        console.print(head)
        rows = [f for f in items if f.status != "PASS"]
        passed = [f for f in items if f.status == "PASS"]
        shown = rows if top <= 0 else rows[:top]
        hidden += len(rows) - len(shown)
        # PASS — строками внизу раздела, серым; с --top места под них нет — только номера
        pass_rows = passed if top <= 0 else []
        if shown or pass_rows:
            table = Table(show_lines=True, expand=True)
            table.add_column("Статус", no_wrap=True)
            table.add_column("Проверка", ratio=1)
            has_advice = any(f.remediation for f in shown)
            if has_advice:
                table.add_column("Что сделать", ratio=1)
            for f in shown:
                row = [Text(f.status or "", style=_STATUS_STYLE.get(f.status or "", "")), _bench_check_cell(f)]
                if has_advice:
                    # совет к WARN — руководство к действию; к NOTE/INFO — для сведения, бледнее
                    row.append(Text(f.remediation or "", style="" if f.status == "WARN" else "dim"))
                table.add_row(*row)
            for f in pass_rows:
                cell = _bench_check_cell(f)
                cell.stylize("dim")
                row = [Text("PASS", style=_STATUS_STYLE["PASS"]), cell]
                if has_advice:
                    row.append(Text(""))   # делать нечего
                table.add_row(*row)
            console.print(table)
            if len(rows) > len(shown):
                console.print(f"[dim]  скрыто --top: {len(rows) - len(shown)}[/dim]")
        if passed and not pass_rows:
            line = Text("  PASS: ", style=_STATUS_STYLE["PASS"])
            line.append(", ".join(f.check_id for f in passed))
            console.print(line)
        console.print()
    if hidden:
        console.print(f"[dim]Скрыто --top: {hidden}. Полный список: --top 0, -f html или -f json[/dim]")
    legend = Text()
    for i, (status, meaning) in enumerate((
        ("WARN", "нарушение рекомендации"), ("NOTE", "решение за вами"),
        ("INFO", "информация или ручная проверка"), ("PASS", "в порядке"),
    )):
        if i:
            legend.append("; ", style="dim")
        legend.append(status, style=_STATUS_STYLE[status])
        legend.append(f" — {meaning}", style="dim")
    legend.append(". (ручная) — Docker Bench не может проверить это сам, посмотрите вручную.", style="dim")
    console.print(legend)


_CONTAINER_BENCH_NOTE = (
    "Проверены 4.1 (от какого пользователя работает контейнер) и раздел 5 «Запуск контейнеров», "
    "то есть docker-bench-security.sh -c check_4_1,container_runtime. Поэтому проверок на одну "
    "больше, чем при запуске только -c container_runtime, и Score может отличаться на 1."
)


def _print_section(console: Console, result: ScanResult, section: Section, top: int) -> None:
    if section.kind == "status":
        console.print(_status_line(section.findings, section))
        if result.kind == "container" and section.tool == "docker-bench":
            console.print(Text(_CONTAINER_BENCH_NOTE, style="dim"))
        console.print()
        _print_status_table(console, section.findings, top)
    else:
        console.print(_severity_line(section.findings, section))
        if section.findings and result.kind in ("config", "dockerfile"):
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
        # «сканирование» среднего рода, «проверка» женского — глагол согласуем
        what = "Сканирование образа НЕ выполнено" if result.kind == "image" else "Проверка НЕ выполнена"
        console.print(
            Panel(
                f"[bold red]{what}.[/bold red]\n"
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
