"""
CLI — тонкий слой поверх pipeline.run_scan().

Вся логика анализа живёт в pipeline/scanners/scoring/dedup и ничего
не знает про argparse, терминал или печать. Это сознательное разделение —
та же самая run_scan() завтра может быть вызвана из дашборда без единой
правки в этом файле.

Две команды: scan (проверить цель) и engines (показать движки).
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from pathlib import Path

from contextlib import contextmanager

from rich.console import Console
from rich.text import Text

from cast import __version__, state
from cast.context import ScanContext
from cast.scanners import ProgressUI
from cast.pipeline import EngineSelectionError, ScanResult, run_scan
from cast.report import console as console_report
from cast.report import html_report, json_report
from cast.scanners import ALL_SCANNERS
from cast.targets import KIND_TITLES, RESERVED_WORDS, Target, TargetError, resolve_target

HELP = """\
CAST — Container Automated Security Testing

Оболочка над готовыми сканерами (Trivy, Docker Bench for Security). Сама ничего
не ищет: подбирает движок под цель, приводит результаты к единому виду, убирает
дубли и расставляет приоритеты. Команда `sarbar` — псевдоним `cast`.

ИСПОЛЬЗОВАНИЕ
  cast scan ЦЕЛЬ [-e ДВИЖОК] [-f ФОРМАТ] [-o ФАЙЛ] [--requirements ПУТЬ]
                 [--top N]
  cast engines
  cast -h | -v

КОМАНДЫ
  scan      проверить цель и показать отчёт
  engines   показать движки: установлены ли, версия, что умеют проверять

ЦЕЛЬ — что проверять (вид определяется по записи, угадывать не нужно)
  alpine:3.19, nginx      образ: любое имя без «./» и «/»
  3f2a9c1b7d4e            запущенный контейнер: ID из docker ps
  Dockerfile              Dockerfile (Dockerfile, Dockerfile.*, *.Dockerfile,
                          Containerfile)
  ., ./app, ../x, /srv    папка: путь, начинающийся с «.», «/» или «~»
  host                    Docker-хост, то есть эта машина

  Явная запись, если автоопределение не подходит:
    cast scan image nginx           образ, даже если рядом есть папка nginx
    cast scan container ИМЯ|ID      контейнер по имени
    cast scan dockerfile ПУТЬ       Dockerfile с нестандартным именем
    cast scan fs ПУТЬ               папка
  Слова host, image, container, dockerfile, fs зарезервированы.

ПАРАМЕТРЫ cast scan
  -e, --engine ДВИЖОК     запустить только эти движки (через запятую):
                          trivy, docker-bench. Без флага движок выбирается
                          по цели
  -f, --format ФОРМАТ     сохранить отчёт файлом: html, json или html,json.
                          Файл создаётся в текущей папке, имя даётся само
  -o, --output ФАЙЛ       сохранить отчёт под своим именем; формат по
                          расширению (.html или .json)
  --requirements ПУТЬ     requirements.txt приложения: уязвимости в пакетах,
                          которые приложение реально использует, получают
                          более высокий приоритет
  --top N                 показать в консоли только N первых строк каждой
                          таблицы (по умолчанию все)
  -h, --help              показать эту справку
  -v, --version           показать версию

ЧЕМ ПРОВЕРЯЕТСЯ ЦЕЛЬ
  образ        trivy         уязвимости в пакетах
  папка        trivy         уязвимые зависимости, секреты, ошибки конфигурации
                             (в том числе Dockerfile внутри)
  Dockerfile   trivy         ошибки конфигурации
  контейнер    docker-bench  как запущен контейнер (CIS Docker Benchmark);
                             содержимое образа проверяет «-e trivy»
  host         docker-bench  настройки Docker-хоста (CIS Docker Benchmark):
                             весь скрипт, разделы 1–7, как при прямом запуске; в заголовке — Всего,
                             PASS/WARN/INFO/NOTE и Score (число самого скрипта)
  Самый первый cast scan заодно проверяет хост; потом — только cast scan host.

ОТЧЁТЫ
  Таблица в консоли печатается всегда. Файлы — только по флагу, в них попадают
  все находки, в том числе PASS у Docker Bench:
    -f html           отчёт для чтения в браузере
    -f json           данные для скриптов и дальнейшей обработки
    -f html,json      оба файла сразу
    -o отчёт.html     файл со своим именем

ПРИМЕРЫ
  cast scan alpine:3.19                 уязвимости пакетов образа
  cast scan 3f2a9c1b7d4e                как запущен контейнер
  cast scan 3f2a9c1b7d4e -e trivy       пакеты образа этого контейнера
  cast scan ./myapp --requirements requirements.txt
  cast scan host -f html                проверка хоста с HTML-отчётом
  cast scan alpine -o alpine.json       JSON под своим именем

КОДЫ ВОЗВРАТА
  0   проверка выполнена, critical нет
  1   найдена критичная уязвимость (critical)
  2   проверка не выполнена: движок упал или цель указана неверно
  130 прервано по Ctrl+C

ПРАВА
  Docker и Docker Bench требуют доступа к демону Docker: запускайте через sudo
  или добавьте себя в группу docker.

ФАЙЛЫ И ПЕРЕМЕННЫЕ
  /var/cache/cast/trivy        общая база уязвимостей Trivy (CAST_CACHE_DIR
                               указывает другую папку)
  /opt/docker-bench-security   Docker Bench (CAST_DOCKER_BENCH_DIR — другая
                               папка)
  CAST_STATE_DIR               где хранить отметку о первом запуске
"""


class _HelpAction(argparse.Action):
    """Единственная справка: -h у любой команды печатает её же."""

    def __init__(self, option_strings, dest=argparse.SUPPRESS, default=argparse.SUPPRESS, help=None):
        super().__init__(option_strings, dest=dest, default=default, nargs=0, help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        print(HELP, end="")
        parser.exit()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cast", usage="cast КОМАНДА ... (справка: cast -h)",
                                     add_help=False)
    subparsers = parser.add_subparsers(dest="command", metavar="КОМАНДА")
    parser.add_argument("-h", "--help", action=_HelpAction)
    parser.add_argument("-v", "--version", action="version", version=f"cast {__version__}")

    scan_parser = subparsers.add_parser("scan", add_help=False,
                                        usage="cast scan ЦЕЛЬ [параметры] (справка: cast -h)")
    scan_parser.add_argument("-h", "--help", action=_HelpAction)
    scan_parser.add_argument("target", nargs="*", metavar="ЦЕЛЬ")
    scan_parser.add_argument("-e", "--engine", metavar="ДВИЖОК")
    scan_parser.add_argument("-f", "--format", metavar="ФОРМАТ", default="console")
    scan_parser.add_argument("-o", "--output", type=Path, metavar="ФАЙЛ")
    scan_parser.add_argument("--requirements", type=Path, default=None, metavar="ПУТЬ")
    scan_parser.add_argument("--top", type=int, default=0, metavar="N")

    engines_parser = subparsers.add_parser("engines", add_help=False, usage="cast engines")
    engines_parser.add_argument("-h", "--help", action=_HelpAction)
    return parser


def _load_context(requirements_path: Path | None, console: Console) -> ScanContext:
    if requirements_path is None:
        return ScanContext.empty()
    if not requirements_path.exists():
        console.print(
            f"[yellow]⚠ Файл {requirements_path} не найден, "
            "контекстная приоритизация по зависимостям отключена.[/yellow]"
        )
        return ScanContext.empty()
    return ScanContext.from_requirements_file(requirements_path)


_TARGET_WORDS = {
    "image": "образ", "container": "контейнер", "dockerfile": "Dockerfile",
    "fs": "папку", "host": "Docker-хост",
}


def cmd_engines(console: Console) -> int:
    console.print("Движки cast:\n")
    for cls in ALL_SCANNERS:
        engine = cls()
        kinds = ", ".join(KIND_TITLES[k] for k in KIND_TITLES if k in engine.targets)
        defaults = ", ".join(KIND_TITLES[k] for k in KIND_TITLES if k in engine.default_targets)
        if engine.is_available():
            console.print(
                f"[green]✓[/green] {engine.name:<13} {engine.version() or '?':<8} "
                f"{engine.path() or ''}"
            )
        else:
            console.print(f"[red]✗[/red] {engine.name:<13} [red]не установлен[/red] "
                          "(установка: sudo bash install.sh --local)")
        console.print(f"    {engine.description}")
        console.print(f"    умеет проверять: {kinds}")
        console.print(f"    запускается сам для: {defaults}\n")
    console.print("[dim]Выбрать движок вручную: cast scan ЦЕЛЬ -e trivy | -e docker-bench[/dim]")
    return 0


def _parse_formats(raw: str) -> list[str]:
    formats: list[str] = []
    for part in (raw or "console").split(","):
        part = part.strip().lower()
        if not part:
            continue
        if part not in ("console", "html", "json"):
            raise ValueError(f"неизвестный формат «{part}». Допустимо: html, json (можно оба через запятую)")
        if part != "console" and part not in formats:
            formats.append(part)
    return formats


def _auto_name(result: ScanResult, ext: str) -> Path:
    label = result.target.container_name if result.target and result.target.kind == "container" \
        else (result.target.value if result.target else result.image)
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", label).strip("-.")[:50] or "report"
    stamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    return Path(f"cast-{result.kind}-{slug}-{stamp}.{ext}")


def _write_reports(result: ScanResult, formats: list[str], output: Path | None,
                   console: Console) -> None:
    jobs: list[tuple[str, Path]] = []
    if output is not None:
        ext = output.suffix.lower().lstrip(".")
        if ext not in ("html", "json"):
            raise ValueError("для -o укажите имя с расширением .html или .json")
        jobs.append((ext, output))
        formats = [f for f in formats if f != ext]
    for fmt in formats:
        jobs.append((fmt, _auto_name(result, fmt)))
    for fmt, path in jobs:
        (html_report if fmt == "html" else json_report).write(result, path)
        console.print(f"[dim]{fmt.upper()}-отчёт сохранён: {path}[/dim]")


def _scan_once(target: Target, engines, context, console: Console) -> ScanResult:
    """Один проход run_scan с индикатором: что делает какой движок."""
    status = console.status("[bold]Подготовка...[/bold]")
    current = {"engine": ""}

    class CliUI(ProgressUI):
        text = ""

        def say(self, text: str) -> None:
            self.text = text
            status.update(f"[bold]{current['engine']}[/bold] — {text}")

        def progress(self, fraction: float, label: str = "") -> None:
            width = 24
            filled = max(0, min(width, round(fraction * width)))
            bar = f"[green]{'█' * filled}[/green][dim]{'░' * (width - filled)}[/dim]"
            status.update(f"[bold]{current['engine']}[/bold] — {self.text}  {bar} "
                          f"{fraction * 100:3.0f}%  [dim]{label}[/dim]")

        @contextmanager
        def live(self):
            status.stop()   # пока Trivy рисует полосу загрузки, наш индикатор не мешает
            try:
                yield
            finally:
                status.start()

    def on_progress(event: str, scanner, detail: str = "") -> None:
        if event == "start":
            current["engine"] = scanner.name
            status.update(f"[bold]{scanner.name}[/bold] — {scanner.progress_hint or 'работаю'}")
        # итог и ошибки печатает отчёт: строка результата или красная плашка

    with status:
        return run_scan(target, context=context, on_progress=on_progress,
                        engines=engines, ui=CliUI())


def cmd_scan(args, console: Console) -> int:
    try:
        formats = _parse_formats(args.format)
        target = resolve_target(args.target)
    except (ValueError, TargetError) as exc:
        console.print(f"[red]Ошибка:[/red] {exc}")
        return 2
    for note in target.notes:
        console.print(Text(f"ⓘ {note}", style="yellow"))

    engines = [e.strip() for e in args.engine.split(",") if e.strip()] if args.engine else None
    context = _load_context(args.requirements, console)

    try:
        result = _scan_once(target, engines, context, console)
    except EngineSelectionError as exc:
        console.print(f"[red]Ошибка:[/red] {exc}")
        return 2

    console_report.render(result, console=console, top=args.top)

    try:
        _write_reports(result, formats, args.output, console)
    except ValueError as exc:
        console.print(f"[red]Ошибка:[/red] {exc}")
        return 2

    if target.kind == "host":
        if not result.image_scan_failed:
            state.mark_host_checked()
    elif not state.host_check_done() and engines is None:
        # самый первый запуск: один раз заодно показываем проверку хоста
        console.print("[bold]Это первый запуск cast, поэтому заодно проверены настройки "
                      "Docker-хоста. Дальше они проверяются командой: cast scan host[/bold]\n")
        host_result = _scan_once(Target("host", "host"), None, ScanContext.empty(), console)
        console_report.render(host_result, console=console, top=args.top)
        if not host_result.image_scan_failed:
            state.mark_host_checked()  # при неудаче метку не ставим: повторим в следующий раз

    if result.image_scan_failed:
        return 2
    return 1 if result.counts_by_severity["critical"] > 0 else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console()

    try:
        if args.command == "scan":
            return cmd_scan(args, console)
        if args.command == "engines":
            return cmd_engines(console)
    except KeyboardInterrupt:
        console.print("\n[yellow]Прервано пользователем.[/yellow]")
        return 130

    print(HELP, end="")
    return 0


def entry_point() -> None:
    """Используется в console_scripts (см. pyproject.toml): и cast, и sarbar
    указывают на одну и ту же функцию — вызывать утилиту можно любым из двух имён."""
    sys.exit(main())


if __name__ == "__main__":
    entry_point()
