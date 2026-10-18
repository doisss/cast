"""
Обёртка над Docker Bench for Security
(https://github.com/docker/docker-bench-security).

Важная архитектурная особенность, которую стоит явно проговорить в ВКР:
Docker Bench проверяет не конкретный образ, а конфигурацию Docker-демона
и хоста в целом (CIS Benchmark для Docker). Поэтому, в отличие от Trivy,
параметр image в scan_image() этим сканером не используется — интерфейс
Scanner.scan_image(image) сохраняется одинаковым для всех сканеров ради
единообразия пайплайна (оркестратор не должен знать про такие частности),
но смысл находок здесь — "проблемы окружения", а не "проблемы образа X".

Вывод у инструмента текстовый (не JSON), поэтому здесь не парсинг JSON,
а разбор построчного формата вида:
    [WARN] 4.1 - Ensure a user for the container has been created
    [PASS] 1.1.1 - Ensure a separate partition for containers has been created
"""

from __future__ import annotations

import os
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from cast.models import Finding, Severity
from cast.scanners.base import Scanner, ScannerError
from cast.utils import BinaryNotFoundError, find_binary

DOCKER_BENCH_INSTALL_HINT = "https://github.com/docker/docker-bench-security"

# Пример строки: "[WARN] 4.1 - Ensure that a user for the container has been created (Automated)"
# Строки вида "[INFO] 1.1 - Linux Hosts Specific Configuration" — это заголовки
# подразделов, а не проверки (проверено по исходникам и реальному выводу).
# Настоящая проверка всегда заканчивается пометкой типа: (Automated), (Manual),
# (Scored) или (Not Scored) — по ней и отличаем.
# Одна проверка в выводе скрипта идёт без номера: "[INFO] Ensure that experimental ... (Deprecated)"
_NOID_RE = re.compile(r"^\[(WARN|NOTE|INFO|PASS)\]\s+(Ensure\b.*)$")
_LINE_RE = re.compile(r"^\[(WARN|NOTE|INFO|PASS)\]\s+(\d+(?:\.\d+)+)\s*-\s*(.+)$")
# после типа проверки может идти ещё пометка: "(Automated) (Swarm mode not enabled)"
_CHECK_SUFFIX_RE = re.compile(
    r"\s*\((?:Automated|Manual|Scored|Not Scored)\)(?:\s*\([^()]*\))*\s*$"
)

# Цветовые escape-последовательности (\033[1;31m ...). Запускаем с -b (без цветов),
# но на всякий случай вычищаем их и из вывода — защита от смены поведения скрипта.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

_SCRIPT_NAME = "docker-bench-security.sh"
_ENV_DIR = "CAST_DOCKER_BENCH_DIR"


def _default_dirs() -> list[Path]:
    """Типовые места установки. /opt — туда кладёт install.sh. Под sudo
    Path.home() указывает на /root, поэтому добавляем и домашнюю папку
    пользователя, который запустил sudo (SUDO_USER)."""
    dirs = [Path("/opt/docker-bench-security"), Path("/usr/local/share/docker-bench-security")]
    homes = [Path.home()]
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd  # только Unix; на Windows этого модуля нет

            homes.append(Path(pwd.getpwnam(sudo_user).pw_dir))
        except (ImportError, KeyError):
            pass
    dirs.extend(h / "docker-bench-security" for h in homes)
    return dirs


def locate_script() -> Path:
    """Ищет docker-bench-security.sh. Порядок: переменная CAST_DOCKER_BENCH_DIR,
    затем PATH (симлинк разворачивается до реального файла), затем типовые папки.
    Скрипт подгружает свои функции по относительному пути (LIBEXEC="."), поэтому
    запускать его нужно из его собственной папки — потому нам нужен именно реальный путь."""
    candidates: list[Path] = []
    env_dir = os.environ.get(_ENV_DIR)
    if env_dir:
        candidates.append(Path(env_dir) / _SCRIPT_NAME)
    try:
        candidates.append(Path(find_binary(_SCRIPT_NAME)).resolve())
    except BinaryNotFoundError:
        pass
    candidates.extend(d / _SCRIPT_NAME for d in _default_dirs())

    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise BinaryNotFoundError(
        _SCRIPT_NAME,
        f"{DOCKER_BENCH_INSTALL_HINT} (git clone, затем укажите папку в переменной "
        f"{_ENV_DIR} или положите в ~/docker-bench-security)",
    )


_STATUSES = ("WARN", "NOTE", "INFO", "PASS")
# Продолжение проверки: "[WARN]      * Running as root: web" — к чему именно замечание.
_DETAIL_RE = re.compile(r"^\[(WARN|NOTE|INFO|PASS)\]\s+\*\s*(.*)$")

# Хост = весь скрипт без отбора групп, ровно то, что показывает «docker-bench-security.sh»
# (разделы 1–7, раздел 5 — по всем запущенным контейнерам).
# Группы проверок скрипта (имена функций из functions_lib.sh) нужны только для контейнера.
CONTAINER_GROUPS = "check_4_1,container_runtime"


def read_version(script: Path) -> str | None:
    """Версия скрипта из строки version='1.6.0' в его начале."""
    try:
        for line in script.read_text(encoding="utf-8", errors="replace").splitlines()[:40]:
            match = re.match(r"^version='([^']+)'", line)
            if match:
                return match.group(1)
    except OSError:
        pass
    return None


def _load_log_json(path: Path) -> dict:
    """JSON-журнал Docker Bench. При запуске отдельных групп (-c ...) сам скрипт
    пишет его с ошибкой — не ставит запятую между проверкой и разделом, — поэтому
    при неудаче чиним это место и пробуем ещё раз. Не вышло — пустой словарь."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    for candidate in (text, re.sub(r"\}(\s*)\{", r"},\1{", text)):
        try:
            data = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(data, dict):
            return data
    # совсем сломанный журнал: хотя бы итоговые числа из его конца
    found = {k: int(m.group(1)) for k in ("checks", "score")
             if (m := re.search(rf'"{k}":\s*(-?\d+)', text))}
    return found


def _read_remediation(path: Path) -> dict[str, tuple[str, str]]:
    """{номер проверки: (что сделать, чем это грозит)} из JSON-журнала Docker Bench.
    Нет журнала или он битый — просто без советов, это не ошибка проверки."""
    data = _load_log_json(path)
    result: dict[str, tuple[str, str]] = {}

    def walk(node) -> None:
        # проверки вложены по разделам (1 -> 1.1 -> 1.1.1), глубина разная: идём рекурсивно
        if isinstance(node, dict):
            if node.get("id") and node.get("remediation"):
                result[str(node["id"])] = (node["remediation"], node.get("remediation-impact") or "")
            for value in node.values():
                if isinstance(value, (dict, list)):
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(data.get("tests", []))
    return result


def _read_summary(path: Path) -> dict[str, int]:
    """Итог самого Docker Bench: {"checks": N, "score": M} из его JSON-журнала.
    Score считает сам скрипт (только «зачётные» проверки), поэтому не выводим его сами."""
    data = _load_log_json(path)
    return {k: data[k] for k in ("checks", "score") if isinstance(data.get(k), int)}


def _strip_container(text: str, name: str | None) -> str:
    """«Running as root: web» -> «Running as root»: имя контейнера и так в заголовке."""
    if name and text.endswith(f": {name}"):
        return text[: -len(name) - 2]
    return text


class DockerBenchScanner(Scanner):
    name = "docker-bench"
    scope = "environment"
    targets = {"host", "container"}
    default_targets = {"host", "container"}
    description = "настройки Docker-хоста и запущенных контейнеров (CIS Docker Benchmark)"
    progress_hint = "проверяю настройки Docker (CIS)"

    def is_available(self) -> bool:
        try:
            locate_script()
            return True
        except BinaryNotFoundError:
            return False

    def version(self) -> str | None:
        try:
            return read_version(locate_script())
        except BinaryNotFoundError:
            return None

    def path(self) -> str | None:
        try:
            return str(locate_script().parent)
        except BinaryNotFoundError:
            return None

    remediation: dict[str, tuple[str, str]] = {}
    summary: dict[str, int] = {}

    def scan_target(self, target) -> list[Finding]:
        script = locate_script()
        if target.kind == "host":
            args = []
        elif target.kind == "container":
            # -i принимает регулярное выражение по имени контейнера: фиксируем точное имя
            args = ["-c", CONTAINER_GROUPS, "-i", f"^{re.escape(target.container_name or target.value)}$"]
        else:
            raise ScannerError(f"docker-bench не умеет проверять цель типа «{target.kind}»")
        findings = self._parse(self._run(script, args))
        for f in findings:
            advice = self.remediation.get(f.check_id)
            if advice and f.status != "PASS":
                f.remediation, f.remediation_impact = advice[0], advice[1] or None
            if target.kind == "container":
                f.details = [_strip_container(x, target.container_name) for x in f.details]
        return findings

    def scan_image(self, image: str) -> list[Finding]:  # совместимость со старым интерфейсом
        from cast.targets import Target

        return self.scan_target(Target("host", "host"))

    def _run(self, script: Path, extra_args: list[str] | None = None) -> str:
        with tempfile.TemporaryDirectory() as tmp:
            # -b: без цветов; -l: лог во временный файл, а не в ./log рядом со скриптом
            # Скрипт написан для bash (#!/bin/bash); через sh (в Debian это dash) часть
            # проверок конфигурации демона даёт неверный результат — см. тесты.
            shell = shutil.which("bash") or "sh"
            log = Path(tmp) / "bench.log"
            # -p: Docker Bench кладёт «что сделать» в JSON-журнал рядом с логом
            cmd = [shell, str(script), "-b", "-p", "-l", str(log), *(extra_args or [])]
            try:
                result = subprocess.run(
                    cmd,
                    cwd=script.parent,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise ScannerError(
                    f"docker-bench-security не ответил за отведённое время: {exc}"
                ) from exc
            except OSError as exc:
                raise ScannerError(f"не удалось запустить docker-bench-security: {exc}") from exc
            self.remediation = _read_remediation(Path(str(log) + ".json"))
            self.summary = _read_summary(Path(str(log) + ".json"))

        if "Error connecting to docker daemon" in result.stdout:
            raise ScannerError(
                "нет доступа к Docker-демону (запустите от root/sudo или добавьте "
                "пользователя в группу docker)"
            )
        # ненулевой код при найденных замечаниях — нормальное поведение, не ошибка запуска
        return result.stdout

    def _parse(self, raw_output: str) -> list[Finding]:
        """Возвращает ВСЕ проверки, включая PASS: статус хранится как есть
        (PASS/WARN/INFO/NOTE), отчёт сам решает, что показывать."""
        findings: list[Finding] = []
        current: Finding | None = None
        for line in _ANSI_RE.sub("", raw_output).splitlines():
            line = line.strip()
            if line.startswith("Section B"):
                break  # дальше идёт список советов, это не проверки
            detail = _DETAIL_RE.match(line)
            if detail:
                text = detail.group(2).strip()
                if current is not None and text:
                    current.details.append(text)
                continue
            match = _LINE_RE.match(line)
            if not match:
                noid = _NOID_RE.match(line)
                if not noid:
                    continue
                match = noid
                status, description = noid.groups()
                check_id = "—"
            else:
                status, check_id, description = match.groups()
            if not _CHECK_SUFFIX_RE.search(description):
                current = None
                continue  # заголовок раздела, а не проверка
            description = _CHECK_SUFFIX_RE.sub("", description).strip()
            current = Finding(
                source_tool=self.name,
                check_id=check_id,
                title=description,
                severity=Severity.UNKNOWN,   # у Docker Bench уровней нет, только статус
                description=description,
                status=status,
            )
            findings.append(current)
        return findings
