"""
Обёртка над Trivy (https://github.com/aquasecurity/trivy).

Trivy ищет известные CVE в пакетах образа (статический анализ: слои, ОС,
зависимости). Мы вызываем его в режиме --format json, чтобы получить
машиночитаемый вывод вместо красивой таблички для терминала, и сами
парсим этот JSON в нашу единую схему Finding.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cast.models import Finding, Severity
from cast.scanners.base import Scanner, ScannerError
from cast.targets import is_dockerfile_name
from cast.utils import find_binary

TRIVY_INSTALL_HINT = (
    "https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
)


def _explain_failure(returncode: int, stderr: str) -> str:
    """Trivy при сбое печатает длинную простыню. Узнаём типовые причины и
    говорим по-человечески, что делать; для остального — короткий хвост."""
    text = stderr or ""
    if "permission denied while trying to connect to the docker" in text.lower():
        return (
            "нет доступа к Docker. Запустите через sudo (sudo cast scan ...) или "
            "добавьте себя в группу docker: sudo usermod -aG docker $USER "
            "(затем перелогиньтесь)"
        )
    low = text.lower()
    if "no space left on device" in low:
        return (
            "на диске закончилось место. Trivy хранит базу уязвимостей в "
            "/var/cache/cast/trivy или ~/.cache/trivy (нужно около 1 ГБ свободно). Проверьте df -h, "
            "освободите место (sudo docker system prune, sudo trivy clean --all) "
            "и повторите"
        )
    if "cache may be in use by another process" in low:
        return (
            "кэш Trivy занят другим процессом (возможно, предыдущий запуск ещё "
            "не завершился). Проверьте: pgrep -a trivy — и дождитесь или "
            "завершите его (sudo pkill trivy)"
        )
    if "could not parse reference" in low:
        return "некорректное имя образа — укажите имя:тег, например alpine:3.19"
    if "context deadline exceeded" in low:
        return ("Trivy не уложился во время (машина медленная или занята). "
                "Повторите запуск: уже скачанные слои и база берутся из кэша")
    if "unable to find the specified image" in text:
        return "образ не найден ни локально, ни в реестре — проверьте имя и тег"
    tail = " ".join(text.split())[-300:]
    return f"trivy завершился с кодом {returncode}: {tail}"


SHARED_CACHE = Path("/var/cache/cast/trivy")

_LOG_ATTR_RE = re.compile(r'(\w+)=("[^"]*"|\S+)')


def _log_fields(line: str) -> tuple[str, dict[str, str]]:
    """Строка журнала Trivy: время, уровень, сообщение, key=value через табуляцию."""
    parts = line.rstrip("\n").split("\t")
    message = parts[2] if len(parts) >= 3 else line
    attrs = {k: v.strip('"') for k, v in _LOG_ATTR_RE.findall(" ".join(parts[3:]))}
    return message, attrs


def _narration(line: str) -> str | None:
    """Что сказать пользователю по строке журнала Trivy (None — ничего)."""
    message, attrs = _log_fields(line)
    if "Detecting vulnerabilities" in message and attrs.get("pkg_num"):
        name = re.match(r"\[([^\]]+)\]", message)
        os_name = f"{name.group(1)} {attrs.get('os_version', '')}".strip() if name else "ОС"
        return f"проверяю {attrs['pkg_num']} пакетов ОС ({os_name}) по базе уязвимостей"
    if "Number of language-specific files" in message and attrs.get("num", "0") != "0":
        return f"проверяю файлы зависимостей языков: {attrs['num']}"
    if "Detected OS" in message:
        fam = attrs.get("family", "")
        ver = attrs.get("version", "")
        return f"образ распакован, ОС: {fam} {ver}".strip()
    return None


# Полоса загрузки Trivy: "58.20 MiB / 128.46 MiB [-----] 45.30% 1.07 MiB p/s 1m5s"
_BAR_RE = re.compile(
    r"([\d.]+ ?[KMGT]?i?B) / ([\d.]+ ?[KMGT]?i?B) \[[^\]]*\]\s+([\d.]+)%(?:\s+([\d.]+ ?[KMGT]?i?B) p/s)?"
)


def _parse_bar(chunk: str) -> tuple[float, str] | None:
    """Достать из куска вывода Trivy долю загрузки и подпись; None — это не полоса."""
    found = _BAR_RE.findall(chunk)
    if not found:
        return None
    done, total, percent, speed = found[-1]
    label = f"{done} / {total}" + (f", {speed}/с" if speed else "")
    return min(1.0, float(percent) / 100), label


def _download(cmd: list[str], on_progress, timeout: int = 1800) -> tuple[int, str]:
    """Запустить загрузку базы так, чтобы Trivy считал терминал настоящим и рисовал полосу
    (через pty), прочитать её и отдать на отрисовку нашему индикатору.
    Возвращает (код возврата, последняя строка вывода без полосы — для сообщения об ошибке)."""
    import pty
    import select
    import time

    master, slave = pty.openpty()
    try:
        proc = subprocess.Popen(
            cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=slave,
            close_fds=True, preexec_fn=_shared_umask if cache_dir() else None,
        )
    finally:
        os.close(slave)
    deadline = time.monotonic() + timeout
    pending = ""
    last_text = ""
    try:
        while True:
            if time.monotonic() > deadline:
                proc.kill()
                raise subprocess.TimeoutExpired(cmd, timeout)
            ready, _, _ = select.select([master], [], [], 0.5)
            if not ready:
                if proc.poll() is not None:
                    break
                continue
            try:
                data = os.read(master, 4096)
            except OSError:      # Linux: pty закрыт, процесс завершился
                break
            if not data:
                break
            pending += data.decode("utf-8", "replace")
            parts = re.split(r"[\r\n]", pending)
            pending = parts.pop()
            for part in parts + ([pending] if _BAR_RE.search(pending) else []):
                bar = _parse_bar(part)
                if bar:
                    on_progress(*bar)
                elif part.strip():
                    last_text = _log_fields(part)[0].strip()
    finally:
        os.close(master)
    return proc.wait(), last_text


def _exec(cmd: list[str], on_line=None) -> tuple[int, str, str]:
    """Запустить команду, читая stderr построчно. Возвращает (код, stdout, stderr).
    Ограничение по времени больше, чем у самого Trivy (у него по умолчанию 5 минут)."""
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        preexec_fn=_shared_umask if cache_dir() else None,
    )
    out_parts: list[str] = []
    err_parts: list[str] = []

    def read_out():
        out_parts.append(proc.stdout.read())

    def read_err():
        for line in proc.stderr:
            err_parts.append(line)
            if on_line:
                on_line(line)

    threads = [threading.Thread(target=read_out, daemon=True),
               threading.Thread(target=read_err, daemon=True)]
    for th in threads:
        th.start()
    try:
        proc.wait(timeout=600)
    except subprocess.TimeoutExpired:
        proc.kill()
        raise
    for th in threads:
        th.join(timeout=5)
    return proc.returncode, "".join(out_parts), "".join(err_parts)


def cache_dir() -> Path | None:
    """Общий кэш Trivy для всех пользователей (создаёт install.sh).
    CAST_CACHE_DIR переопределяет. Нет общего кэша — None, и Trivy берёт свой ~/.cache/trivy."""
    env = os.environ.get("CAST_CACHE_DIR")
    if env:
        return Path(env)
    if SHARED_CACHE.is_dir() and os.access(SHARED_CACHE, os.W_OK | os.X_OK):
        return SHARED_CACHE
    return None


def _db_dir() -> Path:
    return (cache_dir() or Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "trivy") / "db"


def _db_needs_update() -> bool:
    """Нужно ли скачать (или обновить) базу уязвимостей. Решаем сами заранее, чтобы
    честно показать скачивание отдельно от проверки: базы нет или истёк NextUpdate."""
    db = _db_dir()
    if not (db / "trivy.db").exists():
        return True
    try:
        next_update = json.loads((db / "metadata.json").read_text(encoding="utf-8"))["NextUpdate"]
        due = datetime.fromisoformat(next_update.replace("Z", "+00:00"))
        return datetime.now(timezone.utc) >= due
    except (OSError, ValueError, KeyError, TypeError):
        return True


def _with_cache(cmd: list[str]) -> list[str]:
    cd = cache_dir()
    return [cmd[0], "--cache-dir", str(cd), *cmd[1:]] if cd else cmd


def _shared_umask() -> None:
    os.umask(0o002)  # файлы кэша доступны группе docker, иначе второй пользователь не сможет обновить базу


class TrivyScanner(Scanner):
    name = "trivy"
    scope = "image"
    targets = {"image", "fs", "dockerfile", "container"}
    # Для контейнера Trivy по умолчанию не запускается (там главный — Docker Bench);
    # его можно добавить флагом -e trivy: тогда проверится образ этого контейнера.
    default_targets = {"image", "fs", "dockerfile"}
    description = "уязвимости в пакетах образа, зависимости и секреты в папке, ошибки Dockerfile"

    progress_hint = "проверяю"

    def is_available(self) -> bool:
        try:
            find_binary("trivy", TRIVY_INSTALL_HINT)
            return True
        except Exception:
            return False

    def version(self) -> str | None:
        try:
            binary = find_binary("trivy", TRIVY_INSTALL_HINT)
            out = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=20)
        except Exception:
            return None
        match = re.search(r"Version:\s*(\S+)", out.stdout or "")
        return match.group(1) if match else None

    def path(self) -> str | None:
        try:
            return find_binary("trivy", TRIVY_INSTALL_HINT)
        except Exception:
            return None

    def scan_image(self, image: str) -> list[Finding]:
        binary = find_binary("trivy", TRIVY_INSTALL_HINT)
        raw_json = self._run_trivy(binary, image)
        return self._parse(raw_json)

    def scan_target(self, target) -> list[Finding]:
        binary = find_binary("trivy", TRIVY_INSTALL_HINT)
        if target.kind == "dockerfile":
            self.ui.say("проверяю Dockerfile")
            return self._parse(self._scan_dockerfile(binary, Path(target.value).expanduser()))
        if target.kind not in ("image", "container", "fs"):
            raise ScannerError(f"trivy не умеет проверять цель типа «{target.kind}»")

        # Сначала база уязвимостей — отдельным шагом и с настоящей полосой загрузки,
        # потом сама проверка: пользователь видит то, что происходит на самом деле.
        self._ensure_db(binary)
        if target.kind == "image":
            if getattr(target, "image_missing", False):
                self.ui.say(f"скачиваю образ {target.value} из реестра")
            else:
                self.ui.say(f"открываю образ {target.value}")
            return self._parse(self._run_trivy(binary, target.value))
        if target.kind == "container":
            self.ui.say(f"открываю образ контейнера ({target.image_name})")
            # контейнер = его образ; ID образа точнее имени (тег мог уехать на другой образ)
            return self._parse(self._run_trivy(binary, target.image_ref or target.image_name))
        self.ui.say(f"читаю файлы папки {target.value}")
        # misconfig включаем явно, чтобы заодно проверялся Dockerfile внутри папки
        cmd = [binary, "fs", "--format", "json", "--skip-db-update",
               "--scanners", "vuln,secret,misconfig", target.value]
        return self._parse(self._run(cmd))

    def _ensure_db(self, binary: str) -> None:
        if not _db_needs_update():
            return
        self.ui.say("скачиваю базу уязвимостей (один раз, ~130 МБ; потом обновляется раз в сутки)")
        cmd = _with_cache([binary, "image", "--download-db-only"])
        try:
            returncode, tail = _download(cmd, self.ui.progress)
        except (subprocess.TimeoutExpired, OSError) as exc:
            returncode, tail = 1, str(exc)
        if returncode != 0 and not (_db_dir() / "trivy.db").exists():
            raise ScannerError(
                f"не удалось скачать базу уязвимостей ({tail or f'trivy завершился с кодом {returncode}'}). "
                "Проверьте интернет и свободное место (нужно около 1 ГБ): df -h"
            )
        # если база уже есть, но обновить не вышло (нет сети) — проверяем по имеющейся

    # -- внутренняя кухня, вынесена отдельно ради тестируемости --------

    def _scan_dockerfile(self, binary: str, path: Path) -> str:
        """trivy config принимает папку, а не файл, и узнаёт Dockerfile по имени.
        Поэтому кладём копию файла во временную папку под именем Dockerfile."""
        with tempfile.TemporaryDirectory() as tmp:
            name = path.name if is_dockerfile_name(path.name) else "Dockerfile"
            shutil.copy(path, Path(tmp) / name)
            return self._run([binary, "config", "--quiet", "--format", "json", tmp])

    def _run_trivy(self, binary: str, image: str) -> str:
        return self._run([binary, "image", "--format", "json", "--skip-db-update", image])

    def _run(self, cmd: list[str]) -> str:
        """Запуск Trivy. Его журнал (stderr) читаем на лету и пересказываем
        пользователю только то, что Trivy действительно сообщил."""
        try:
            returncode, stdout, stderr = _exec(_with_cache(cmd), self._narrate)
        except subprocess.TimeoutExpired as exc:
            raise ScannerError(f"trivy не ответил за отведённое время: {exc}") from exc
        except OSError as exc:
            raise ScannerError(f"не удалось запустить trivy: {exc}") from exc
        if returncode != 0:
            raise ScannerError(_explain_failure(returncode, stderr))
        return stdout

    def _narrate(self, line: str) -> None:
        text = _narration(line)
        if text:
            self.ui.say(text)

    def _parse(self, raw_json: str) -> list[Finding]:
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError as exc:
            raise ScannerError(f"не удалось разобрать JSON от trivy: {exc}") from exc

        findings: list[Finding] = []
        for result in data.get("Results", []) or []:
            layer_digest = None
            pkg_type = result.get("Type")
            target_name = result.get("Target")
            for vuln in result.get("Vulnerabilities", []) or []:
                layer = vuln.get("Layer") or {}
                layer_digest = layer.get("Digest") or layer_digest
                findings.append(
                    Finding(
                        source_tool=self.name,
                        check_id=vuln.get("VulnerabilityID", "UNKNOWN"),
                        title=vuln.get("Title") or vuln.get("VulnerabilityID", ""),
                        severity=Severity.from_trivy(vuln.get("Severity", "")),
                        description=vuln.get("Description", ""),
                        package=vuln.get("PkgName"),
                        installed_version=vuln.get("InstalledVersion"),
                        fixed_version=vuln.get("FixedVersion"),
                        layer=layer_digest,
                        pkg_type=pkg_type,
                        location=target_name,
                        url=vuln.get("PrimaryURL"),
                        fix_status=vuln.get("Status"),
                    )
                )
            # ошибки конфигурации (Dockerfile, yaml, terraform ...)
            for mis in result.get("Misconfigurations", []) or []:
                if (mis.get("Status") or "FAIL").upper() == "PASS":
                    continue
                cause = mis.get("CauseMetadata") or {}
                line = cause.get("StartLine")
                where = f"{target_name}:{line}" if target_name and line else target_name
                findings.append(
                    Finding(
                        source_tool=self.name,
                        check_id=mis.get("ID") or mis.get("AVDID") or "MISCONFIG",
                        title=mis.get("Title") or mis.get("Message") or "",
                        severity=Severity.from_trivy(mis.get("Severity", "")),
                        description=mis.get("Description") or mis.get("Message") or "",
                        package=None,
                        pkg_type="config",
                        location=where,
                        remediation=mis.get("Resolution") or None,
                        url=mis.get("PrimaryURL"),
                    )
                )
            # найденные секреты (пароли, ключи)
            for secret in result.get("Secrets", []) or []:
                line = secret.get("StartLine")
                where = f"{target_name}:{line}" if target_name and line else target_name
                findings.append(
                    Finding(
                        source_tool=self.name,
                        check_id=secret.get("RuleID") or "SECRET",
                        title=secret.get("Title") or "Найден секрет",
                        severity=Severity.from_trivy(secret.get("Severity", "")),
                        description=secret.get("Title") or "",
                        package=None,
                        pkg_type="secret",
                        location=where,
                    )
                )
        return findings
