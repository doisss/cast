"""
Веб-интерфейс cast: `cast web` поднимает страницу в браузере поверх того же
pipeline.run_scan(), что и консоль. Логика проверки не дублируется: веб только
принимает цель, запускает проверку в фоне и рисует ScanResult.

Без новых зависимостей: встроенный http.server и Jinja2 (она уже нужна HTML-отчёту).
По умолчанию открыт в сеть: зайти можно и с этой машины, и с другой (например, с
хоста на ВМ); --local — только с этой машины. Запросы принимаются только по
адресам и имени этой машины, вход — по логину и паролю (cast/web/auth.py), а
POST-запросы проверяются токеном: чужая страница в браузере не может запустить
проверку на этой машине.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
from http.cookies import CookieError, SimpleCookie
import socket
import queue
import secrets
import shlex
import subprocess
import threading
import time
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from jinja2 import Environment, FileSystemLoader, select_autoescape

from cast import __version__
from cast.context import ScanContext
from cast.pipeline import EngineSelectionError, ScanResult, run_scan
from cast.report import html_report, json_report
from cast.report.console import (_BENCH_MARKS, _BENCH_SECTIONS, _SHOW_WHERE, _group_by_place, _has_lines,
                                 _merge_same, _message_differs)
from cast.report.fix_hint import CHANGE, EXISTS, hint_lines
from cast.report.sections import (STATUS_HELP, build_sections, container_image_note,
                                  sort_status_findings)
from cast.scanners import ALL_SCANNERS, ProgressUI
from cast.targets import KIND_TITLES, Target, TargetError, resolve_target, run_docker
from cast.web import auth as web_auth
from cast.web import files as web_files
from cast.web.discover import Discovery, user_home

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_FAVICON = (Path(__file__).parent / "static" / "favicon.svg").read_bytes()
_SEVERITIES = ("critical", "high", "medium", "low", "unknown")


@dataclass
class Job:
    """Одна проверка, запущенная из браузера."""

    id: int
    query: str
    engines: list[str] | None
    requirements: str = ""
    state: str = "queued"          # queued | running | done | error
    target: Target | None = None
    engine: str = ""               # какой движок работает сейчас
    text: str = ""                 # что он делает (ProgressUI.say)
    fraction: float | None = None  # полоса загрузки (ProgressUI.progress)
    label: str = ""
    log: list[str] = field(default_factory=list)
    error: str = ""
    result: ScanResult | None = None
    created: float = field(default_factory=time.time)
    started: float = 0.0
    finished: float = 0.0

    def status(self) -> dict:
        now = self.finished or time.time()
        return {
            "id": self.id, "state": self.state, "engine": self.engine, "text": self.text,
            "fraction": self.fraction, "label": self.label, "log": self.log[-30:],
            "error": self.error,
            "seconds": round(now - self.started, 1) if self.started else 0,
        }


class _JobUI(ProgressUI):
    def __init__(self, job: Job):
        self.job = job

    def say(self, text: str) -> None:
        self.job.text = text
        self.job.fraction = None
        self.job.log.append(f"{self.job.engine}: {text}")

    def progress(self, fraction: float, label: str = "") -> None:
        self.job.fraction = max(0.0, min(1.0, fraction))
        self.job.label = label


class JobStore:
    """Очередь проверок. Проверки идут по одной: два Trivy одновременно
    спорили бы за свою базу уязвимостей."""

    def __init__(self, runner=run_scan):
        self.jobs: dict[int, Job] = {}
        self._queue: queue.Queue[Job] = queue.Queue()
        self._lock = threading.Lock()
        self._next = 1
        self._runner = runner
        threading.Thread(target=self._work, daemon=True, name="cast-web-worker").start()

    def submit(self, query: str, engines: list[str] | None, requirements: str = "") -> Job:
        with self._lock:
            job = Job(self._next, query, engines, requirements)
            self._next += 1
            self.jobs[job.id] = job
        self._queue.put(job)
        return job

    def recent(self) -> list[Job]:
        return sorted(self.jobs.values(), key=lambda j: j.id, reverse=True)

    def _work(self) -> None:
        while True:
            job = self._queue.get()
            try:
                self._run(job)
            except Exception as exc:  # веб не должен падать из-за одной проверки
                job.state, job.error = "error", f"внутренняя ошибка: {exc}"
            job.finished = time.time()

    def _run(self, job: Job) -> None:
        job.state, job.started = "running", time.time()
        try:
            target = resolve_target(shlex.split(job.query))
        except (TargetError, ValueError) as exc:
            job.state, job.error = "error", str(exc)
            return
        job.target = target
        job.log.extend(f"ⓘ {note}" for note in target.notes)
        context = ScanContext.empty()
        if job.requirements:
            path = Path(job.requirements).expanduser()
            if path.exists():
                context = ScanContext.from_requirements_file(path)
            else:
                job.log.append(f"⚠ файл {path} не найден, приоритизация по зависимостям отключена")

        def on_progress(event: str, scanner, detail: str = "") -> None:
            if event == "start":
                job.engine, job.fraction = scanner.name, None
                job.text = scanner.progress_hint or "работаю"
                job.log.append(f"{scanner.name}: запущен")
            elif event == "done":
                job.log.append(f"{scanner.name}: готово, записей: {detail}")
            elif event == "fail":
                job.log.append(f"{scanner.name}: НЕ ВЫПОЛНЕН: {detail}")

        try:
            job.result = self._runner(target, context=context, on_progress=on_progress,
                                      engines=job.engines, ui=_JobUI(job))
        except EngineSelectionError as exc:
            job.state, job.error = "error", str(exc)
            return
        job.state = "done"


def engines_info() -> list[dict]:
    """То же, что `cast engines`, но данными."""
    info = []
    for cls in ALL_SCANNERS:
        engine = cls()
        available = engine.is_available()
        info.append({
            "name": engine.name,
            "available": available,
            "version": engine.version() if available else None,
            "path": engine.path() if available else None,
            "description": engine.description,
            "targets": [KIND_TITLES[k] for k in KIND_TITLES if k in engine.targets],
        })
    return info


def _code_lines(lines: list[dict]) -> list[dict]:
    """Строки кода как в терминале: номер, отметка [ или ┌ │ └ у строк-причин."""
    causes = [i for i, line in enumerate(lines) if line["is_cause"]]
    out = []
    for i, line in enumerate(lines):
        if not line["is_cause"]:
            mark = " "
        elif len(causes) == 1:
            mark = "["
        else:
            mark = "┌" if i == causes[0] else ("└" if i == causes[-1] else "│")
        out.append({"number": line["number"], "mark": mark, "content": line["content"].rstrip(),
                    "cause": line["is_cause"]})
    return out


def _place_label(place: str, cluster: bool) -> str:
    if not cluster:
        return place + ("" if _has_lines(place) or place == "—" else " — весь файл")
    m = re.search(r":(\d+)(?:-(\d+))?$", place)
    if not m:
        return "весь ресурс"
    return f"строки {m.group(1)}–{m.group(2)}" if m.group(2) else f"строка {m.group(1)}"


def _config_places(findings, cluster: bool = False) -> list[dict]:
    """Ошибки конфигурации по месту в файле — как в терминале: код один раз, правила под ним."""
    places = []
    for place, group in _group_by_place(findings):
        code = next((f.code_lines for f in group if f.code_lines), [])
        rules = []
        for f in sorted(group, key=lambda f: (-f.severity.rank, f.check_id)):
            hint = [{"text": t, "state": "exists" if st == EXISTS else "new",
                     "old": old if st == CHANGE else None}
                    for t, st, old in hint_lines(f.check_id, f.remediation, f.message, f.code_lines or code)]
            rules.append({"f": f, "message": f.message if _message_differs(f) else "", "hint": hint})
        places.append({"place": place, "label": _place_label(place, cluster),
                       "whole_file": not _has_lines(place) and place != "—",
                       "counts": _sev_counts(group), "code": _code_lines(code), "rules": rules,
                       "no_code": not code and _has_lines(place)})
    return places


def what_is(raw: str) -> dict:
    """Что cast увидит в этом пути: та же логика, что у cast scan ПУТЬ."""
    if not raw or not Path(raw).exists():
        return {"ok": False, "text": "такого пути нет"}
    try:
        target = resolve_target([raw])
    except TargetError as exc:
        return {"ok": False, "text": str(exc)}
    title = KIND_TITLES.get(target.kind, target.kind)
    if getattr(target, "subtype", ""):
        title += f" ({target.subtype})"
    return {"ok": True, "text": title}


def _split_location(f) -> tuple[str, str]:
    """У кластера место — «ресурс: что внутри»: «kube-system/Pod/etcd: Pod/etcd:17-29»
    у ошибок конфигурации и «kube-system/Pod/etcd: registry.k8s.io/etcd:3.5 (debian 12)» у уязвимостей."""
    loc = f.location or ""
    resource, sep, rest = loc.partition(": ")
    return (resource, rest) if sep else (loc or "—", "")


def _worst(findings) -> int:
    return max((f.severity.rank for f in findings), default=0)


def _cluster_resources(findings) -> list[dict]:
    """Ошибки конфигурации кластера: по ресурсам, внутри — места, как у файла."""
    groups: dict[str, list] = {}
    for f in findings:
        resource, rest = _split_location(f)
        groups.setdefault(resource, []).append(f)
    out = []
    for resource, group in groups.items():
        out.append({"name": resource, "counts": _sev_counts(group), "total": len(group),
                    "worst": _worst(group), "places": _config_places(group, cluster=True)})
    out.sort(key=lambda g: (-g["worst"], -g["total"], g["name"]))
    return out


def _cluster_vulns(findings) -> list[dict]:
    """Уязвимости кластера: по ресурсам, внутри — по тому, где нашёл Trivy: ОС образа
    («registry.k8s.io/kube-proxy:v1.31.0 (debian 12.5)») или программа в образе
    («usr/local/bin/kube-proxy»)."""
    groups: dict[str, dict[str, list]] = {}
    for f in findings:
        resource, target = _split_location(f)
        groups.setdefault(resource, {}).setdefault(target or resource, []).append(f)
    out = []
    for resource, targets in groups.items():
        parts = []
        for target, group in targets.items():
            os_image = target.endswith(")") and " (" in target
            parts.append({"name": target, "what": "образ" if os_image else "программа в образе",
                          "counts": _sev_counts(group), "total": len(group), "worst": _worst(group),
                          "rows": [{"f": f, "packages": pk} for f, pk in _merge_same(group)]})
        parts.sort(key=lambda t: (-t["worst"], -t["total"], t["name"]))
        every = [f for group in targets.values() for f in group]
        out.append({"name": resource, "targets": parts, "counts": _sev_counts(every),
                    "total": len(every), "worst": _worst(every)})
    out.sort(key=lambda g: (-g["worst"], -g["total"], g["name"]))
    return out


def _sev_counts(findings) -> dict[str, int]:
    counts = dict.fromkeys(_SEVERITIES, 0)
    for f in findings:
        counts[f.severity.value] += 1
    return counts


def _status_counts(findings) -> dict[str, int]:
    counts = {"WARN": 0, "NOTE": 0, "INFO": 0, "PASS": 0}
    for f in findings:
        if f.status in counts:
            counts[f.status] += 1
    return counts


def _bench_groups(findings) -> list[dict]:
    groups: dict[str, list] = {}
    for f in sort_status_findings(findings):
        groups.setdefault(f.section or "", []).append(f)
    out = []
    for key in sorted(groups, key=lambda k: (not k.isdigit(), int(k) if k.isdigit() else 0)):
        ru, en = _BENCH_SECTIONS.get(key, ("Без раздела", ""))
        out.append({"key": key, "ru": ru, "en": en, "findings": groups[key],
                    "counts": _status_counts(groups[key])})
    return out


def _marks(finding) -> list[str]:
    out = []
    for mark in finding.marks:
        if mark in _BENCH_MARKS:
            out.append(_BENCH_MARKS[mark])
        elif mark not in ("Automated", "Scored", "Not Scored"):
            out.append(mark)
    return out


class WebApp:
    def __init__(self, store: JobStore | None = None, auth: web_auth.Auth | None = None):
        self.store = store or JobStore()
        self.auth = auth                 # None — без входа (только в тестах)
        self.discovery = Discovery()
        self.token = secrets.token_urlsafe(24)
        self.env = Environment(loader=FileSystemLoader(_TEMPLATES_DIR),
                               autoescape=select_autoescape(["html", "jinja"]))
        self.env.globals.update(version=__version__, token=self.token,
                                kind_titles=KIND_TITLES, status_help=STATUS_HELP,
                                marks=_marks, auth_on=auth is not None)

    def render(self, name: str, **ctx) -> str:
        return self.env.get_template(name).render(**ctx)

    def page_index(self) -> str:
        return self.render("index.html.jinja", engines=engines_info(), jobs=self.store.recent(),
                           cwd=os.getcwd(), home=str(user_home()), is_root=os.geteuid() == 0)

    def page_job(self, job: Job) -> str:
        sections, note = [], ""
        if job.result is not None:
            note = container_image_note(job.result)
            for sec in build_sections(job.result):
                data = {"sec": sec}
                if sec.kind == "status":
                    data["groups"] = _bench_groups(sec.findings)
                    data["counts"] = _status_counts(sec.findings)
                else:
                    data["counts"] = _sev_counts(sec.findings)
                    if job.result.kind in ("config", "dockerfile"):
                        data["places"] = _config_places(sec.findings)
                    elif job.result.kind == "cluster":
                        configs = [f for f in sec.findings if f.pkg_type == "config"]
                        data["resources"] = _cluster_resources(configs)
                        data["vulns"] = _cluster_vulns([f for f in sec.findings if f.pkg_type != "config"])
                        data["config_counts"] = _sev_counts(configs)
                    else:
                        data["rows"] = [{"f": f, "packages": pk} for f, pk in _merge_same(sec.findings)]
                        data["show_where"] = job.result.kind in _SHOW_WHERE
                sections.append(data)
        need_root = bool(job.result) and os.geteuid() != 0 and any(
            r.name == "docker-bench" and r.status != "ok" for r in job.result.runs)
        return self.render("job.html.jinja", job=job, result=job.result, need_root=need_root,
                           sections=sections, note=note, jobs=self.store.recent())


def make_handler(app: WebApp, port: int, addresses: list[str] | None = None):
    """addresses — адреса этой машины, по которым к ней можно обращаться
    (кроме 127.0.0.1 и localhost, они разрешены всегда)."""
    allowed_hosts = {f"{a}:{port}" for a in ["127.0.0.1", "localhost", *(addresses or [])]}
    cookie_name = f"cast_session_{port}"   # cookie не различают порты: у двух cast web — свои

    class Handler(BaseHTTPRequestHandler):
        server_version = f"cast-web/{__version__}"

        def log_message(self, fmt, *args):  # журнал запросов не нужен в терминале
            pass

        def _send(self, body: str | bytes, ctype: str = "text/html; charset=utf-8",
                  status: int = 200, extra: dict | None = None) -> None:
            data = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            for name, value in (extra or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(data)

        def _allowed(self) -> bool:
            # защита от DNS rebinding: страница с чужого домена не достучится до нас
            if self.headers.get("Host", "") in allowed_hosts:
                return True
            self._send("Неверный адрес", "text/plain; charset=utf-8", 403)
            return False

        def _session(self) -> str | None:
            try:
                morsel = SimpleCookie(self.headers.get("Cookie", "")).get(cookie_name)
            except CookieError:
                return None
            return morsel.value if morsel else None

        def _authed(self) -> bool:
            return app.auth is None or app.auth.valid(self._session())

        def _login_page(self, error: str = "", status: int = 200, login: str = ""):
            return self._send(app.render("login.html.jinja", error=error, login=login, login_page=True),
                              status=status)

        def _login(self, form: dict) -> None:
            addr = self.client_address[0]
            wait = app.auth.blocked(addr)
            if wait:
                return self._login_page(f"Слишком много неверных попыток. Подождите {wait} с.", 429)
            login = form.get("login", [""])[0]
            session = app.auth.check(addr, login, form.get("password", [""])[0])
            if not session:
                wait = app.auth.blocked(addr)
                return self._login_page(
                    f"Слишком много неверных попыток. Подождите {wait} с." if wait
                    else "Неверный логин или пароль", 429 if wait else 401, login)
            cookie = f"{cookie_name}={session}; Path=/; HttpOnly; SameSite=Strict"
            return self._send("", status=303, extra={"Location": "/", "Set-Cookie": cookie})

        def _json(self, data, status: int = 200) -> None:
            self._send(json.dumps(data, ensure_ascii=False), "application/json; charset=utf-8", status)

        def _download(self, raw: str) -> None:
            path = Path(raw)
            if not path.is_file():
                return self._json({"error": "файла нет"}, 404)
            try:
                data = path.read_bytes()
            except OSError as exc:
                return self._json({"error": exc.strerror or str(exc)}, 403)
            name = path.name.replace('"', "")
            return self._send(data, "application/octet-stream",
                              extra={"Content-Disposition": f'attachment; filename="{name}"'})

        def _file_op(self, form: dict) -> None:
            get = lambda key: form.get(key, [""])[0]
            op = get("op")
            try:
                if op == "mkdir":
                    result = {"path": web_files.make_dir(get("path"), get("name"))}
                elif op == "rename":
                    result = {"path": web_files.rename(get("path"), get("name"))}
                elif op == "delete":
                    for raw in form.get("path", []):
                        web_files.delete(raw)
                    result = {}
                else:
                    return self._json({"error": "нет такого действия"}, 400)
            except web_files.FileError as exc:
                return self._json({"error": str(exc)}, 400)
            return self._json({"ok": True, **result})

        def _job(self, raw: str) -> Job | None:
            return app.store.jobs.get(int(raw)) if raw.isdigit() else None

        def do_GET(self):
            if not self._allowed():
                return
            parts = [p for p in urlparse(self.path).path.split("/") if p]
            if parts in (["favicon.svg"], ["favicon.ico"]):   # .ico браузер просит сам, без ссылки
                return self._send(_FAVICON, "image/svg+xml")
            if parts == ["login"]:
                return self._login_page() if app.auth else self._send("", status=303, extra={"Location": "/"})
            if parts == ["logout"]:
                if app.auth:
                    app.auth.logout(self._session())
                gone = f"{cookie_name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"
                return self._send("", status=303, extra={"Location": "/login", "Set-Cookie": gone})
            if not self._authed():
                if parts[-1:] == ["status"] or parts[:1] == ["api"]:   # запросы из страницы — без перехода
                    return self._send('{"error": "login"}', "application/json; charset=utf-8", 401)
                return self._send("", status=303, extra={"Location": "/login"})
            if not parts:
                return self._send(app.page_index())
            if parts[0] == "api" and len(parts) == 2:
                query = parse_qs(urlparse(self.path).query)
                path = query.get("path", [""])[0]
                if parts[1] == "download":
                    return self._download(path)
                if parts[1] == "files":
                    data = web_files.list_dir(path, query.get("hidden", ["0"])[0] == "1")
                elif parts[1] == "what":
                    data = what_is(path)
                elif parts[1] == "view":
                    data = web_files.read_text(path)
                elif parts[1] == "discover":
                    data = app.discovery.get(refresh=query.get("refresh", ["0"])[0] == "1")
                else:
                    return self._json({"error": "нет такого запроса"}, 404)
                return self._json(data)
            if parts[0] == "jobs" and len(parts) >= 2 and (job := self._job(parts[1])):
                if len(parts) == 2:
                    return self._send(app.page_job(job))
                if parts[2] == "status":
                    return self._send(json.dumps(job.status(), ensure_ascii=False),
                                      "application/json; charset=utf-8")
                if parts[2] in ("report.html", "report.json") and job.result is not None:
                    if parts[2] == "report.html":
                        body, ctype = html_report.render_html(job.result), "text/html; charset=utf-8"
                    else:
                        body = json.dumps(json_report.to_dict(job.result), ensure_ascii=False, indent=2)
                        ctype = "application/json; charset=utf-8"
                    name = f"cast-{job.id}.{parts[2].split('.')[1]}"
                    return self._send(body, ctype,
                                      extra={"Content-Disposition": f'attachment; filename="{name}"'})
            return self._send(app.render("missing.html.jinja"), status=404)

        def do_POST(self):
            if not self._allowed():
                return
            path = urlparse(self.path).path
            if path not in ("/jobs", "/login", "/api/fs"):
                return self._send(app.render("missing.html.jinja"), status=404)
            length = min(int(self.headers.get("Content-Length") or 0), 64 * 1024)
            form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            sent = form.get("token", [""])[0].encode("utf-8")
            if not secrets.compare_digest(sent, app.token.encode("utf-8")):
                return self._send("Устаревшая страница, обновите её", "text/plain; charset=utf-8", 403)
            if path == "/login":
                if not app.auth:
                    return self._send("", status=303, extra={"Location": "/"})
                return self._login(form)
            if not self._authed():
                if path == "/api/fs":
                    return self._json({"error": "login"}, 401)
                return self._send("", status=303, extra={"Location": "/login"})
            if path == "/api/fs":
                return self._file_op(form)
            queries = [q.strip() for q in form.get("target", []) if q.strip()]
            if not queries:
                return self._send("", status=303, extra={"Location": "/"})
            engines = form.get("engine") or None
            jobs = [app.store.submit(q, engines, form.get("requirements", [""])[0].strip()) for q in queries]
            # несколько целей сразу (выбрано несколько файлов) — встают в очередь, открываем первую
            return self._send("", status=303, extra={"Location": f"/jobs/{jobs[0].id}"})

    return Handler


def _lan_addresses() -> list[str]:
    """IPv4-адреса этой машины в сетях, откуда можно зайти (без docker и VPN-туннелей)."""
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True,
                             text=True, timeout=5).stdout
    except (OSError, subprocess.TimeoutExpired):
        out = ""
    addrs = []
    for line in out.splitlines():
        fields = line.split()
        if len(fields) < 4 or fields[1].startswith(("lo", "docker", "br-", "veth")):
            continue
        if "/32" in fields[3]:   # точка-точка (VPN) — с хоста по нему не зайти
            continue
        addrs.append(fields[3].split("/")[0])
    if not addrs and not out:
        # нет команды ip: адрес, через который машина ходит в сеть. connect у UDP
        # ничего не отправляет, только выбирает маршрут
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(("192.0.2.1", 9))
                addr = sock.getsockname()[0]
            if not addr.startswith("127."):
                addrs.append(addr)
        except OSError:
            pass
    return addrs


def _host_names() -> list[str]:
    """Имя машины: с другой машины часто заходят по нему (kali:8765, kali.local:8765)."""
    name = socket.gethostname()
    return [name, f"{name}.local"] if name and name != "localhost" else []


def _firewall_hint(port: int) -> str | None:
    """ufw на Debian/Ubuntu по умолчанию выключен; если включён — порт закрыт снаружи."""
    try:
        conf = Path("/etc/ufw/ufw.conf").read_text()
    except OSError:
        return None
    if "ENABLED=yes" in conf.replace(" ", ""):
        return (f"Включён брандмауэр ufw: если с другой машины не открывается, "
                f"разрешите порт: sudo ufw allow {port}/tcp")
    return None


PORT_TRIES = 10   # занят порт — пробуем следующие
# окружение, которое нужно процессу под sudo: где лежат движки, kubeconfig и
# экран пользователя (чтобы открыть ему браузер). sudo сбрасывает окружение
_KEEP_ENV = ("PATH", "PYTHONPATH", "KUBECONFIG", "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY",
             "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "LANG", "LC_ALL", "TERM")


def sudo_command(argv: list[str], environ=None) -> list[str]:
    """Та же команда cast web, но от root: sudo env ПЕРЕМЕННЫЕ python -m cast web …
    Через env, а не sudo --preserve-env: env — обычная команда, sudo разрешает её
    всем, кому разрешено sudo, без отдельного права SETENV."""
    environ = os.environ if environ is None else environ
    keep = [f"{k}={environ[k]}" for k in _KEEP_ENV if environ.get(k)]
    if not environ.get("KUBECONFIG"):
        kube = Path(environ.get("HOME", str(Path.home()))) / ".kube" / "config"
        if kube.is_file():           # у root своего kubeconfig нет — берём пользователя
            keep.append(f"KUBECONFIG={kube}")
    return ["sudo", "--", "env", *keep, sys.executable, "-m", "cast", *argv]


def rerun_with_sudo(console=None, run=subprocess.call) -> int | None:
    """Перезапустить cast web от root. None — не нужно (уже root) или нельзя (нет sudo):
    тогда веб работает от текущего пользователя."""
    say = console.print if console else print
    if os.geteuid() == 0:
        return None
    if not shutil.which("sudo"):
        say("sudo не найден — веб работает от текущего пользователя: host и Docker "
            "проверить не получится.")
        return None
    say("host и Docker проверяются только от root — запускаю cast web через sudo "
        "(без root: cast web --no-sudo).")
    try:
        return run(sudo_command(sys.argv[1:]))
    except KeyboardInterrupt:
        return 130


def _open_browser(url: str) -> None:
    """Под sudo браузер открываем тому, кто запустил sudo: браузер от root не нужен
    (а Firefox и Chrome от root и не запускаются)."""
    user = os.environ.get("SUDO_USER")
    if os.geteuid() == 0 and user and user != "root":
        gui = [f"{k}={os.environ[k]}" for k in _KEEP_ENV[3:8] if os.environ.get(k)]
        if not gui or not shutil.which("xdg-open"):
            return                    # нет экрана (зашли по ssh) — адрес и так напечатан
        try:
            subprocess.Popen(["sudo", "-u", user, "env", *gui, "xdg-open", url],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            pass
        return
    import webbrowser
    webbrowser.open(url)


def _load_auth(say, reset: bool, path=None) -> web_auth.Auth | None:
    """Логин и пароль из ~/.config/cast/web.json; при первом запуске — спросить и сохранить."""
    found = None if reset else web_auth.load(path)
    if found:
        return web_auth.Auth(*found)
    if not sys.stdin.isatty():
        say("Ошибка: для входа в веб нужен логин и пароль, а спросить их негде "
            "(cast web запущен не из терминала). Запустите cast web один раз в терминале.")
        return None
    say("Вход в веб — по логину и паролю. Задайте их (спрашиваю один раз, "
        "сменить: cast web --reset-password).")
    login, password = web_auth.ask(say)
    saved = web_auth.save(login, web_auth.hash_password(password), path)
    say(f"Сохранено в {saved} (пароль — в виде хэша, не открытым текстом)")
    return web_auth.Auth(*web_auth.load(path))


def serve(port: int = 8765, open_browser: bool = True, console=None,
          local: bool = False, port_fixed: bool = False, reset_password: bool = False,
          auth_path=None) -> int:
    """local — слушать только 127.0.0.1; иначе все адреса машины (0.0.0.0).
    port_fixed — порт задан явно (--port): если занят, не подбирать другой."""
    say = console.print if console else print
    host = "127.0.0.1" if local else "0.0.0.0"
    auth = _load_auth(say, reset_password, auth_path)
    if auth is None:
        return 2
    addresses = [] if local else _lan_addresses()
    app = WebApp(auth=auth)
    httpd, error = None, None
    for candidate in [port] if port_fixed else range(port, port + PORT_TRIES):
        try:
            httpd = ThreadingHTTPServer(
                (host, candidate), make_handler(app, candidate, addresses + _host_names()))
            break
        except OSError as exc:
            error = exc
    if httpd is None:
        busy = f"{port}" if port_fixed else f"{port}–{port + PORT_TRIES - 1}"
        say(f"Ошибка: не удалось слушать порт {busy}: {error.strerror}. "
            "Укажите другой: cast web --port 9000")
        return 2
    if httpd.server_address[1] != port:
        say(f"Порт {port} занят — беру {httpd.server_address[1]}")
    port = httpd.server_address[1]
    url = f"http://127.0.0.1:{port}/"
    say(f"Веб-интерфейс cast: {url}  (логин: {auth.login})")
    if os.geteuid() == 0:
        say("Работает от root: host и Docker проверяются. Свой кэш Trivy у root отдельный — "
            "первая проверка скачает базу уязвимостей заново.")
    else:
        say("Работает без root: host и запущенные контейнеры проверить не получится.")
    if local:
        say("Доступен только с этой машины (--local). Остановить: Ctrl+C")
    else:
        for addr in addresses:
            say(f"С другой машины:   http://{addr}:{port}/")
        if not addresses:
            say("Адрес в сети не найден (машина не подключена к сети?) — пока доступен только отсюда.")
        hint = _firewall_hint(port)
        if hint:
            say(hint)
        say("Только с этой машины: cast web --local. Остановить: Ctrl+C")
    if open_browser:
        threading.Timer(0.5, _open_browser, args=(url,)).start()
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()
    return 0
