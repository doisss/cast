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
from cast.report.console import _BENCH_MARKS, _BENCH_SECTIONS
from cast.report.sections import (STATUS_HELP, build_sections, container_image_note,
                                  sort_status_findings)
from cast.scanners import ALL_SCANNERS, ProgressUI
from cast.targets import KIND_TITLES, Target, TargetError, resolve_target, run_docker
from cast.web import auth as web_auth

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


def docker_suggestions() -> dict:
    """Запущенные контейнеры и локальные образы — чтобы выбрать цель одним щелчком."""
    containers, images = [], []
    ps = run_docker("ps", "--format", "{{.Names}}\t{{.Image}}")
    if ps is not None and ps.returncode == 0:
        for line in ps.stdout.splitlines():
            name, _, image = line.partition("\t")
            if name:
                containers.append({"name": name, "image": image})
    im = run_docker("images", "--format", "{{.Repository}}:{{.Tag}}")
    if im is not None and im.returncode == 0:
        images = [x for x in im.stdout.splitlines() if x and "<none>" not in x][:12]
    return {"docker": ps is not None and ps.returncode == 0,
            "containers": containers, "images": images}


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
        self.token = secrets.token_urlsafe(24)
        self.env = Environment(loader=FileSystemLoader(_TEMPLATES_DIR),
                               autoescape=select_autoescape(["html", "jinja"]))
        self.env.globals.update(version=__version__, token=self.token,
                                kind_titles=KIND_TITLES, status_help=STATUS_HELP,
                                marks=_marks, auth_on=auth is not None)

    def render(self, name: str, **ctx) -> str:
        return self.env.get_template(name).render(**ctx)

    def page_index(self) -> str:
        return self.render("index.html.jinja", engines=engines_info(),
                           suggest=docker_suggestions(), jobs=self.store.recent())

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
                sections.append(data)
        return self.render("job.html.jinja", job=job, result=job.result,
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
                if parts[-1:] == ["status"]:     # опрос хода проверки из страницы — без перехода
                    return self._send('{"error": "login"}', "application/json; charset=utf-8", 401)
                return self._send("", status=303, extra={"Location": "/login"})
            if not parts:
                return self._send(app.page_index())
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
            if path not in ("/jobs", "/login"):
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
                return self._send("", status=303, extra={"Location": "/login"})
            query = form.get("target", [""])[0].strip()
            if not query:
                return self._send("", status=303, extra={"Location": "/"})
            engines = form.get("engine") or None
            job = app.store.submit(query, engines, form.get("requirements", [""])[0].strip())
            return self._send("", status=303, extra={"Location": f"/jobs/{job.id}"})

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
        import webbrowser
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()
    return 0
