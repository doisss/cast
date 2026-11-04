"""Веб-интерфейс: страницы, очередь проверок и защита (только локальный адрес, токен)."""

import json
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from cast.cli import main
from cast.models import Finding, Severity
from cast.pipeline import run_scan
from cast.web import server as web
from tests.test_pipeline import FakeScanner


def _findings():
    return [
        Finding(source_tool="trivy", check_id="CVE-2024-0001", title="уязвимость <b>",
                severity=Severity.CRITICAL, package="openssl", installed_version="3.0.1",
                fixed_version="3.0.9", remediation=None, url="https://avd.example/CVE-2024-0001"),
        Finding(source_tool="trivy", check_id="CVE-2024-0002", title="вторая",
                severity=Severity.LOW, package="zlib", installed_version="1.2"),
    ]


def _fake_runner(target, **kw):
    scanners = [FakeScanner("trivy", _findings())]
    return run_scan(target, scanners=scanners, **kw)


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setattr(web, "docker_suggestions",
                        lambda: {"docker": True, "containers": [{"name": "web1", "image": "nginx"}],
                                 "images": ["alpine:3.19"]})
    monkeypatch.setattr(web, "engines_info", lambda: [])
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    application = web.WebApp(web.JobStore(runner=_fake_runner))
    httpd = ThreadingHTTPServer(("127.0.0.1", port), web.make_handler(application, port))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield application, f"http://127.0.0.1:{port}"
    httpd.shutdown()
    httpd.server_close()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


def _post(base, data):
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        opener.open(base + "/jobs", urllib.parse.urlencode(data, doseq=True).encode())
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Location")
    return 200, None


def _wait(application, job_id):
    for _ in range(100):
        if application.store.jobs[job_id].state in ("done", "error"):
            return application.store.jobs[job_id]
        time.sleep(0.05)
    raise AssertionError("проверка не закончилась")


def test_index_shows_suggestions_and_token(app):
    application, base = app
    html = urllib.request.urlopen(base + "/").read().decode()
    assert "Что проверить?" in html
    assert "container web1" in html and "alpine:3.19" in html
    assert application.token in html


def test_scan_runs_and_report_page_escapes_and_links(app):
    application, base = app
    code, location = _post(base, {"token": application.token, "target": "image alpine:3.19"})
    assert code == 303 and location == "/jobs/1"
    job = _wait(application, 1)
    assert job.state == "done"
    html = urllib.request.urlopen(base + "/jobs/1").read().decode()
    assert "CVE-2024-0001" in html and "→ 3.0.9" in html
    assert "уязвимость &lt;b&gt;" in html          # данные движка экранируются
    assert "исправления нет" in html               # у второй находки нет fixed_version
    status = json.loads(urllib.request.urlopen(base + "/jobs/1/status").read())
    assert status["state"] == "done"
    report = json.loads(urllib.request.urlopen(base + "/jobs/1/report.json").read())
    assert report["summary"]["critical"] == 1


def test_bad_target_shows_error(app):
    application, base = app
    _post(base, {"token": application.token, "target": "config"})
    job = _wait(application, 1)
    assert job.state == "error" and job.error
    assert "Ошибка" in urllib.request.urlopen(base + "/jobs/1").read().decode()


def test_post_without_token_is_refused(app):
    application, base = app
    code, _ = _post(base, {"token": "чужой", "target": "alpine"})
    assert code == 403
    assert application.store.jobs == {}


def test_foreign_host_header_is_refused(app):
    _, base = app
    req = urllib.request.Request(base + "/", headers={"Host": "evil.example:80"})
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req)
    assert exc.value.code == 403


def test_unknown_page_is_404(app):
    _, base = app
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(base + "/jobs/99")
    assert exc.value.code == 404


def test_cli_web_reports_busy_port(capsys, monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    web.web_auth.save("d", web.web_auth.hash_password("secret-pass"))
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen()
        port = s.getsockname()[1]
        assert main(["web", "--port", str(port), "--no-browser"]) == 2
    assert "не удалось слушать" in capsys.readouterr().out


def test_lan_mode_accepts_machine_address_only():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    application = web.WebApp(web.JobStore(runner=_fake_runner))
    httpd = ThreadingHTTPServer(("127.0.0.1", port),
                                web.make_handler(application, port, ["192.168.0.196"]))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{port}"
        ok = urllib.request.Request(base + "/missing", headers={"Host": f"192.168.0.196:{port}"})
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(ok)
        assert exc.value.code == 404           # адрес машины принят (страницы просто нет)
        bad = urllib.request.Request(base + "/", headers={"Host": f"evil.example:{port}"})
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(bad)
        assert exc.value.code == 403
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_lan_addresses_skip_docker_vpn_and_loopback(monkeypatch):
    out = ("1: lo    inet 127.0.0.1/8 scope host lo\n"
           "2: eth0    inet 192.168.0.196/24 brd 192.168.0.255 scope global eth0\n"
           "3: docker0    inet 172.17.0.1/16 scope global docker0\n"
           "4: br-26bf    inet 172.18.0.1/16 scope global br-26bf\n"
           "5: amn0    inet 10.8.1.3/32 scope global amn0\n")
    monkeypatch.setattr(web.subprocess, "run",
                        lambda *a, **k: type("R", (), {"stdout": out})())
    assert web._lan_addresses() == ["192.168.0.196"]


def test_favicon_is_served_and_linked(app):
    _, base = app
    for path in ("/favicon.svg", "/favicon.ico"):
        resp = urllib.request.urlopen(base + path)
        assert resp.headers["Content-Type"] == "image/svg+xml"
        assert resp.read().startswith(b"<svg")
    assert '<link rel="icon"' in urllib.request.urlopen(base + "/").read().decode()


def _fake_serve(monkeypatch, tmp_path):
    """serve() без вечного цикла: запоминаем, на каком адресе он слушал бы."""
    bound = {}
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    web.web_auth.save("d", web.web_auth.hash_password("secret-pass"))

    class FakeServer:
        def __init__(self, address, handler):
            if address[1] in bound.get("busy", ()):
                raise OSError(98, "Address already in use")
            self.server_address = address
            bound["address"] = address

        def serve_forever(self):
            pass

        def server_close(self):
            pass

    monkeypatch.setattr(web, "ThreadingHTTPServer", FakeServer)
    monkeypatch.setattr(web, "_lan_addresses", lambda: ["192.168.0.196"])
    monkeypatch.setattr(web, "_firewall_hint", lambda port: None)
    return bound


def test_web_is_open_to_lan_by_default(monkeypatch, tmp_path):
    bound = _fake_serve(monkeypatch, tmp_path)
    said = []
    assert web.serve(open_browser=False, console=type("C", (), {"print": staticmethod(said.append)})()) == 0
    assert bound["address"] == ("0.0.0.0", 8765)
    assert any("http://192.168.0.196:8765/" in line for line in said)


def test_web_local_listens_on_loopback_only(monkeypatch, tmp_path):
    bound = _fake_serve(monkeypatch, tmp_path)
    web.serve(open_browser=False, console=type("C", (), {"print": staticmethod(lambda *_: None)})(),
              local=True)
    assert bound["address"] == ("127.0.0.1", 8765)


def test_busy_port_takes_next_unless_given(monkeypatch, tmp_path):
    bound = _fake_serve(monkeypatch, tmp_path)
    bound["busy"] = {8765}
    quiet = type("C", (), {"print": staticmethod(lambda *_: None)})()
    assert web.serve(open_browser=False, console=quiet) == 0
    assert bound["address"][1] == 8766
    del bound["address"]
    assert web.serve(8765, open_browser=False, console=quiet, port_fixed=True) == 2
    assert "address" not in bound



# ------------------------------------------------------------------ вход по паролю
from cast.web import auth as web_auth  # noqa: E402


def test_password_is_stored_as_hash_with_private_rights(tmp_path):
    path = web_auth.save("d", web_auth.hash_password("secret-pass"), tmp_path / "cast" / "web.json")
    text = path.read_text()
    assert "secret-pass" not in text and "scrypt$" in text
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    login, stored = web_auth.load(path)
    assert login == "d" and web_auth.verify_password("secret-pass", stored)
    assert not web_auth.verify_password("wrong", stored)


def test_login_blocked_after_five_failures():
    now = [0.0]
    a = web_auth.Auth("d", web_auth.hash_password("secret-pass"), clock=lambda: now[0])
    for _ in range(5):
        assert a.check("10.0.0.5", "d", "wrong") is None
    assert a.blocked("10.0.0.5") == 60
    assert a.check("10.0.0.5", "d", "secret-pass") is None      # верный пароль тоже не пускаем
    assert a.blocked("10.0.0.6") == 0                            # другой адрес не затронут
    now[0] = 61
    assert a.valid(a.check("10.0.0.5", "d", "secret-pass"))


def test_first_run_asks_and_saves(monkeypatch, tmp_path):
    monkeypatch.setattr(web.sys, "stdin", type("T", (), {"isatty": staticmethod(lambda: True)})())
    secrets_typed = iter(["short", "secret-pass", "secret-pass"])
    real_ask = web_auth.ask
    monkeypatch.setattr(web_auth, "ask", lambda say: real_ask(
        say, read=lambda _: "admin", read_secret=lambda _: next(secrets_typed)))
    said = []
    auth = web._load_auth(said.append, reset=False, path=tmp_path / "web.json")
    assert auth.login == "admin"
    assert any("короче 8" in line for line in said)
    assert web_auth.load(tmp_path / "web.json")[0] == "admin"


def test_no_terminal_and_no_password_refuses(monkeypatch, tmp_path):
    monkeypatch.setattr(web.sys, "stdin", type("T", (), {"isatty": staticmethod(lambda: False)})())
    said = []
    assert web._load_auth(said.append, reset=False, path=tmp_path / "web.json") is None
    assert "не из терминала" in said[0]




@pytest.fixture
def auth_app(monkeypatch):
    monkeypatch.setattr(web, "docker_suggestions", lambda: {"docker": False, "containers": [], "images": []})
    monkeypatch.setattr(web, "engines_info", lambda: [])
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    application = web.WebApp(web.JobStore(runner=_fake_runner),
                             auth=web_auth.Auth("d", web_auth.hash_password("secret-pass")))
    httpd = ThreadingHTTPServer(("127.0.0.1", port), web.make_handler(application, port))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield application, f"http://127.0.0.1:{port}", port
    httpd.shutdown()
    httpd.server_close()


def _req(url, data=None, cookie=None):
    opener = urllib.request.build_opener(_NoRedirect)
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers={"Cookie": cookie} if cookie else {})
    try:
        return opener.open(req)
    except urllib.error.HTTPError as exc:
        return exc


def test_pages_need_login(auth_app):
    application, base, port = auth_app
    resp = _req(base + "/")
    assert resp.status == 303 and resp.headers["Location"] == "/login"
    assert _req(base + "/jobs/1/status").status == 401
    assert _req(base + "/jobs", {"token": application.token, "target": "alpine"}).status == 303
    assert not application.store.jobs                           # без входа проверка не запущена
    assert "Вход" in _req(base + "/login").read().decode()


def test_login_logout_flow(auth_app):
    application, base, port = auth_app
    bad = _req(base + "/login", {"token": application.token, "login": "d", "password": "nope"})
    assert bad.status == 401 and "Неверный логин" in bad.read().decode()
    ok = _req(base + "/login", {"token": application.token, "login": "d", "password": "secret-pass"})
    assert ok.status == 303
    cookie = ok.headers["Set-Cookie"].split(";")[0]
    assert cookie.startswith(f"cast_session_{port}=") and "HttpOnly" in ok.headers["Set-Cookie"]
    page = _req(base + "/", cookie=cookie)
    assert page.status == 200 and "Выйти" in page.read().decode()
    _req(base + "/logout", cookie=cookie)
    assert _req(base + "/", cookie=cookie).status == 303        # после выхода сессии нет
