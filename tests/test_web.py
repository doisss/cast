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


class _FakeDiscovery:
    def get(self, refresh=False):
        return {"running": False, "files": {"dockerfile": ["/srv/app/Dockerfile"]}, "cut": False,
                "roots": ["/srv"], "seconds": 0.1, "kube": False, "context": "", "error": "",
                "docker": {"docker": True, "containers": [{"name": "web1", "image": "nginx", "status": "Up"}],
                           "images": [{"ref": "alpine:3.19", "size": "7MB"}]}}


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setattr(web, "Discovery", _FakeDiscovery)
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
    assert "Что проверить?" in html and 'id="fm"' in html
    assert application.token in html
    found = json.loads(urllib.request.urlopen(base + "/api/discover").read())
    assert found["docker"]["containers"][0]["name"] == "web1"
    assert found["files"]["dockerfile"] == ["/srv/app/Dockerfile"]


def test_scan_runs_and_report_page_escapes_and_links(app):
    application, base = app
    code, location = _post(base, {"token": application.token, "target": "image alpine:3.19"})
    assert code == 303 and location == "/jobs/1"
    job = _wait(application, 1)
    assert job.state == "done"
    html = urllib.request.urlopen(base + "/jobs/1").read().decode()
    assert "CVE-2024-0001" in html and "3.0.9" in html and ">openssl<" in html
    assert "Приор." not in html and "базовая критичность" not in html
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
        assert main(["web", "--port", str(port), "--no-browser", "--no-sudo"]) == 2
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
    monkeypatch.setattr(web, "Discovery", _FakeDiscovery)
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



def test_file_panel_lists_dirs_first_and_detects_kind(tmp_path):
    (tmp_path / "b.txt").write_text("x")
    (tmp_path / "Dockerfile").write_text("FROM alpine:3.19\n")
    (tmp_path / "a-dir").mkdir()
    (tmp_path / ".secret").write_text("x")
    listing = web.web_files.list_dir(str(tmp_path))
    assert [e["name"] for e in listing["entries"]] == ["a-dir", "b.txt", "Dockerfile"]
    assert [e["kind"] for e in listing["entries"]] == ["папка", "txt", "файл"]
    assert all(e["mtime"] > 0 for e in listing["entries"])
    assert ".secret" in [e["name"] for e in web.web_files.list_dir(str(tmp_path), show_hidden=True)["entries"]]
    assert web.what_is(str(tmp_path / "Dockerfile")) == {"ok": True, "text": "Dockerfile"}
    assert web.what_is(str(tmp_path / "нет")) ["ok"] is False


def test_file_api_needs_login(auth_app):
    application, base, port = auth_app
    assert _req(base + "/api/files?path=/").status == 401


def test_config_page_groups_by_place_with_terminal_code():
    from cast.pipeline import ScanResult, ScannerRun
    from cast.targets import Target
    code = [{"number": 16, "content": "          securityContext:", "is_cause": True},
            {"number": 17, "content": "            privileged: true", "is_cause": True}]
    f = Finding(source_tool="trivy", check_id="KSV-0017", title="Privileged", severity=Severity.HIGH,
                remediation="Change 'containers[].securityContext.privileged' to 'false'.",
                location="deploy.yaml:16-17", code_lines=code,
                message="Container 'web' of Deployment 'web' should set 'securityContext.privileged' to false")
    f.confirmed_by = ["trivy"]
    result = ScanResult(image="deploy.yaml", findings=[f], target=Target("config", "deploy.yaml"),
                        runs=[ScannerRun("trivy", "config", "ok", "", 1, 1.0)])
    application = web.WebApp(web.JobStore(runner=_fake_runner))
    job = web.Job(1, "deploy.yaml", None, state="done", target=result.target, result=result)
    html = application.page_job(job)
    assert "▌ deploy.yaml:16-17" in html and "Код из файла" in html
    assert '<span class="mk">┌</span>' in html and '<span class="mk">└</span>' in html
    assert 'class="h-exists">    securityContext:' in html
    assert "сейчас" not in html
    assert 'class="h-new">      privileged: false' in html
    assert "зелёным</span> — добавить или изменить" in html


def test_password_file_under_sudo_is_the_users(monkeypatch, tmp_path):
    """sudo cast web берёт тот же файл, что и cast web без sudo, и оставляет его пользователю."""
    import pwd
    home = tmp_path / "home-d"
    home.mkdir()
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setattr(web_auth.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1000")
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: type("P", (), {"pw_dir": str(home)})())
    assert web_auth.config_path() == home / ".config" / "cast" / "web.json"
    chowned = []
    monkeypatch.setattr(web_auth.os, "chown", lambda p, u, g: chowned.append((str(p), u, g)))
    real_stat = type(home).stat
    monkeypatch.setattr(type(home), "stat", lambda self, **kw: type("S", (), {
        "st_uid": 0, "st_mode": real_stat(self).st_mode})())
    web_auth.save("d", web_auth.hash_password("secret-pass"))
    assert (str(home / ".config" / "cast" / "web.json"), 1000, 1000) in chowned


def test_file_api_needs_login_for_changes(auth_app):
    application, base, port = auth_app
    assert _req(base + "/api/fs", {"token": application.token, "op": "mkdir", "path": "/tmp", "name": "x"}).status == 401
    assert _req(base + "/api/discover").status == 401
    assert _req(base + "/api/view?path=/etc/hostname").status == 401


def _login(base, application):
    r = _req(base + "/login", {"token": application.token, "login": "d", "password": "secret-pass"})
    return r.headers["Set-Cookie"].split(";")[0]


def test_file_operations_through_api(auth_app, tmp_path):
    application, base, port = auth_app
    cookie = _login(base, application)
    fs = lambda **kw: json.loads(_req(base + "/api/fs", {"token": application.token, **kw}, cookie).read())
    assert fs(op="mkdir", path=str(tmp_path), name="new")["path"] == str(tmp_path / "new")
    assert fs(op="rename", path=str(tmp_path / "new"), name="renamed")["ok"]
    assert (tmp_path / "renamed").is_dir()
    (tmp_path / "renamed" / "f.txt").write_text("привет")
    view = json.loads(_req(base + "/api/view?path=" + urllib.parse.quote(str(tmp_path / "renamed" / "f.txt")),
                           cookie=cookie).read())
    assert view == {"ok": True, "text": "привет"}
    assert fs(op="delete", path=str(tmp_path / "renamed"))["ok"]
    assert not (tmp_path / "renamed").exists()
    bad = _req(base + "/api/fs", {"token": application.token, "op": "delete", "path": "/usr"}, cookie)
    assert bad.status == 400 and "системная" in json.loads(bad.read())["error"]
    bad = _req(base + "/api/fs", {"token": "wrong", "op": "mkdir", "path": str(tmp_path), "name": "y"}, cookie)
    assert bad.status == 403 and not (tmp_path / "y").exists()


def test_file_names_cannot_escape_folder(tmp_path):
    with pytest.raises(web.web_files.FileError):
        web.web_files.make_dir(str(tmp_path), "../evil")
    with pytest.raises(web.web_files.FileError):
        web.web_files.rename("/", "x")
    (tmp_path / "bin.dat").write_bytes(b"\0\1\2")
    assert web.web_files.read_text(str(tmp_path / "bin.dat"))["ok"] is False


def test_several_targets_queue_several_jobs(app):
    application, base = app
    code, location = _post(base, {"token": application.token, "target": ["alpine:3.19", "nginx:1"]})
    assert code == 303 and location == "/jobs/1"
    assert [j.query for j in application.store.recent()] == ["nginx:1", "alpine:3.19"]


def test_discovery_finds_what_cast_can_scan(tmp_path):
    from cast.web.discover import scan_files
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "Dockerfile").write_text("FROM alpine:3.19\n")
    (tmp_path / "app" / "requirements.txt").write_text("django==2.2\n")
    (tmp_path / "app" / ".git").mkdir()
    (tmp_path / "k8s").mkdir()
    (tmp_path / "k8s" / "deploy.yaml").write_text("apiVersion: v1\nkind: Pod\n")
    (tmp_path / "k8s" / "tpl.yaml").write_text("apiVersion: v1\nkind: Pod\nname: {{ .Values.x }}\n")
    (tmp_path / "chart" / "templates").mkdir(parents=True)
    (tmp_path / "chart" / "Chart.yaml").write_text("name: c\n")
    (tmp_path / "chart" / "templates" / "d.yaml").write_text("apiVersion: v1\nkind: Pod\n")
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "Dockerfile").write_text("FROM x\n")
    (tmp_path / "dockerfile.cast.json").write_text("{}")
    found, cut = scan_files([tmp_path])
    assert not cut
    assert found["dockerfile"] == [str(tmp_path / "app" / "Dockerfile")]
    assert found["Kubernetes"] == [str(tmp_path / "k8s" / "deploy.yaml")]
    assert found["Helm"] == [str(tmp_path / "chart")]
    assert found["project"] == [str(tmp_path / "app")] and found["git"] == [str(tmp_path / "app")]


def test_cluster_page_groups_by_resource_and_image():
    from cast.pipeline import ScanResult, ScannerRun
    from cast.targets import Target
    conf = Finding(source_tool="trivy", check_id="KSV-0014", title="RO fs", severity=Severity.HIGH,
                   remediation="Change 'containers[].securityContext.readOnlyRootFilesystem' to 'true'.",
                   location="cast-demo/Deployment/web: Deployment/web:33-48", pkg_type="config",
                   message="Container 'web' of Deployment 'web' should set 'securityContext.readOnlyRootFilesystem' to true",
                   code_lines=[{"number": 40, "content": "        securityContext:", "is_cause": True}])
    vuln = Finding(source_tool="trivy", check_id="CVE-2026-1", title="bug", severity=Severity.CRITICAL,
                   package="openssl", installed_version="3.0", fixed_version="3.1",
                   location="cast-demo/Deployment/web: alpine:3.18.0 (alpine 3.18.0)")
    for f in (conf, vuln):
        f.confirmed_by = ["trivy"]
    result = ScanResult(image="cluster", findings=[conf, vuln], target=Target("cluster", "cluster"),
                        runs=[ScannerRun("trivy", "cluster", "ok", "", 2, 1.0)])
    application = web.WebApp(web.JobStore(runner=_fake_runner))
    html = application.page_job(web.Job(1, "cluster", None, state="done", target=result.target, result=result))
    assert "Ошибки конфигурации ресурсов" in html and "Уязвимости в образах" in html
    assert "▌ строки 33–48" in html and "readOnlyRootFilesystem: true" in html
    assert "▌ alpine:3.18.0 (alpine 3.18.0)" in html and "1 шт., ресурсов: 1" in html
    assert "class=\"mono nowrap\"" not in html and "small nowrap" not in html


def test_web_reruns_itself_with_sudo(monkeypatch, tmp_path):
    (tmp_path / ".kube").mkdir()
    (tmp_path / ".kube" / "config").write_text("x")
    cmd = web.sudo_command(["web", "--port", "9000"], {"PATH": "/home/d/.local/bin:/usr/bin", "HOME": str(tmp_path)})
    assert cmd[:3] == ["sudo", "--", "env"]
    assert "PATH=/home/d/.local/bin:/usr/bin" in cmd and f"KUBECONFIG={tmp_path}/.kube/config" in cmd
    assert cmd[-5:] == ["-m", "cast", "web", "--port", "9000"]
    ran = []
    monkeypatch.setattr(web.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(web.shutil, "which", lambda name: "/usr/bin/sudo")
    assert web.rerun_with_sudo(run=lambda c: ran.append(c) or 0) == 0 and ran[0][0] == "sudo"
    monkeypatch.setattr(web.os, "geteuid", lambda: 0)
    assert web.rerun_with_sudo(run=lambda c: 1 / 0) is None     # уже root — не перезапускаем


def test_no_sudo_flag_skips_rerun(monkeypatch, tmp_path):
    monkeypatch.setattr(web, "rerun_with_sudo", lambda console=None: pytest.fail("sudo не нужен"))
    monkeypatch.setattr(web, "serve", lambda *a, **kw: 0)
    assert main(["web", "--no-sudo"]) == 0


def test_folder_page_shows_configs_per_file_and_versions_per_package():
    from cast.pipeline import ScanResult, ScannerRun
    from cast.targets import Target
    conf = Finding(source_tool="trivy", check_id="KSV-0017", title="Privileged", severity=Severity.HIGH,
                   remediation="Change 'containers[].securityContext.privileged' to 'false'.",
                   location="deploy.yaml:16-17", pkg_type="config",
                   message="Container 'web' of Deployment 'web' should set 'securityContext.privileged' to false",
                   code_lines=[{"number": 16, "content": "          securityContext:", "is_cause": True},
                               {"number": 17, "content": "            privileged: true", "is_cause": True}])
    a = Finding(source_tool="trivy", check_id="CVE-2026-7", title="mount", severity=Severity.HIGH,
                package="bsdutils", installed_version="1:2.41.5", location="requirements.txt")
    b = Finding(source_tool="trivy", check_id="CVE-2026-7", title="mount", severity=Severity.HIGH,
                package="libblkid1", installed_version="2.41.5", location="requirements.txt")
    for f in (conf, a, b):
        f.confirmed_by = ["trivy"]
    result = ScanResult(image=".", findings=[conf, a, b], target=Target("fs", "/x"),
                        runs=[ScannerRun("trivy", "fs", "ok", "", 3, 1.0)])
    application = web.WebApp(web.JobStore(runner=_fake_runner))
    html = application.page_job(web.Job(1, "/x", None, state="done", target=result.target, result=result))
    assert "Ошибки конфигурации в файлах" in html and "Уязвимые пакеты" in html
    assert '<span class="mono">deploy.yaml</span>' in html and "▌ строки 16–17" in html
    assert 'class="h-new">      privileged: false' in html and "Код из файла" in html
    assert html.count("CVE-2026-7</a>") + html.count(">CVE-2026-7<") == 1       # одна строка
    assert '<div><div>bsdutils</div></div><div class="small">1:2.41.5</div>' in html   # версия напротив пакета


def test_live_log_does_not_repeat_current_step():
    from cast.targets import Target
    job = web.Job(1, "x", None, engine="trivy", text="проверяю", text_is_hint=True,
                  target=Target("fs", "/home/d/demo"))
    ui = web._JobUI(job)
    ui.say("скачиваю базу")
    ui.say("скачиваю базу")
    assert job.text == "скачиваю базу" and job.log == []      # текущий шаг — только сверху
    ui.say("читаю файлы папки /home/d/demo")
    assert job.log == ["trivy: скачиваю базу"] and job.text == "читаю файлы папки"


def test_broken_utf8_in_login_asks_again():
    typed = iter([UnicodeDecodeError("utf-8", b"\xd1", 0, 1, "invalid"), "ад мин", "админ"])

    def read(_):
        value = next(typed)
        if isinstance(value, Exception):
            raise value
        return value
    said = []
    login, password = web_auth.ask(said.append, read=read, read_secret=lambda _: "")
    assert login == "админ" and password                  # русский логин можно
    assert any("оборванный символ" in s for s in said) and any("пробелов" in s for s in said)
