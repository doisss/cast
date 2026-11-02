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


def test_cli_web_reports_busy_port(capsys):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen()
        port = s.getsockname()[1]
        assert main(["web", "--port", str(port), "--no-browser"]) == 2
    assert "Не удалось занять порт" in capsys.readouterr().out
