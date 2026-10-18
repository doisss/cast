import json
import subprocess
from contextlib import contextmanager

import pytest

from cast.scanners import ProgressUI, ScannerError
from cast.scanners import trivy as t
from cast.scanners.trivy import TrivyScanner
from cast.targets import Target


def _db(tmp_path, next_update):
    (tmp_path / "db").mkdir(exist_ok=True)
    (tmp_path / "db" / "trivy.db").write_text("x")
    (tmp_path / "db" / "metadata.json").write_text(json.dumps({"NextUpdate": next_update}))


def test_db_needed_when_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("CAST_CACHE_DIR", str(tmp_path))
    assert t._db_needs_update() is True


def test_db_not_needed_until_next_update(tmp_path, monkeypatch):
    monkeypatch.setenv("CAST_CACHE_DIR", str(tmp_path))
    _db(tmp_path, "2999-01-01T00:00:00.5Z")
    assert t._db_needs_update() is False
    _db(tmp_path, "2000-01-01T00:00:00Z")
    assert t._db_needs_update() is True


def test_db_download_is_a_separate_live_step(tmp_path, monkeypatch):
    monkeypatch.setenv("CAST_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(t, "find_binary", lambda *a, **k: "/usr/bin/trivy")
    events, cmds = [], []

    class UI(ProgressUI):
        def say(self, text):
            events.append(("say", text))

        def progress(self, fraction, label=""):
            events.append(("bar", fraction))

    def fake_download(cmd, on_progress, timeout=1800):
        cmds.append(cmd)
        on_progress(0.5, "64 MiB / 128 MiB")
        on_progress(1.0, "128 MiB / 128 MiB")
        _db(tmp_path, "2999-01-01T00:00:00Z")
        return 0, ""

    def fake_exec(cmd, on_line=None):
        cmds.append(cmd)
        return 0, '{"Results": []}', ""

    monkeypatch.setattr(t, "_download", fake_download)
    monkeypatch.setattr(t, "_exec", fake_exec)
    scanner = TrivyScanner()
    scanner.ui = UI()
    scanner.scan_target(Target("image", "alpine"))
    assert "--download-db-only" in cmds[0] and "--skip-db-update" in cmds[1]
    assert events[0][0] == "say" and "скачиваю базу" in events[0][1]
    assert ("bar", 0.5) in events and ("bar", 1.0) in events   # полоса идёт в наш индикатор
    assert "открываю образ alpine" in events[-1][1]
    # второй запуск: база свежая, скачивания нет
    cmds.clear()
    scanner.scan_target(Target("image", "alpine"))
    assert all("--download-db-only" not in c for c in cmds)


def test_failed_db_download_without_db_is_an_honest_error(tmp_path, monkeypatch):
    monkeypatch.setenv("CAST_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(t, "find_binary", lambda *a, **k: "/usr/bin/trivy")
    monkeypatch.setattr(t, "_download", lambda cmd, on_progress, timeout=1800: (1, "no network"))
    with pytest.raises(ScannerError, match="не удалось скачать базу"):
        TrivyScanner().scan_target(Target("image", "alpine"))


def test_cache_dir_is_passed_to_trivy(tmp_path, monkeypatch):
    monkeypatch.setenv("CAST_CACHE_DIR", str(tmp_path))
    assert t._with_cache(["trivy", "image", "x"]) == ["trivy", "--cache-dir", str(tmp_path), "image", "x"]


def test_no_shared_cache_leaves_command_alone(monkeypatch):
    monkeypatch.delenv("CAST_CACHE_DIR", raising=False)
    monkeypatch.setattr(t, "SHARED_CACHE", t.Path("/nonexistent/x"))
    assert t._with_cache(["trivy", "image", "x"]) == ["trivy", "image", "x"]


def test_missing_image_is_announced_as_download(tmp_path, monkeypatch):
    monkeypatch.setattr(t, "find_binary", lambda *a, **k: "/usr/bin/trivy")
    monkeypatch.setattr(t, "_db_needs_update", lambda: False)
    monkeypatch.setattr(t, "_exec", lambda cmd, on_line=None: (0, '{"Results": []}', ""))
    said = []

    class UI(ProgressUI):
        def say(self, text):
            said.append(text)

    scanner = TrivyScanner()
    scanner.ui = UI()
    target = Target("image", "mysql")
    target.image_missing = True
    scanner.scan_target(target)
    assert "скачиваю образ mysql из реестра" == said[-1]


def test_trivy_log_is_narrated_truthfully():
    line = '2026-10-17T10:00:00Z\tINFO\t[alpine] Detecting vulnerabilities...\tos_version="3.19"\trepository="3.19"\tpkg_num=14'
    assert t._narration(line) == "проверяю 14 пакетов ОС (alpine 3.19) по базе уязвимостей"
    assert t._narration("2026-10-17T10:00:00Z\tINFO\tNumber of language-specific files\tnum=0") is None
    assert "12" in t._narration("x\tINFO\tNumber of language-specific files\tnum=12")
    assert t._narration("x\tINFO\tVulnerability scanning is enabled") is None


def test_status_heading_has_total_and_score():
    from io import StringIO
    from rich.console import Console
    from cast.report.console import _status_line
    from cast.report.sections import Section
    from cast.models import Finding, Severity

    def f(status):
        return Finding(source_tool="docker-bench", check_id="1.1", title="t", severity=Severity.UNKNOWN, status=status)

    sec = Section(tool="docker-bench", title="Настройки Docker-хоста", kind="status", findings=[],
                  seconds=1.0, summary={"checks": 3, "score": 9})
    text = _status_line([f("PASS"), f("PASS"), f("WARN")], sec).plain
    assert "Всего: 3" in text and "PASS: 2" in text and "Score: 9" in text  # Score берём у скрипта, не считаем сами


def test_download_reads_trivy_bar_through_a_pty():
    import sys
    code = (
        "import sys\n"
        "sys.stderr.write('2026-10-18T10:14:47Z\\tINFO\\t[vulndb] Downloading\\n')\n"
        "sys.stderr.write('32.00 MiB / 128.00 MiB [---] 25.00% 1.07 MiB p/s 1m\\r')\n"
        "sys.stderr.write('128.00 MiB / 128.00 MiB [---] 100.00% 1.07 MiB p/s 0s\\n')\n"
    )
    seen = []
    rc, _ = t._download([sys.executable, "-c", code], lambda f, label="": seen.append((round(f, 2), label)))
    assert rc == 0
    assert seen[0][0] == 0.25 and seen[-1][0] == 1.0
    assert "128.00 MiB" in seen[-1][1]


def test_unknown_severity_is_counted_in_heading():
    from cast.report.console import _severity_line
    from cast.report.sections import Section
    from cast.models import Finding, Severity
    f = [Finding(source_tool="trivy", check_id="CVE-1", title="t", severity=Severity.UNKNOWN),
         Finding(source_tool="trivy", check_id="CVE-2", title="t", severity=Severity.HIGH)]
    text = _severity_line(f, Section(tool="trivy", title="Уязвимости образа x", kind="severity", findings=f)).plain
    assert ": 2" in text and "HIGH: 1" in text and "UNKNOWN: 1" in text
