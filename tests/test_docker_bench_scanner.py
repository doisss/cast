import pytest

from cast.models import Severity
from cast.scanners.base import ScannerError
from cast.scanners.docker_bench import DockerBenchScanner, locate_script
from cast.utils import BinaryNotFoundError

# Фрагмент НАСТОЯЩЕГО вывода `docker-bench-security.sh -b` (снят на Kali, v1.6.0).
# Заголовки подразделов ("[INFO] 1.1 - Linux Hosts ...") имеют тот же вид, что и
# проверки, но без пометки (Automated)/(Manual)/(Scored); после проверок идут
# дополнительные строки "[INFO]       * ..." и сообщения оболочки об ошибках.
REAL_OUTPUT = """
[INFO] 1 - Host Configuration
[INFO] 1.1 - Linux Hosts Specific Configuration
[WARN] 1.1.1 - Ensure a separate partition for containers has been created (Automated)
[INFO] 1.1.2 - Ensure only trusted users are allowed to control Docker daemon (Automated)
[INFO]       * Users: 
[INFO] 1.2 - General Configuration
[NOTE] 1.2.1 - Ensure the container host has been Hardened (Manual)
[PASS] 1.2.2 - Ensure that the version of Docker is up to date (Manual)
[INFO]        * Using 28.5.2+4 which is current
[INFO] 2 - Docker daemon configuration
[WARN] 2.2 - Ensure network traffic is restricted between containers on the default bridge (Scored)
docker-bench-security.sh: 37: [[: not found
[PASS] 2.3 - Ensure the logging level is set to 'info' (Scored)
"""


def test_parse_real_output_keeps_real_checks_with_all_statuses():
    findings = DockerBenchScanner()._parse(REAL_OUTPUT)
    assert [f.check_id for f in findings] == ["1.1.1", "1.1.2", "1.2.1", "1.2.2", "2.2", "2.3"]


def test_parse_skips_subsection_headers():
    ids = {f.check_id for f in DockerBenchScanner()._parse(REAL_OUTPUT)}
    assert "1.1" not in ids and "1.2" not in ids      # заголовки подразделов


def test_parse_keeps_statuses_as_is_without_levels():
    findings = {f.check_id: f for f in DockerBenchScanner()._parse(REAL_OUTPUT)}

    assert findings["1.1.1"].status == "WARN"
    assert findings["1.2.1"].status == "NOTE"
    assert findings["1.1.2"].status == "INFO"
    assert findings["1.2.2"].status == "PASS"
    assert findings["1.1.1"].severity == Severity.UNKNOWN   # своих уровней не назначаем
    assert findings["1.1.1"].title == "Ensure a separate partition for containers has been created"
    assert findings["1.1.1"].source_tool == "docker-bench"
    assert findings["1.1.1"].package is None


COLORED = (
    "\x1b[1;31m[WARN]\x1b[0m 4.1 - Ensure that a user for the container has been created (Automated)\n"
    "\x1b[1;31m[WARN]\x1b[0m      * Running as root: web\n"
    "\x1b[1;32m[PASS]\x1b[0m 4.2 - Ensure trusted base images (Manual)\n"
)


def test_parse_attaches_detail_lines_to_the_check():
    findings = {f.check_id: f for f in DockerBenchScanner()._parse(COLORED)}
    assert findings["4.1"].details == ["Running as root: web"]
    assert findings["4.2"].details == []


def test_parse_strips_ansi_colors():
    findings = DockerBenchScanner()._parse(COLORED)
    assert [(f.check_id, f.status) for f in findings] == [("4.1", "WARN"), ("4.2", "PASS")]


def _fake_script(directory, body):
    script = directory / "docker-bench-security.sh"
    script.write_text(body, encoding="utf-8")
    return script


def test_locate_script_via_env(tmp_path, monkeypatch):
    script = _fake_script(tmp_path, "#!/bin/sh\n")
    monkeypatch.setenv("CAST_DOCKER_BENCH_DIR", str(tmp_path))
    assert locate_script() == script


def test_locate_script_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("CAST_DOCKER_BENCH_DIR", str(tmp_path / "nope"))
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr("cast.scanners.docker_bench._default_dirs", lambda: [tmp_path / "x"])
    with pytest.raises(BinaryNotFoundError):
        locate_script()


def test_default_dirs_include_sudo_users_home(monkeypatch, tmp_path):
    # под sudo Path.home() == /root; скрипт лежит в домашней папке обычного пользователя
    pytest.importorskip("pwd")
    from types import SimpleNamespace

    from cast.scanners import docker_bench

    home = tmp_path / "home" / "d"
    monkeypatch.setenv("SUDO_USER", "d")
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path / "root")
    monkeypatch.setattr("pwd.getpwnam", lambda name: SimpleNamespace(pw_dir=str(home)))

    dirs = docker_bench._default_dirs()

    assert home / "docker-bench-security" in dirs
    assert (tmp_path / "root" / "docker-bench-security") in dirs


def test_run_executes_from_script_dir_with_nocolor_flag(tmp_path):
    # Имитация настоящего скрипта: падает, если запущен не из своей папки
    # (как LIBEXEC="." у оригинала) и печатает строки только при флаге -b.
    (tmp_path / "functions").mkdir()
    script = _fake_script(
        tmp_path,
        '#!/bin/sh\n[ -d ./functions ] || { echo "cannot find functions"; exit 2; }\n'
        'case "$1" in -b) echo "[WARN] 4.1 - Ensure a user has been created (Automated)";; esac\n',
    )
    scanner = DockerBenchScanner()
    findings = scanner._parse(scanner._run(script))
    assert [(f.check_id, f.status) for f in findings] == [("4.1", "WARN")]


def test_run_reports_docker_daemon_error(tmp_path):
    script = _fake_script(
        tmp_path,
        '#!/bin/sh\necho "Error connecting to docker daemon (does docker ps work?)"\nexit 1\n',
    )
    with pytest.raises(ScannerError, match="Docker-демону"):
        DockerBenchScanner()._run(script)
