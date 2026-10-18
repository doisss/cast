import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "install.sh"


def run(*args, env=None):
    return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, env=env)


def test_syntax_is_valid():
    assert subprocess.run(["bash", "-n", str(SCRIPT)]).returncode == 0
    assert subprocess.run(["bash", "-n", str(ROOT / "uninstall.sh")]).returncode == 0


def test_help():
    r = run("--help")
    assert r.returncode == 0
    assert "--dry-run" in r.stdout


def test_dry_run_local_changes_nothing():
    r = run("--local", "--dry-run")
    assert r.returncode == 0, r.stderr
    assert "dry-run" in r.stdout


def test_refuses_placeholder_repo():
    r = run()
    assert r.returncode != 0
    assert "OWNER" in (r.stdout + r.stderr)


def test_unknown_option():
    r = run("--bogus")
    assert r.returncode != 0
    assert "--bogus" in (r.stdout + r.stderr)


def test_no_mytool_left():
    for p in list(ROOT.glob("*.sh")) + list(ROOT.glob("src/**/*.py")) + [ROOT / "pyproject.toml"]:
        assert "mytool" not in p.read_text(), p
