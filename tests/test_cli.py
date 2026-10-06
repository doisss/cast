"""CLI surface: commands, short flags, --fail-on, exit codes, report output."""
from __future__ import annotations

import json

import pytest

from sarbar.cli import (EXIT_OK, EXIT_POLICY_FAIL, EXIT_USAGE, UsageError,
                        _apply_fail_on, build_parser, main)
from sarbar.policy import load_profile


VULN_DOCKERFILE = (
    "FROM ubuntu:latest\n"
    "ADD app.tar.gz /app\n"
    "ENV API_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456\n"
    "RUN apt-get update && apt-get install -y curl\n"
    "CMD [\"python3\", \"app.py\"]\n"
)
CLEAN_DOCKERFILE = "FROM alpine:3.19\nUSER app\nHEALTHCHECK CMD true\n"


@pytest.fixture
def clean(tmp_path, monkeypatch):
    """A directory with a Dockerfile, an isolated HOME and no network."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    df = tmp_path / "Dockerfile"
    df.write_text(CLEAN_DOCKERFILE)
    return df


# ---------------------------------------------------------------- parser

def test_short_flags_exist():
    """-v version, -e engine, -p profile, -f format, -X explain."""
    p = build_parser()
    args = p.parse_args(["scan", "x", "-e", "falco", "-p", "ci",
                         "-f", "json", "-ex"])
    assert args.engine == "falco" and args.profile == "ci"
    assert args.fmt == "json" and args.explain is True


def test_short_version_flag(capsys):
    with pytest.raises(SystemExit) as e:
        main(["-v"])
    assert e.value.code == 0
    assert "sarbar" in capsys.readouterr().out


def test_long_version_flag(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0


def test_engine_choices_include_falco_and_none():
    p = build_parser()
    assert p.parse_args(["scan", "x", "-e", "falco"]).engine == "falco"
    assert p.parse_args(["scan", "x", "-e", "none"]).engine == "none"
    assert p.parse_args(["scan", "x", "-e", "trivy"]).engine == "trivy"


def test_our_checks_flag_is_gone():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["scan", "x", "--our-checks"])


def test_scan_is_not_advertised_as_an_alias(capsys):
    """`scan` is a subcommand, not a name for the program."""
    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out
    alias_line = next(l for l in out.splitlines() if "alias" in l.lower())
    assert "scan" not in alias_line
    assert "cast" in alias_line


def test_offline_is_available_as_flag_and_command():
    p = build_parser()
    assert p.parse_args(["scan", "x", "--offline"]).offline
    assert p.parse_args(["offline", "x"]).offline


def test_history_takes_a_limit():
    assert build_parser().parse_args(["history", "--limit", "3"]).limit == 3


def test_all_documented_flags_parse():
    args = build_parser().parse_args([
        "scan", "./app", "--profile", "strict", "--engine", "trivy",
        "--format", "sarif", "-o", "out.sarif", "--offline",
        "-ex", "--no-history", "--fail-on", "critical=1,high=5,score=60",
    ])
    assert args.profile == "strict" and args.fmt == "sarif"
    assert args.offline and args.explain and args.no_history


def test_bare_invocation_prints_help(capsys):
    assert main([]) == EXIT_USAGE
    assert "usage: sarbar" in capsys.readouterr().out


# ---------------------------------------------------------------- help text

def test_help_describes_cast_and_says_sarbar_is_an_alias(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out
    assert "Container Automated Security Testing" in out
    assert "alias" in out.lower()
    assert "Old Norse" not in out, "the etymology paragraph must stay gone"
    assert "Barely Armored" not in out


def test_help_lists_every_command(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out
    for cmd in ("scan", "offline", "pipeline", "history", "engines", "setup"):
        assert cmd in out, cmd


# ---------------------------------------------------------------- --fail-on

def test_fail_on_parses_every_key():
    pol = _apply_fail_on(load_profile("default"),
                         "critical=2,high=7,secret=0,score=55.5,degraded=off")
    assert pol.fail_on_critical == 2 and pol.fail_on_high == 7
    assert pol.fail_on_secret == 0 and pol.fail_score == 55.5
    assert pol.fail_on_degraded is False


def test_fail_on_absent_is_a_noop():
    pol = load_profile("default")
    assert _apply_fail_on(pol, None) is pol


@pytest.mark.parametrize("spec", [
    "high=abc", "critical=1.5.2", "score=high", "degraded=maybe",
    "nonsense", "critical", "unknownkey=1",
])
def test_fail_on_rejects_garbage(spec):
    with pytest.raises(UsageError):
        _apply_fail_on(load_profile("default"), spec)


def test_fail_on_error_is_clean(clean, capsys):
    rc = main(["scan", str(clean), "--fail-on", "high=abc", "--no-history"])
    assert rc == EXIT_USAGE
    assert "error:" in capsys.readouterr().err


# ---------------------------------------------------------------- exit codes

def test_missing_path_is_a_usage_error(tmp_path, capsys):
    rc = main(["scan", str(tmp_path / "nope"), "--no-history"])
    assert rc == EXIT_USAGE
    assert "does not exist" in capsys.readouterr().err


def test_missing_dockerfile_is_a_usage_error(tmp_path, capsys):
    rc = main(["scan", str(tmp_path / "Dockerfile"), "--no-history"])
    assert rc == EXIT_USAGE
    assert "does not exist" in capsys.readouterr().err


def test_clean_target_passes(clean, capsys):
    rc = main(["scan", str(clean), "-e", "none", "--profile", "report",
               "--no-history"])
    assert rc == EXIT_OK


def test_strict_profile_exits_one(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    df = tmp_path / "Dockerfile"
    df.write_text(VULN_DOCKERFILE)
    rc = main(["scan", str(df), "-e", "trivy", "-p", "strict", "--no-history"])
    assert rc == EXIT_POLICY_FAIL


def test_pipeline_has_the_same_flags(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    df = tmp_path / "Dockerfile"
    df.write_text(VULN_DOCKERFILE)
    rc = main(["pipeline", str(df), "-e", "trivy", "-p", "strict",
               "--no-history"])
    assert rc == EXIT_POLICY_FAIL


def test_offline_command_behaves_like_the_flag(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    app = tmp_path / "app"
    app.mkdir()
    (app / "x.py").write_text("x = 1\n")
    rc = main(["offline", str(app), "-e", "none", "-p", "report", "--no-history"])
    assert rc in (EXIT_OK, EXIT_POLICY_FAIL)


# ---------------------------------------------------------------- reports

def test_report_written_to_file_for_every_format(clean, capsys):
    for fmt, suffix, probe in (("json", "json", b'"tool"'),
                               ("sarif", "sarif", b'"version": "2.1.0"'),
                               ("html", "html", b"<!doctype html>")):
        dest = clean.parent / f"r.{suffix}"
        main(["scan", str(clean), "-e", "none", "-f", fmt, "-o", str(dest),
              "--no-history"])
        assert dest.exists(), fmt
        assert probe in dest.read_bytes(), fmt


def test_console_format_honours_output(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    df = tmp_path / "Dockerfile"
    df.write_text(VULN_DOCKERFILE)
    dest = tmp_path / "console.txt"
    main(["scan", str(df), "-e", "trivy", "-f", "console",
          "-o", str(dest), "--no-history"])
    assert dest.exists() and dest.stat().st_size > 0
    text = dest.read_text()
    assert "scanners: trivy" in text
    assert "DS-" in text, "findings must come from the scanner"


def test_unwritable_output_is_a_usage_error(clean, capsys):
    rc = main(["scan", str(clean), "-e", "none", "-f", "json",
               "-o", str(clean.parent / "no" / "dir" / "x.json"), "--no-history"])
    assert rc == EXIT_USAGE
    assert "cannot write report" in capsys.readouterr().err


def test_json_report_uses_scanner_terms(clean, capsys):
    main(["scan", str(clean), "-e", "none", "-f", "json", "--no-history"])
    d = json.loads(capsys.readouterr().out)
    assert "scanners_used" in d and "engines_used" not in d


# ---------------------------------------------------------------- meta commands

def test_engines_command(clean, capsys):
    assert main(["engines"]) == EXIT_OK
    out = capsys.readouterr().out
    for name in ("trivy", "grype", "dockle", "falco"):
        assert name in out
    assert "docker daemon" in out


def test_history_on_empty_db(clean, capsys):
    assert main(["history", "--limit", "5"]) == EXIT_OK
    assert "no runs recorded yet" in capsys.readouterr().out


def test_history_roundtrip(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    df = tmp_path / "Dockerfile"
    df.write_text(CLEAN_DOCKERFILE)
    main(["scan", str(df), "-e", "none", "-p", "report"])
    assert "recorded run #1" in capsys.readouterr().out
    assert main(["history", "--limit", "5"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "#1" in out and str(df) in out


def test_history_limit_is_respected(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    df = tmp_path / "Dockerfile"
    df.write_text(CLEAN_DOCKERFILE)
    for _ in range(3):
        main(["scan", str(df), "-e", "none", "-p", "report", "--no-history"])
        main(["scan", str(df), "-e", "none", "-p", "report"])
    main(["history", "--limit", "2"])
    out = capsys.readouterr().out
    assert len([l for l in out.splitlines() if l.startswith("#")]) == 2


def test_no_history_flag(clean, capsys):
    main(["scan", str(clean), "-e", "none", "-p", "report", "--no-history"])
    assert "recorded run" not in capsys.readouterr().out


def test_setup_is_dispatched_with_its_own_arguments(monkeypatch, capsys):
    """`sarbar setup --only falco` must reach sarbar.setup, not argparse."""
    seen = {}
    import sarbar.setup as real

    def fake(argv):
        seen["argv"] = argv
        return 0

    monkeypatch.setattr(real, "run_setup", fake)
    assert main(["setup", "--only", "falco"]) == 0
    assert seen["argv"] == ["--only", "falco"]