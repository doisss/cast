"""Engine adapters: parsing, severity dialects, CVSS shapes, failure reporting.

Covers the code that had 28% coverage and produced silent zero-result scans.
"""
from __future__ import annotations

import pytest

from sarbar.engines import (STATUS_FAILED, STATUS_OK, STATUS_TIMEOUT,
                            STATUS_UNAVAILABLE, DockleEngine, FalcoEngine,
                            GrypeEngine, TrivyEngine, _cvss_of, _find_binary,
                            _load_json, _run_cmd, resolve)
from sarbar.model import SEVERITIES, normalize_severity
from tests import fixtures as fx


# ---------------------------------------------------------------- resolution

def test_resolve_prefers_path(tmp_path, monkeypatch):
    fake = tmp_path / "trivy"
    fake.write_text("#!/bin/sh\necho 1\n")
    fake.chmod(0o755)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "trivy").write_text("#!/bin/sh\necho 2\n")
    (bindir / "trivy").chmod(0o755)
    monkeypatch.setenv("PATH", str(bindir))
    assert resolve("trivy") == str(bindir / "trivy")


def test_resolve_falls_back_to_sarbar_bin(tmp_path, monkeypatch):
    import sarbar.engines as eng
    home = tmp_path / ".sarbar"
    (home / "bin").mkdir(parents=True)
    tool = home / "bin" / "grype"
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o755)
    monkeypatch.setattr(eng, "SARBAR_BIN", str(home / "bin"))
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    assert resolve("grype") == str(tool)


def test_resolve_returns_none_when_absent(monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent-dir-xyz")
    import sarbar.engines as eng
    monkeypatch.setattr(eng, "SARBAR_BIN", "/nonexistent-sarbar-bin")
    assert resolve("definitely-not-a-real-scanner") is None


def test_find_binary_alias_exists():
    assert _find_binary("sh") is not None


def test_is_available_requires_executable(tmp_path, monkeypatch):
    """I-4: a file that exists but cannot run must not report as available."""
    import sarbar.engines as eng
    d = tmp_path / "bin"
    d.mkdir()
    broken = d / "dockle"
    broken.write_bytes(b"\x7fELF not really an executable")
    broken.chmod(0o755)
    monkeypatch.setattr(eng, "SARBAR_BIN", str(d))
    monkeypatch.setenv("PATH", str(d))
    assert DockleEngine().resolve() is not None
    assert DockleEngine().is_available() is False


# ---------------------------------------------------------------- subprocess

def test_run_cmd_reports_missing_binary():
    code, _ = _run_cmd(["definitely-not-a-real-scanner-xyz", "--version"])
    assert code == 127


def test_run_cmd_reports_timeout(tmp_path):
    slow = tmp_path / "slow"
    slow.write_text("#!/bin/sh\nsleep 5\n")
    slow.chmod(0o755)
    code, _ = _run_cmd([str(slow)], timeout=1)
    assert code == 124


def test_load_json_finds_embedded_document():
    assert _load_json(fx.TRIVY_NOISY)["SchemaVersion"] == 2


def test_load_json_rejects_non_json():
    assert _load_json(fx.TRIVY_FATAL) is None
    assert _load_json("") is None
    assert _load_json("[1,2,3]") is None


# ---------------------------------------------------------------- cvss

@pytest.mark.parametrize("obj,expected", [
    ({"cvss": [{"metrics": "9.8", "type": "NVD"}]}, 9.8),
    ({"cvss": [{"score": 7.2}]}, 7.2),
    ({"cvss": [{"metrics": "0"}]}, 0.0),
    ({"CVSS": {"nvd": {"V3Score": 9.1}}}, 9.1),
    ({"CVSS": {"V3Score": 7.2}}, 7.2),
    ({"CVSS": {"redhat": {"V3Score": 6.1}, "nvd": {"V3Score": 8.0}}}, 8.0),
    ({"cvssScore": 5.5}, 5.5),
    ({}, 0.0),
    ({"cvss": "garbage"}, 0.0),
])
def test_cvss_shapes(obj, expected):
    assert _cvss_of(obj) == expected


def test_grype_cvss_is_not_silently_zero():
    """Regression: grype reports cvss as a list; it used to score 0.0."""
    assert _cvss_of(fx.GRYPE_JSON["matches"][0]["vulnerability"]) == 9.8


# ---------------------------------------------------------------- severity

@pytest.mark.parametrize("raw,expected", [
    ("Emergency", "CRITICAL"), ("ALERT", "CRITICAL"), ("Critical", "CRITICAL"),
    ("Error", "HIGH"), ("Warning", "MEDIUM"), ("WARN", "MEDIUM"),
    ("Notice", "LOW"), ("Informational", "INFO"), ("Negligible", "INFO"),
    ("DEBUG", "INFO"), ("bogus", "UNKNOWN"), ("", "UNKNOWN"), (None, "UNKNOWN"),
])
def test_severity_dialects(raw, expected):
    assert normalize_severity(raw) == expected


def test_every_mapped_priority_is_canonical():
    for p in ("Emergency", "Alert", "Critical", "Error", "Warning", "Notice",
              "Informational"):
        assert normalize_severity(p) in SEVERITIES


# ---------------------------------------------------------------- trivy

def test_trivy_parses_all_three_categories():
    out = TrivyEngine().parse(fx.TRIVY_JSON, "app:latest")
    cats = {f.category for f in out}
    assert cats == {"vuln", "misconfig", "secret"}
    vuln = next(f for f in out if f.category == "vuln")
    assert vuln.check_id == "CVE-2024-1111"
    assert vuln.cvss == 9.1
    assert vuln.fixed_version == "3.1.4-r6"
    assert len(vuln.description) == 500, "description must be truncated"
    secret = next(f for f in out if f.category == "secret")
    assert secret.severity == "HIGH"
    assert secret.locations == ["app/config.py:3"]


def test_trivy_run_fails_loudly_on_fatal_output(tmp_path, monkeypatch):
    """I-1: a scanner that dies must not look like a clean scan."""
    bad = tmp_path / "trivy"
    bad.write_text("#!/bin/sh\necho 'FATAL unable to initialize DB'\nexit 1\n")
    bad.chmod(0o755)
    monkeypatch.setattr(TrivyEngine, "resolve", lambda self: str(bad))
    res = TrivyEngine().run("app:latest", "image")
    assert res.status == STATUS_FAILED
    assert res.findings == []
    assert "unable to initialize DB" in res.detail


def test_trivy_run_succeeds_with_no_findings(tmp_path, monkeypatch):
    ok = tmp_path / "trivy"
    ok.write_text('#!/bin/sh\necho \'{"SchemaVersion":2,"Results":[]}\'\n')
    ok.chmod(0o755)
    monkeypatch.setattr(TrivyEngine, "resolve", lambda self: str(ok))
    res = TrivyEngine().run("app:latest", "image")
    assert res.status == STATUS_OK
    assert res.findings == []


def test_trivy_unsupported_kind_is_explicit():
    assert TrivyEngine().supports  # sanity


# ---------------------------------------------------------------- grype

def test_grype_parses_matches_and_cvss():
    out = GrypeEngine().parse(fx.GRYPE_JSON, "app:latest")
    assert len(out) == 2
    a, b = out
    assert a.check_id == "CVE-2024-1111"
    assert a.severity == "CRITICAL"
    assert a.cvss == 9.8
    assert a.fixed_version == "3.1.4-r6"
    assert b.check_id == "CVE-2024-3333"
    assert b.severity == "LOW"
    assert b.fixed_version == ""


def test_grype_declines_dockerfile_mode():
    res = GrypeEngine().run("./Dockerfile", "dockerfile")
    assert not res.ok


# ---------------------------------------------------------------- dockle

def test_dockle_parses_details():
    out = DockleEngine().parse(fx.DOCKLE_JSON, "app:latest")
    assert [f.check_id for f in out] == ["CIS-DI-0001", "CIS-DI-0002", "CIS-DI-0010"]
    assert [f.severity for f in out] == ["MEDIUM", "HIGH", "INFO"]


def test_dockle_ignores_summary_object():
    """The old dead loop assumed summary was a list; it is a dict."""
    data = {"summary": {"fatal": 0, "warn": 0}, "details": []}
    assert DockleEngine().parse(data, "x") == []


# ---------------------------------------------------------------- falco

def test_falco_maps_every_priority():
    out = FalcoEngine().parse(fx.FALCO_NDJSON, "c1")
    by_rule = {f.check_id: f.severity for f in out}
    assert by_rule["FALCO-Write-below-binary-dir"] == "MEDIUM"
    assert by_rule["FALCO-Contact-K8S-API-server"] == "LOW"
    assert by_rule["FALCO-Outbound-Connection"] == "CRITICAL"
    assert by_rule["FALCO-Terminal-shell-in-container"] == "INFO"
    assert by_rule["FALCO-Core-dumped"] == "CRITICAL"


def test_falco_check_ids_have_no_spaces():
    for f in FalcoEngine().parse(fx.FALCO_NDJSON, "c1"):
        assert " " not in f.check_id
        assert f.check_id.startswith("FALCO-")


def test_falco_skips_malformed_lines():
    out = FalcoEngine().parse(fx.FALCO_NDJSON, "c1")
    assert len(out) == 5, "one of six lines is not JSON"


def test_falco_needs_root_and_declares_it():
    assert FalcoEngine.needs_root is True


def test_falco_timeout_is_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(FalcoEngine, "running_as_root", staticmethod(lambda: True))
    slow = tmp_path / "falco"
    slow.write_text("#!/bin/sh\necho 'Falco version: 0.45.0'\nsleep 30\n")
    slow.chmod(0o755)
    monkeypatch.setattr(FalcoEngine, "resolve", lambda self: str(slow))
    monkeypatch.setattr(FalcoEngine, "WINDOW_SECONDS", 1)
    res = FalcoEngine().run("c1", "container")
    assert res.status == STATUS_TIMEOUT
    assert "not observed" in res.detail


def test_falco_empty_window_says_so(tmp_path, monkeypatch):
    monkeypatch.setattr(FalcoEngine, "running_as_root", staticmethod(lambda: True))
    quiet = tmp_path / "falco"
    quiet.write_text("#!/bin/sh\necho 'Falco version: 0.45.0'\necho 'no events'\n")
    quiet.chmod(0o755)
    monkeypatch.setattr(FalcoEngine, "resolve", lambda self: str(quiet))
    res = FalcoEngine().run("c1", "container")
    assert res.status == STATUS_OK
    assert res.findings == []
    assert "0 events" in res.detail


def test_engine_absent_is_unavailable(tmp_path, monkeypatch):
    import sarbar.engines as eng
    monkeypatch.setattr(eng, "SARBAR_BIN", str(tmp_path))
    monkeypatch.setenv("PATH", str(tmp_path))
    for E in (TrivyEngine, GrypeEngine, DockleEngine, FalcoEngine):
        res = E().run("x", "image")
        assert res.status == STATUS_UNAVAILABLE
        assert res.findings == []


def test_engine_result_ok_predicate():
    from sarbar.engines import EngineResult
    assert EngineResult(status=STATUS_OK).ok
    assert not EngineResult(status=STATUS_FAILED).ok
    assert not EngineResult(status=STATUS_UNAVAILABLE).ok


def test_falco_command_has_no_removed_flag():
    """Regression: -A was removed in Falco 0.42 and made it exit immediately."""
    e = FalcoEngine()
    argv = e.build_command(seconds=7) or []
    assert "-A" not in argv
    assert "-M" in argv and argv[argv.index("-M") + 1] == "7"
    assert "-U" in argv, "unbuffered output is required to read events in time"
    assert "-c" in argv and "-r" in argv


def test_falco_config_and_rules_are_located(tmp_path, monkeypatch):
    monkeypatch.setattr(FalcoEngine, "resolve", lambda self: "/usr/bin/falco")
    conf = tmp_path / "etc" / "falco"
    conf.mkdir(parents=True)
    (conf / "falco.yaml").write_text("rules_file: /x\n")
    (conf / "falco_rules.yaml").write_text("- rule: a\n")
    monkeypatch.setattr(FalcoEngine, "CONFIG_CANDIDATES",
                        (str(tmp_path / "etc" / "falco" / "falco.yaml"),))
    monkeypatch.setattr(FalcoEngine, "RULES_CANDIDATES",
                        (str(tmp_path / "etc" / "falco" / "falco_rules.yaml"),))
    assert e_path(FalcoEngine().config_path())
    assert e_path(FalcoEngine().rules_path())
    argv = FalcoEngine().build_command()
    assert argv[argv.index("-c") + 1].endswith("falco.yaml")
    assert argv[argv.index("-r") + 1].endswith("falco_rules.yaml")


def e_path(p):
    return p is not None and p.endswith(".yaml")


def test_falco_reports_missing_config_instead_of_guessing(tmp_path, monkeypatch):
    monkeypatch.setattr(FalcoEngine, "resolve", lambda self: "/usr/bin/falco")
    monkeypatch.setattr(FalcoEngine, "CONFIG_CANDIDATES",
                        (str(tmp_path / "nope.yaml"),))
    monkeypatch.setattr(FalcoEngine, "RULES_CANDIDATES",
                        (str(tmp_path / "nope_rules.yaml"),))
    res = FalcoEngine().run("c1", "container")
    assert res.status == STATUS_UNAVAILABLE
    assert "no falco.yaml" in res.detail


def test_falco_recognises_a_missing_driver(monkeypatch):
    """Falco exits when it has no event source; that is not '0 events'."""
    monkeypatch.setattr(FalcoEngine, "running_as_root", staticmethod(lambda: True))
    out = ("Falco initialized with configuration files: falco.yaml | ok\n"
           "Loading rules from: falco_rules.yaml | ok\n"
           "Error: Plugin requirement not satisfied, must load one of: container")
    monkeypatch.setattr(FalcoEngine, "resolve", lambda self: "/usr/bin/falco")
    monkeypatch.setattr(FalcoEngine, "config_path", lambda self: "/etc/falco/falco.yaml")
    monkeypatch.setattr(FalcoEngine, "rules_path", lambda self: "/etc/falco/falco_rules.yaml")
    monkeypatch.setattr("sarbar.engines._run_cmd", lambda cmd, timeout=0: (1, out))
    res = FalcoEngine().run("c1", "container")
    assert res.status == STATUS_UNAVAILABLE
    assert "setup --driver" in res.detail


def test_trivy_offline_hint_mentions_the_command(monkeypatch):
    monkeypatch.setattr(TrivyEngine, "resolve", lambda self: "/usr/bin/trivy")
    monkeypatch.setattr("sarbar.engines._run_cmd",
                        lambda cmd, timeout=0: (1, "FATAL unable to initialize DB"))
    res = TrivyEngine().run("x", "image")
    assert res.status == STATUS_FAILED
    assert "sarbar offline" in res.detail


def test_trivy_db_presence_check(tmp_path, monkeypatch):
    monkeypatch.setattr(TrivyEngine, "DB_DIR", str(tmp_path / "db"))
    monkeypatch.setattr(TrivyEngine, "DB_META", str(tmp_path / "db" / "metadata.json"))
    assert TrivyEngine.db_present() is False
    (tmp_path / "db").mkdir()
    (tmp_path / "db" / "metadata.json").write_text("{}")
    assert TrivyEngine.db_present() is True

# ---------------------------------------------------------------- falco + sudo

def test_falco_asks_for_root_and_says_how_to_get_it(tmp_path, monkeypatch):
    """No root, no sudo: say so instead of pretending the container was clean."""
    monkeypatch.setattr(FalcoEngine, "running_as_root", staticmethod(lambda: False))
    monkeypatch.setattr(FalcoEngine, "authorise_sudo",
                        staticmethod(lambda: (False, "the password was not accepted")))
    res = FalcoEngine().run("c1", "container")
    assert res.status == STATUS_UNAVAILABLE
    assert res.findings == []
    assert "needs root" in res.detail
    assert "setup --driver" in res.detail
    assert "--no-sudo" in res.detail


def test_falco_no_sudo_flag_skips_the_prompt(tmp_path, monkeypatch):
    monkeypatch.setattr(FalcoEngine, "running_as_root", staticmethod(lambda: False))

    def explode():
        raise AssertionError("--no-sudo must not trigger a password prompt")

    monkeypatch.setattr(FalcoEngine, "authorise_sudo", staticmethod(explode))
    res = FalcoEngine().run("c1", "container", allow_sudo=False)
    assert res.status == STATUS_UNAVAILABLE
    assert "--no-sudo was given" in res.detail


def test_falco_uses_sudo_n_after_authorisation(tmp_path, monkeypatch):
    """The password prompt goes to the terminal, the run uses sudo -n so the
    JSON output can still be captured."""
    monkeypatch.setattr(FalcoEngine, "running_as_root", staticmethod(lambda: False))
    monkeypatch.setattr(FalcoEngine, "authorise_sudo",
                        staticmethod(lambda: (True, "ok")))
    fake = tmp_path / "falco"
    fake.write_text("#!/bin/sh\necho 'Falco version: 0.45.0'\n")
    fake.chmod(0o755)
    monkeypatch.setattr(FalcoEngine, "resolve", lambda self: str(fake))
    seen = {}

    def fake_run(cmd, timeout=0):
        seen["cmd"] = cmd
        return 0, "Falco version: 0.45.0\nno events"

    monkeypatch.setattr("sarbar.engines._run_cmd", fake_run)
    FalcoEngine().run("c1", "container")
    assert seen["cmd"][:2] == ["sudo", "-n"], seen["cmd"]


def test_sudo_authorisation_failure_is_reported(monkeypatch):
    monkeypatch.setattr(FalcoEngine, "running_as_root", staticmethod(lambda: False))
    monkeypatch.setattr("sarbar.engines.shutil.which",
                        lambda name: "/usr/bin/sudo" if name == "sudo" else None)
    monkeypatch.setattr("sarbar.engines.subprocess",
                        type("S", (), {"SubprocessError": OSError,
                                       "run": staticmethod(
                                           lambda *a, **k: type(
                                               "R", (), {"returncode": 1})())}))
    ok, why = FalcoEngine.authorise_sudo()
    assert not ok and "password" in why


def test_sudo_authorisation_succeeds_when_already_root(monkeypatch):
    monkeypatch.setattr(FalcoEngine, "running_as_root", staticmethod(lambda: True))
    assert FalcoEngine.authorise_sudo() == (True, "already root")


# ------------------------------------------- falco must actually have run

def test_sudo_refusal_is_never_reported_as_zero_events(monkeypatch):
    """The failure this tool exists to prevent.

    `sudo -n` refuses, prints its own message, and falco never starts. If that
    were read as "0 events, status ok", the container would be called clean.
    """
    monkeypatch.setattr(FalcoEngine, "running_as_root", staticmethod(lambda: False))
    monkeypatch.setattr(FalcoEngine, "authorise_sudo",
                        staticmethod(lambda: (True, "looks authorised")))
    monkeypatch.setattr(FalcoEngine, "resolve", lambda self: "/usr/bin/falco")
    monkeypatch.setattr(
        "sarbar.engines._run_cmd",
        lambda cmd, timeout=0: (1, "sudo: a password is required\n"))
    res = FalcoEngine().run("abc123", "container")
    assert res.status == STATUS_UNAVAILABLE
    assert res.findings == []
    assert "did not run" in res.detail
    assert "sudo -v" in res.detail


def test_output_without_the_falco_banner_means_nothing_was_observed(monkeypatch):
    monkeypatch.setattr(FalcoEngine, "running_as_root", staticmethod(lambda: True))
    monkeypatch.setattr(FalcoEngine, "resolve", lambda self: "/usr/bin/falco")
    monkeypatch.setattr("sarbar.engines._run_cmd",
                        lambda cmd, timeout=0: (0, "Events detected: 0\n"))
    res = FalcoEngine().run("abc123", "container")
    assert res.status == STATUS_UNAVAILABLE
    assert res.findings == []


def test_a_real_falco_run_with_no_events_is_ok(tmp_path, monkeypatch):
    """The counterpart: falco really started, saw nothing, that IS a valid 0."""
    monkeypatch.setattr(FalcoEngine, "running_as_root", staticmethod(lambda: True))
    quiet = tmp_path / "falco"
    quiet.write_text("#!/bin/sh\necho 'Falco version: 0.45.0'\necho 'no events'\n")
    quiet.chmod(0o755)
    monkeypatch.setattr(FalcoEngine, "resolve", lambda self: str(quiet))
    res = FalcoEngine().run("c1", "container")
    assert res.status == STATUS_OK
    assert res.findings == []


# ------------------------------------------------- the container plugin recipe

def test_falco_enables_the_container_plugin_it_installed(tmp_path, monkeypatch):
    """falco 0.45 ships load_plugins: [] and a bare library_path. Without these
    two overrides falco exits with 'Plugin requirement not satisfied'."""
    monkeypatch.setattr(FalcoEngine, "resolve", lambda self: "/usr/bin/falco")
    monkeypatch.setattr(FalcoEngine, "container_plugin",
                        classmethod(lambda cls: "/opt/falco/libcontainer.so"))
    cmd = FalcoEngine().build_command()
    assert "plugins[0].library_path=/opt/falco/libcontainer.so" in cmd
    assert "load_plugins=container" in cmd


def test_plugin_index_is_read_from_the_config_not_assumed(tmp_path):
    """A config listing another plugin first must not point at the wrong index."""
    conf = tmp_path / "falco.yaml"
    conf.write_text("load_plugins: []\nplugins:\n"
                    "  - name: k8saudit\n    library_path: libk8saudit.so\n"
                    "  - name: container\n    library_path: libcontainer.so\n")
    assert FalcoEngine.plugin_index(str(conf)) == 1


def test_plugin_index_falls_back_to_zero_when_the_name_is_absent(tmp_path):
    conf = tmp_path / "falco.yaml"
    conf.write_text("plugins:\n  - name: k8saudit\n")
    assert FalcoEngine.plugin_index(str(conf)) == 0


def test_plugin_index_is_zero_when_there_is_no_config():
    assert FalcoEngine.plugin_index(None) == 0
    assert FalcoEngine.plugin_index("/nope/missing.yaml") == 0


def test_container_plugin_is_found_where_we_installed_it(tmp_path, monkeypatch):
    """A per-user install cannot write /usr/share/falco/plugins.

    The search list is redirected into a temp directory on purpose: reading the
    real ~/.local/share here would let the test create or delete a file in the
    user's actual installation, which has already happened twice in this project.
    """
    plugins = tmp_path / "share" / "falco" / "plugins"
    plugins.mkdir(parents=True)
    target = str(plugins / "libcontainer.so")
    open(target, "wb").close()
    monkeypatch.setattr(FalcoEngine, "PLUGIN_DIRS", (str(plugins),))
    assert FalcoEngine.container_plugin() == target


def test_container_plugin_search_list_covers_both_layouts():
    """Both the system location and the per-user one must be searched."""
    dirs = FalcoEngine.PLUGIN_DIRS
    assert "/usr/share/falco/plugins" in dirs
    assert any(d.endswith("/share/falco/plugins") and "usr/bin" not in d
               for d in dirs), dirs


# --------------------------------------- offline flags differ per subcommand

def test_offline_flags_are_not_shared_between_subcommands():
    """`trivy config` has no --skip-db-update and no --offline-scan.

    Measured against trivy 0.75: passing them makes it exit 1 with
    "unknown flag: --skip-db-update", which sarbar correctly reported as a
    failure — but the feature was broken for Dockerfiles until this was fixed.
    """
    assert "--skip-db-update" not in TrivyEngine.OFFLINE_FLAGS["dockerfile"]
    assert "--offline-scan" not in TrivyEngine.OFFLINE_FLAGS["dockerfile"]
    assert "--skip-check-update" in TrivyEngine.OFFLINE_FLAGS["dockerfile"]
    for kind in ("image", "fs", "container"):
        assert "--skip-db-update" in TrivyEngine.OFFLINE_FLAGS[kind]
        assert "--offline-scan" in TrivyEngine.OFFLINE_FLAGS[kind]


@pytest.mark.parametrize("kind,expected", [
    ("image", "image"), ("fs", "fs"), ("dockerfile", "config"),
])
def test_offline_run_passes_only_the_flags_its_subcommand_knows(kind, expected):
    seen = {}
    monkey_cmd = kind
    import sarbar.engines as eng
    orig = TrivyEngine.resolve

    def fake_run(cmd, timeout=0):
        seen["cmd"] = cmd
        return 0, '{"Results": []}'

    TrivyEngine.resolve = lambda self: "/usr/bin/trivy"
    eng._run_cmd = fake_run
    try:
        TrivyEngine().run("t", monkey_cmd, offline=True)
    finally:
        TrivyEngine.resolve = orig
    cmd = seen["cmd"]
    assert expected in cmd
    for flag in ("--skip-db-update", "--offline-scan", "--skip-check-update"):
        if flag in TrivyEngine.OFFLINE_FLAGS[kind]:
            assert flag in cmd
        else:
            assert flag not in cmd, f"{flag} must not reach `trivy {expected}`"
