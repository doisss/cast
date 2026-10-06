"""Policy loading: packaged YAML overlay, profiles, and the offline switch."""
from __future__ import annotations

import os


from sarbar.policy import (BUILTIN_PROFILES, POLICY_FIELDS, engines_for,
                           load_profile)


def test_every_builtin_profile_has_a_yaml_file():
    """I-11: profiles must ship inside the package, not beside the repo."""
    from sarbar.policy import _policies_dir
    d = _policies_dir()
    for name in BUILTIN_PROFILES:
        assert os.path.isfile(os.path.join(d, f"{name}.yaml")), name


def test_every_yaml_key_is_a_known_policy_field():
    import yaml

    from sarbar.policy import _policies_dir
    d = _policies_dir()
    for name in BUILTIN_PROFILES:
        with open(os.path.join(d, f"{name}.yaml")) as fh:
            data = yaml.safe_load(fh) or {}
        assert set(data) <= set(POLICY_FIELDS), (name, set(data) - set(POLICY_FIELDS))


def test_builtin_and_yaml_agree():
    """The embedded table and the shipped YAML must not drift apart."""
    import yaml

    from sarbar.policy import _policies_dir
    d = _policies_dir()
    for name, expected in BUILTIN_PROFILES.items():
        with open(os.path.join(d, f"{name}.yaml")) as fh:
            data = yaml.safe_load(fh) or {}
        for key in POLICY_FIELDS:
            if key in expected:
                assert data.get(key) == expected[key], (name, key)


def test_default_profile():
    p = load_profile("default")
    assert p.name == "default"
    assert p.engines_fs == ["trivy"]
    assert p.fail_on_critical == 1
    assert p.fail_on_secret == 1
    assert p.fail_score == 80.0
    assert p.fail_on_degraded is True


def test_ci_profile_is_stricter():
    ci, strict, default = load_profile("ci"), load_profile("strict"), load_profile("default")
    assert len(ci.engines_fs) > len(default.engines_fs)
    assert ci.fail_score < default.fail_score
    assert strict.fail_score < ci.fail_score
    assert strict.fail_on_high == 1


def test_offline_profile_has_no_engines_and_allows_degraded():
    p = load_profile("offline")
    assert p.engines_image == [] and p.engines_fs == []
    assert p.fail_on_degraded is False, \
        "a run with no external engine is this profile's declared intent"


def test_report_profile_never_fails():
    p = load_profile("report")
    assert p.fail_on_critical == -1 and p.fail_score == -1.0
    assert p.fail_on_secret == -1


def test_no_policy_has_a_run_checks_field():
    """Own checks were removed; the flag must not linger in any profile."""
    assert "run_cast_checks" not in POLICY_FIELDS
    assert not hasattr(load_profile("default"), "run_cast_checks")


def test_dockerfile_scanner_is_trivy_not_dockle():
    """dockle is not installed by default; trivy config covers Dockerfiles."""
    for name in ("default", "ci", "report", "strict"):
        assert load_profile(name).engines_dockerfile[0] == "trivy", name
    assert load_profile("offline").engines_dockerfile == []


def test_falco_is_not_in_the_default_profile():
    """falco needs root and a driver, so it is opt-in via ci/strict."""
    default = load_profile("default")
    assert "falco" not in default.engines_container
    assert "falco" in load_profile("ci").engines_container
    assert "falco" in load_profile("strict").engines_container


def test_offline_flag_keeps_the_scanners_but_is_recorded():
    """Offline means "use the local database", so trivy must still run.

    Clearing the engine lists here produced a passing report with zero
    findings, which is the opposite of what offline is for.
    """
    p = load_profile("ci", offline=True)
    assert p.offline is True
    assert p.engines_fs == ["trivy", "grype"]
    assert p.engines_image == ["trivy", "grype"]


def test_unknown_profile_falls_back_to_default_values():
    p = load_profile("does-not-exist")
    assert p.fail_on_critical == load_profile("default").fail_on_critical
    assert p.name == "does-not-exist"


def test_engines_for_dispatch():
    p = load_profile("ci")
    assert engines_for(p, "fs") == p.engines_fs
    assert engines_for(p, "image") == p.engines_image
    assert engines_for(p, "container") == p.engines_container
    assert engines_for(p, "dockerfile") == p.engines_dockerfile
    assert engines_for(p, "unknown-kind") == p.engines_image


def test_yaml_overlay_is_applied(tmp_path, monkeypatch):
    import sarbar.policy as pol

    profiles = tmp_path / "policies"
    profiles.mkdir()
    (profiles / "default.yaml").write_text("fail_score: 12.5\nfail_on_high: 2\n")
    monkeypatch.setattr(pol, "_policies_dir", lambda: str(profiles))
    p = pol.load_profile("default")
    assert p.fail_score == 12.5
    assert p.fail_on_high == 2
    assert p.engines_fs == ["trivy"], "unspecified keys keep the embedded defaults"


def test_malformed_yaml_is_reported_not_ignored(tmp_path, monkeypatch, capsys):
    import sarbar.policy as pol
    profiles = tmp_path / "policies"
    profiles.mkdir()
    (profiles / "default.yaml").write_text("fail_score: [unclosed\n")
    monkeypatch.setattr(pol, "_policies_dir", lambda: str(profiles))
    p = pol.load_profile("default")
    assert p.fail_score == 80.0, "falls back to the embedded table"
    assert "cannot parse" in capsys.readouterr().err


def test_yaml_list_profile_is_ignored(tmp_path, monkeypatch):
    import sarbar.policy as pol
    profiles = tmp_path / "policies"
    profiles.mkdir()
    (profiles / "default.yaml").write_text("- just\n- a list\n")
    monkeypatch.setattr(pol, "_policies_dir", lambda: str(profiles))
    assert pol.load_profile("default").fail_score == 80.0


def test_missing_yaml_file_is_fine(tmp_path, monkeypatch):
    import sarbar.policy as pol
    monkeypatch.setattr(pol, "_policies_dir", lambda: str(tmp_path))
    assert pol.load_profile("default").fail_score == 80.0


def test_works_without_pyyaml(tmp_path, monkeypatch):
    """The tool must run air-gapped: no PyYAML means embedded values only."""
    import builtins
    import sarbar.policy as pol
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "yaml":
            raise ImportError("blocked for test")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    p = pol.load_profile("ci")
    assert p.engines_fs == ["trivy", "grype"]
    assert p.fail_score == 60.0