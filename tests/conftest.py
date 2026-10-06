"""Shared fixtures.

The autouse fixture below exists because the falco adapter looks for its
configuration and its container plugin under the *user's real home directory*.
Without it the suite passes locally and fails on a clean CI runner, where
~/.sarbar and ~/.local/share do not exist — a test suite that only works on the
author's machine is worse than no suite, because it reports green where it has
checked nothing.

Class attributes are used rather than patching methods, so an individual test
can still override any of them.
"""
from __future__ import annotations


import pytest

from sarbar.engines import FalcoEngine


@pytest.fixture(autouse=True)
def falco_install_in_tmp(tmp_path, monkeypatch):
    """Point falco's config, rules and plugin at a temporary directory.

    A dedicated subdirectory is used rather than tmp_path itself, because
    individual tests build their own trees under tmp_path and would otherwise
    collide with this one.
    """
    root = tmp_path / "_fixture_falco"
    etc = root / "etc" / "falco"
    etc.mkdir(parents=True, exist_ok=True)
    config = etc / "falco.yaml"
    rules = etc / "falco_rules.yaml"
    config.write_text("rules_file: /x\n")
    rules.write_text("- rule: test\n")

    plugins = root / "share" / "falco" / "plugins"
    plugins.mkdir(parents=True, exist_ok=True)
    (plugins / "libcontainer.so").write_bytes(b"\x7fELF")

    monkeypatch.setattr(FalcoEngine, "CONFIG_CANDIDATES", (str(config),))
    monkeypatch.setattr(FalcoEngine, "RULES_CANDIDATES", (str(rules),))
    monkeypatch.setattr(FalcoEngine, "PLUGIN_DIRS", (str(plugins),))
    return {"config": str(config), "rules": str(rules),
            "plugins": str(plugins)}


@pytest.fixture
def no_home(monkeypatch, tmp_path):
    """A home directory with nothing in it, for path-resolution tests."""
    home = tmp_path / "empty-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_STATE_HOME", str(home / ".local" / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(home / ".local" / "share"))
    return str(home)


@pytest.fixture
def isolated_path(monkeypatch, tmp_path):
    """Redirect every home-relative lookup setup.py performs into tmp_path.

    Used as a guard by the tests that assert sarbar never writes into a real
    home directory. Without this, a single mispatched path can overwrite the
    user's installation and the suite will report success.
    """
    real = tmp_path / "home"
    real.mkdir()
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.setenv("XDG_STATE_HOME", str(real / ".local" / "state"))
    monkeypatch.setenv("XDG_DATA_HOME", str(real / ".local" / "share"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(real / ".config"))
    return str(real)


@pytest.fixture
def stub_binary(tmp_path, monkeypatch):
    """Write a runnable fake scanner and make `resolve()` return it.

    Tests must never depend on a scanner being installed on the machine running
    them: that is why this suite failed on a clean CI runner while passing here.
    """
    counter = {"n": 0}

    def make(script: str, name: str = "stub"):
        counter["n"] += 1
        path = tmp_path / f"_stub_{name}_{counter['n']}"
        path.write_text(script)
        path.chmod(0o755)
        return str(path)

    return make