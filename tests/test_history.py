"""History store: schema, migration, and round-trip."""
from __future__ import annotations

import sqlite3


from sarbar.history import (SCHEMA_VERSION, db_path, list_runs, migrate_legacy,
                            run_findings, save)


def _result(target="app:latest", kind="image", scanners=("trivy",),
            degraded=False, findings=()):
    return {
        "target": target, "target_kind": kind, "profile": "default",
        "scanners_used": list(scanners),
        "risk": {"score": 42.0, "level": "medium", "counts": {"HIGH": 1},
                 "max_cvss": 7.5, "reasons": ["HIGH:1x -> +10.0"]},
        "verdict": "fail", "offline": degraded, "degraded": degraded,
        "findings": list(findings),
    }


def _finding(check_id="CVE-1", engine="trivy", engines_seen=("trivy",)):
    from sarbar.model import Finding
    f = Finding(check_id, "title", "HIGH", target="t", package="p",
                installed_version="1", engine=engine, category="vuln")
    f.engines_seen = list(engines_seen)
    return f


def test_db_path_follows_xdg_state_home(tmp_path, monkeypatch):
    """XDG_STATE_HOME is the spec's home for action history; /var/lib is not."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    assert db_path() == str(tmp_path / "state" / "sarbar" / "history.db")


def test_db_path_defaults_to_local_state(tmp_path, monkeypatch):
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    assert db_path() == str(tmp_path / ".local" / "state" / "sarbar" / "history.db")


def test_relative_xdg_state_home_is_ignored(tmp_path, monkeypatch):
    """The spec: a relative value in an XDG variable is invalid, ignore it."""
    monkeypatch.setenv("XDG_STATE_HOME", "not/absolute")
    monkeypatch.setenv("HOME", str(tmp_path))
    assert db_path() == str(tmp_path / ".local" / "state" / "sarbar" / "history.db")


def test_legacy_database_is_migrated_not_lost(tmp_path, monkeypatch):
    """Upgrading must not throw away the record of past runs."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("HOME", str(tmp_path))
    old_dir = tmp_path / ".sarbar"
    old_dir.mkdir(parents=True)
    old_db = old_dir / "history.db"
    rid = save(_result(findings=[_finding()]), path=str(old_db))
    assert old_db.is_file()

    assert migrate_legacy() == db_path()
    assert not old_db.exists()
    runs = list_runs(10)
    assert len(runs) == 1
    assert runs[0]["id"] == rid


def test_migration_is_a_noop_when_there_is_nothing_to_move(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "state" / "sarbar").mkdir(parents=True)
    (tmp_path / "state" / "sarbar" / "history.db").write_text("")
    assert migrate_legacy() is None


def test_roundtrip(tmp_path):
    db = str(tmp_path / "h.db")
    rid = save(_result(findings=[_finding()]), path=db)
    runs = list_runs(10, path=db)
    assert len(runs) == 1
    assert runs[0]["id"] == rid
    assert runs[0]["target"] == "app:latest"
    assert runs[0]["engines"] == "trivy"
    assert runs[0]["degraded"] == 0


def test_findings_are_stored_with_all_engines(tmp_path):
    """Regression: history recorded only the first engine, losing engines_seen."""
    db = str(tmp_path / "h.db")
    save(_result(findings=[_finding(engine="trivy",
                                    engines_seen=("trivy", "grype"))]), path=db)
    rows = run_findings(1, path=db)
    assert rows[0]["engine"] == "trivy,grype"


def test_degraded_flag_is_persisted(tmp_path):
    db = str(tmp_path / "h.db")
    save(_result(degraded=True), path=db)
    assert list_runs(5, path=db)[0]["degraded"] == 1


def test_multiple_runs_are_newest_first(tmp_path):
    db = str(tmp_path / "h.db")
    save(_result(target="a"), path=db)
    save(_result(target="b"), path=db)
    save(_result(target="c"), path=db)
    assert [r["target"] for r in list_runs(10, path=db)] == ["c", "b", "a"]


def test_limit_is_respected(tmp_path):
    db = str(tmp_path / "h.db")
    for i in range(5):
        save(_result(target=f"t{i}"), path=db)
    assert len(list_runs(2, path=db)) == 2


def test_empty_database_lists_nothing(tmp_path):
    assert list_runs(5, path=str(tmp_path / "empty.db")) == []


def test_schema_version_is_stamped(tmp_path):
    db = str(tmp_path / "h.db")
    save(_result(), path=db)
    c = sqlite3.connect(db)
    assert c.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0] \
        == str(SCHEMA_VERSION)
    c.close()


def test_migration_adds_degraded_column_to_old_database(tmp_path):
    """An existing history.db from an older sarbar must keep working."""
    db = str(tmp_path / "old.db")
    c = sqlite3.connect(db)
    c.executescript("""
        CREATE TABLE runs(
          id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, target TEXT,
          kind TEXT, profile TEXT, engines TEXT, score REAL, level TEXT,
          verdict TEXT, counts TEXT, offline INTEGER);
        CREATE TABLE findings(
          run_id INTEGER, check_id TEXT, severity TEXT, package TEXT,
          version TEXT, engine TEXT, category TEXT, title TEXT);
        INSERT INTO runs(ts,target,kind,profile,engines,score,level,verdict,
                         counts,offline)
        VALUES(1,'legacy','image','default','trivy',10.0,'low','pass','{}',0);
    """)
    c.commit()
    c.close()

    runs = list_runs(5, path=db)
    assert len(runs) == 1 and runs[0]["target"] == "legacy"
    assert runs[0]["degraded"] == 0
    save(_result(target="new"), path=db)   # must not raise
    assert len(list_runs(5, path=db)) == 2


def test_long_title_is_truncated(tmp_path):
    db = str(tmp_path / "h.db")
    save(_result(findings=[_finding(check_id="CVE-X")]), path=db)
    rows = run_findings(1, path=db)
    assert len(rows[0]["title"]) <= 500


def test_runs_are_dict_like(tmp_path):
    db = str(tmp_path / "h.db")
    save(_result(), path=db)
    run = list_runs(1, path=db)[0]
    assert run["target"] == "app:latest"
    assert run.get("target") == "app:latest"