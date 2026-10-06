"""Local run history (SQLite). A future web UI can read the same DB.

Location: $XDG_STATE_HOME/sarbar/history.db  (default ~/.local/state/sarbar/)

Why state, why not /var/lib: the XDG Base Directory Specification says
XDG_STATE_HOME holds "state data that should persist between (application)
restarts ... actions history (logs, history, recently used files)". Scan history
is precisely that. /var/lib is for daemons that own machine-wide state
(/var/lib/apt, /var/lib/dpkg, /var/lib/docker), not for one person's log of what
they scanned.

An existing ~/.sarbar/history.db from an older sarbar is migrated on first use,
so upgrading does not lose the record of past runs.

The schema is created with an idempotent migration so an existing database from
an older sarbar version keeps working and stops the engine-name drift that used
so rows written by an older sarbar stay readable.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time


SCHEMA_VERSION = 2

_BASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER, target TEXT, kind TEXT, profile TEXT,
  engines TEXT, score REAL, level TEXT, verdict TEXT,
  counts TEXT, offline INTEGER, degraded INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS findings(
  run_id INTEGER, check_id TEXT, severity TEXT, package TEXT,
  version TEXT, engine TEXT, category TEXT, title TEXT);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
"""

# Column additions applied to pre-existing databases.
_MIGRATIONS = {
    2: [("runs", "degraded", "INTEGER DEFAULT 0")],
}


class _Row(dict):
    """dict that also allows attribute access (cosmetic for callers)."""
    __getattr__ = dict.__getitem__


def state_dir() -> str:
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    if not os.path.isabs(base):
        base = os.path.expanduser("~/.local/state")
    return os.path.join(base, "sarbar")


def legacy_db() -> str:
    """Where older sarbar versions kept the database."""
    return os.path.join(os.path.expanduser("~/.sarbar"), "history.db")


def db_path() -> str:
    d = state_dir()
    try:
        os.makedirs(d, mode=0o700, exist_ok=True)
    except OSError:
        pass
    return os.path.join(d, "history.db")


def migrate_legacy() -> str | None:
    """Move a pre-XDG database into the new location. Returns the new path."""
    old, new = legacy_db(), db_path()
    if not os.path.isfile(old) or os.path.abspath(old) == os.path.abspath(new):
        return None
    os.makedirs(os.path.dirname(new), exist_ok=True)
    try:
        os.replace(old, new)
    except OSError:
        return None
    return new


def _conn(path: str | None = None) -> sqlite3.Connection:
    if path is None:
        migrate_legacy()
    c = sqlite3.connect(path or db_path())
    c.execute("PRAGMA foreign_keys = ON")
    c.executescript(_BASE_SCHEMA)
    cur = int(c.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0]) \
        if c.execute("SELECT 1 FROM meta WHERE key='schema_version'").fetchone() else 1
    for version in sorted(_MIGRATIONS):
        if version <= cur:
            continue
        for table, column, decl in _MIGRATIONS[version]:
            cols = {r[1] for r in c.execute(f"PRAGMA table_info({table})")}
            if column not in cols:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
    c.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('schema_version',?)",
              (str(SCHEMA_VERSION),))
    c.commit()
    return c


def save(res: dict, path: str | None = None) -> int:
    c = _conn(path)
    try:
        cur = c.execute(
            "INSERT INTO runs(ts,target,kind,profile,engines,score,level,verdict,"
            "counts,offline,degraded) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (int(time.time()), res["target"], res["target_kind"], res["profile"],
             ",".join(res["scanners_used"]), res["risk"]["score"], res["risk"]["level"],
             res["verdict"], json.dumps(res["risk"]["counts"]),
             int(bool(res.get("offline"))), int(bool(res.get("degraded")))))
        rid = int(cur.lastrowid or 0)
        rows = []
        for f in res["findings"]:
            # engines_seen is the authoritative engine list after dedup; `engine`
            # only records which adapter produced the row first.
            engines = ",".join(getattr(f, "engines_seen", []) or [getattr(f, "engine", "")])
            rows.append((rid, f.check_id, f.severity, f.package, f.installed_version,
                         engines, f.category, f.title[:500]))
        c.executemany("INSERT INTO findings VALUES(?,?,?,?,?,?,?,?)", rows)
        c.commit()
        return rid
    finally:
        c.close()


def list_runs(limit: int = 20, path: str | None = None) -> list[dict]:
    c = _conn(path)
    try:
        rows = c.execute(
            "SELECT id,ts,target,kind,profile,engines,score,level,verdict,"
            "offline,COALESCE(degraded,0) FROM runs ORDER BY id DESC LIMIT ?",
            (limit,)).fetchall()
    finally:
        c.close()
    keys = ["id", "ts", "target", "kind", "profile", "engines", "score", "level",
            "verdict", "offline", "degraded"]
    return [_Row(zip(keys, r)) for r in rows]


def run_findings(run_id: int, path: str | None = None) -> list[dict]:
    c = _conn(path)
    try:
        rows = c.execute(
            "SELECT check_id,severity,package,version,engine,category,title "
            "FROM findings WHERE run_id=? ORDER BY severity", (run_id,)).fetchall()
    finally:
        c.close()
    keys = ["check_id", "severity", "package", "version", "engine", "category", "title"]
    return [dict(zip(keys, r)) for r in rows]