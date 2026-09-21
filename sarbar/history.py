"""Local run history (SQLite). Web UI later reads the same DB — core untouched.

Location: ~/.sarbar/history.db
"""
from __future__ import annotations

import json
import os
import sqlite3
import time


def db_path() -> str:
    d = os.path.expanduser("~/.sarbar")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "history.db")


def _conn(path: str | None = None) -> sqlite3.Connection:
    c = sqlite3.connect(path or db_path())
    c.execute("""CREATE TABLE IF NOT EXISTS runs(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts INTEGER, target TEXT, kind TEXT, profile TEXT,
      engines TEXT, score REAL, level TEXT, verdict TEXT,
      counts TEXT, offline INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS findings(
      run_id INTEGER, check_id TEXT, severity TEXT, package TEXT,
      version TEXT, engine TEXT, category TEXT, title TEXT)""")
    return c


def save(res: dict, path: str | None = None) -> int:
    c = _conn(path)
    cur = c.execute(
        "INSERT INTO runs(ts,target,kind,profile,engines,score,level,verdict,counts,offline)"
        " VALUES(?,?,?,?,?,?,?,?,?,?)",
        (int(time.time()), res["target"], res["target_kind"], res["profile"],
         ",".join(res["engines_used"]), res["risk"]["score"], res["risk"]["level"],
         res["verdict"], json.dumps(res["risk"]["counts"]), int(bool(res.get("offline")))))
    rid = cur.lastrowid or 0
    for f in res["findings"]:
        c.execute("INSERT INTO findings VALUES(?,?,?,?,?,?,?,?)",
                  (rid, f.check_id, f.severity, f.package, f.installed_version,
                   f.engine, f.category, f.title))
    c.commit()
    c.close()
    return int(rid)


def list_runs(limit: int = 20, path: str | None = None) -> list[dict]:
    c = _conn(path)
    rows = c.execute("SELECT id,ts,target,kind,profile,engines,score,level,verdict,offline"
                     " FROM runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    c.close()
    keys = ["id", "ts", "target", "kind", "profile", "engines", "score", "level", "verdict", "offline"]
    return [dict(zip(keys, r)) for r in rows]
