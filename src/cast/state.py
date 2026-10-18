"""
Маленькое хранилище состояния: отметка «проверка хоста уже показывалась».

По правилам Linux данные программы лежат в /var/lib/<имя>; если туда нельзя
писать (обычный пользователь), используется ~/.local/state/<имя> (XDG).
Переменная CAST_STATE_DIR переопределяет место (нужна тестам).
"""

from __future__ import annotations

import os
from pathlib import Path

_MARKER = "host-checked"


def _candidate_dirs() -> list[Path]:
    override = os.environ.get("CAST_STATE_DIR")
    if override:
        return [Path(override)]
    xdg = os.environ.get("XDG_STATE_HOME")
    user_dir = (Path(xdg) if xdg else Path.home() / ".local" / "state") / "cast"
    return [Path("/var/lib/cast"), user_dir]


def host_check_done() -> bool:
    return any((d / _MARKER).exists() for d in _candidate_dirs())


def mark_host_checked() -> None:
    for directory in _candidate_dirs():
        try:
            directory.mkdir(parents=True, exist_ok=True)
            (directory / _MARKER).touch()
            return
        except OSError:
            continue
