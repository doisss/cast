"""
Проводник веба: содержимое папок и простые действия с файлами (переименовать,
удалить, создать папку, посмотреть текст). Всё — на машине, где запущен cast web,
и только после входа по паролю.

Под sudo веб работает от root, поэтому созданная папка отдаётся тому, кто
запустил sudo (SUDO_UID), а удалять корень и системные папки нельзя совсем.
"""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path

from cast.web.discover import user_home

VIEW_LIMIT = 1024 * 1024        # больше — не показываем в браузере, только скачать
# корень и системные папки: удалить или переименовать их из веба нельзя
_PROTECTED = {"/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib32", "/lib64", "/libx32",
              "/media", "/mnt", "/opt", "/proc", "/root", "/run", "/sbin", "/srv", "/sys", "/tmp",
              "/usr", "/var"}


class FileError(Exception):
    """Сообщение для пользователя."""


def _kind(entry: os.DirEntry, is_dir: bool, is_link: bool) -> str:
    if is_dir:
        return "папка"
    if is_link:
        return "ссылка"
    name = entry.name
    if "." in name.strip("."):
        return name.rsplit(".", 1)[1].lower()
    return "файл"


def list_dir(raw: str, show_hidden: bool = False) -> dict:
    """Содержимое папки: имя, дата изменения, размер, тип. Файлы не читаются."""
    path = Path(raw or os.getcwd()).expanduser()
    try:
        path = path.resolve()
        if not path.is_dir():
            path = path.parent
        entries = []
        with os.scandir(path) as it:
            for entry in it:
                if entry.name.startswith(".") and not show_hidden:
                    continue
                try:
                    is_link = entry.is_symlink()
                    is_dir = entry.is_dir()
                    st = entry.stat(follow_symlinks=not is_link or is_dir)
                    size, mtime = (0 if is_dir else st.st_size), st.st_mtime
                except OSError:
                    is_link, is_dir, size, mtime = False, False, 0, 0
                entries.append({"name": entry.name, "path": str(path / entry.name), "dir": is_dir,
                                "link": is_link, "size": size, "mtime": mtime,
                                "kind": _kind(entry, is_dir, is_link)})
    except PermissionError:
        return {"path": str(path), "parent": str(path.parent), "entries": [],
                "error": "нет прав читать эту папку"}
    except OSError as exc:
        return {"path": str(path), "parent": str(path.parent), "entries": [],
                "error": exc.strerror or str(exc)}
    entries.sort(key=lambda e: (not e["dir"], e["name"].lower()))
    return {"path": str(path), "parent": str(path.parent), "entries": entries, "error": ""}


def _checked(raw: str) -> Path:
    if not raw or not raw.startswith("/"):
        raise FileError("нужен полный путь")
    path = Path(os.path.normpath(raw))
    if str(path) in _PROTECTED or path in (Path.home(), user_home()):
        raise FileError(f"{path} — системная папка, её из веба не трогаем")
    return path


def _new_name(name: str) -> str:
    name = name.strip()
    if not name or name in (".", "..") or "/" in name or "\0" in name:
        raise FileError("недопустимое имя")
    return name


def _give_to_user(path: Path) -> None:
    """Под sudo новая папка принадлежала бы root — отдаём её тому, кто запустил sudo."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if os.geteuid() == 0 and uid and gid:
        try:
            os.chown(path, int(uid), int(gid))
        except (OSError, ValueError):
            pass


def make_dir(parent: str, name: str) -> str:
    folder = Path(parent)
    if not folder.is_dir():
        raise FileError("папки нет")
    path = folder / _new_name(name)
    try:
        path.mkdir()
    except FileExistsError:
        raise FileError(f"«{path.name}» уже есть") from None
    except OSError as exc:
        raise FileError(exc.strerror or str(exc)) from None
    _give_to_user(path)
    return str(path)


def rename(raw: str, name: str) -> str:
    path = _checked(raw)
    new = path.parent / _new_name(name)
    if new.exists() or new.is_symlink():
        raise FileError(f"«{new.name}» уже есть")
    try:
        path.rename(new)
    except OSError as exc:
        raise FileError(exc.strerror or str(exc)) from None
    return str(new)


def delete(raw: str) -> None:
    path = _checked(raw)
    try:
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()
    except FileNotFoundError:
        raise FileError("уже удалено") from None
    except OSError as exc:
        raise FileError(exc.strerror or str(exc)) from None


def read_text(raw: str) -> dict:
    """Текст файла для просмотра в браузере (без изменений, только чтение)."""
    path = Path(raw)
    try:
        st = path.stat()
    except OSError as exc:
        return {"ok": False, "text": exc.strerror or str(exc)}
    if not stat.S_ISREG(st.st_mode):
        return {"ok": False, "text": "это не обычный файл"}
    if st.st_size > VIEW_LIMIT:
        return {"ok": False, "text": f"файл больше {VIEW_LIMIT // 1024 // 1024} МБ — его можно только скачать"}
    try:
        data = path.read_bytes()
    except OSError as exc:
        return {"ok": False, "text": exc.strerror or str(exc)}
    if b"\0" in data[:8192]:
        return {"ok": False, "text": "двоичный файл — его можно только скачать"}
    return {"ok": True, "text": data.decode("utf-8", "replace")}
