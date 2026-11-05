"""
Вход в веб-интерфейс по логину и паролю.

Пароль спрашивается в терминале при первом `cast web` и сохраняется в
~/.config/cast/web.json (права 600). Под sudo — в том же файле того, кто запустил
sudo: пароль один, с sudo и без. Сохраняется не сам пароль, а его хэш
scrypt с солью: по файлу пароль не восстановить, можно только проверить.
Сменить логин и пароль: cast web --reset-password.

В браузере после входа ставится cookie сессии (HttpOnly, SameSite=Strict).
Сессии живут, пока запущен cast web. После 5 неверных попыток с одного адреса
вход с него закрыт на минуту — чтобы пароль нельзя было подбирать.
"""

from __future__ import annotations

import base64
import getpass
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from pathlib import Path

_N, _R, _P = 2 ** 14, 8, 1        # параметры scrypt: ~16 МБ памяти и ~50 мс на проверку
MAX_FAILS, BLOCK_SECONDS = 5, 60


def _sudo_owner() -> tuple[int, int] | None:
    """Под sudo — кто запустил (uid, gid): пароль у него один и тот же, с sudo и без."""
    if os.geteuid() != 0 or not os.environ.get("SUDO_UID"):
        return None
    try:
        return int(os.environ["SUDO_UID"]), int(os.environ.get("SUDO_GID", os.environ["SUDO_UID"]))
    except ValueError:
        return None


def config_path() -> Path:
    if os.environ.get("XDG_CONFIG_HOME"):
        return Path(os.environ["XDG_CONFIG_HOME"]) / "cast" / "web.json"
    owner = _sudo_owner()
    if owner:
        import pwd
        try:
            return Path(pwd.getpwuid(owner[0]).pw_dir) / ".config" / "cast" / "web.json"
        except KeyError:
            pass
    return Path.home() / ".config" / "cast" / "web.json"


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_N, r=_R, p=_P)
    b64 = lambda b: base64.b64encode(b).decode("ascii")
    return f"scrypt${_N}${_R}${_P}${b64(salt)}${b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        kind, n, r, p, salt, digest = stored.split("$")
        if kind != "scrypt":
            return False
        got = hashlib.scrypt(password.encode("utf-8"), salt=base64.b64decode(salt),
                             n=int(n), r=int(r), p=int(p))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(got, base64.b64decode(digest))


def load(path: Path | None = None) -> tuple[str, str] | None:
    """(логин, хэш) из файла или None, если файла нет или он испорчен."""
    path = path or config_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return str(data["login"]), str(data["password"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def save(login: str, password_hash: str, path: Path | None = None) -> Path:
    path = path or config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    # сначала создаём с правами 600, потом пишем: хэш ни на миг не виден другим
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({"login": login, "password": password_hash}, fh, ensure_ascii=False)
    os.chmod(path, 0o600)
    owner = _sudo_owner()
    if owner:      # создано под sudo — файл и папка всё равно принадлежат пользователю
        for item in (path.parent.parent, path.parent, path):
            if item.exists() and item.stat().st_uid == 0 and item != Path.home():
                os.chown(item, *owner)
    return path


_BROKEN_INPUT = ("Не разобрал ввод: в нём оборванный символ. Так бывает, если стереть русскую "
                 "букву, а терминал удалил только половину её байтов. Введите ещё раз.")


def _read(read, prompt: str, say) -> str:
    """Ввод с повтором: оборванный UTF-8 (стёртая наполовину русская буква) — не падение,
    а просьба ввести снова."""
    while True:
        try:
            return read(prompt)
        except UnicodeDecodeError:
            say(_BROKEN_INPUT)


def check_login(login: str) -> str:
    """Пусто — логин подходит, иначе что не так. Логин — любые буквы (и русские),
    цифры и знаки, но без пробелов: его вводят в форме входа, и пробел по краям легко
    не заметить."""
    if not login:
        return "логин пустой"
    if len(login) > 64:
        return "логин длиннее 64 символов"
    if any(ch.isspace() or not ch.isprintable() for ch in login):
        return "в логине не должно быть пробелов и служебных символов"
    return ""


def ask(say, read=input, read_secret=getpass.getpass) -> tuple[str, str]:
    """Спросить логин и пароль в терминале. Пустой пароль — придумать случайный."""
    try:
        import readline  # noqa: F401  — с ним input() стирает русскую букву целиком
    except ImportError:
        pass
    default = os.environ.get("SUDO_USER") or getpass.getuser()
    while True:
        login = _read(read, f"Логин для входа в веб [{default}]: ", say).strip() or default
        problem = check_login(login)
        if not problem:
            break
        say(f"Не подходит: {problem}")
    while True:
        password = _read(read_secret, "Пароль (Enter — придумать случайный): ", say)
        if not password:
            password = secrets.token_urlsafe(9)
            say(f"Пароль: {password}  — запишите его, больше он не покажется")
            break
        if len(password) < 8:
            say("Пароль короче 8 символов — придумайте длиннее")
            continue
        if _read(read_secret, "Ещё раз: ", say) == password:
            break
        say("Пароли не совпали, попробуйте снова")
    return login, password


class Auth:
    """Проверка логина и пароля, сессии и счётчик неудачных попыток."""

    def __init__(self, login: str, password_hash: str, clock=time.monotonic):
        self.login = login
        self.password_hash = password_hash
        self._sessions: set[str] = set()
        self._fails: dict[str, tuple[int, float]] = {}   # адрес -> (неудач подряд, когда закрыт до)
        self._lock = threading.Lock()
        self._clock = clock

    def blocked(self, addr: str) -> int:
        """Сколько секунд ещё закрыт вход с этого адреса (0 — открыт)."""
        with self._lock:
            _, until = self._fails.get(addr, (0, 0.0))
            return max(0, int(until - self._clock() + 0.999))

    def check(self, addr: str, login: str, password: str) -> str | None:
        """Новая сессия при верных логине и пароле, иначе None."""
        if self.blocked(addr):
            return None
        # пароль проверяем всегда, даже при неверном логине: по времени ответа
        # нельзя понять, угадан ли логин
        ok = verify_password(password, self.password_hash)
        ok = hmac.compare_digest(login.encode("utf-8"), self.login.encode("utf-8")) and ok
        with self._lock:
            if not ok:
                fails = self._fails.get(addr, (0, 0.0))[0] + 1
                until = self._clock() + BLOCK_SECONDS if fails >= MAX_FAILS else 0.0
                self._fails[addr] = (0 if until else fails, until)
                return None
            self._fails.pop(addr, None)
            session = secrets.token_urlsafe(32)
            self._sessions.add(session)
            return session

    def valid(self, session: str | None) -> bool:
        if not session:
            return False
        with self._lock:
            return any(hmac.compare_digest(session, s) for s in self._sessions)

    def logout(self, session: str | None) -> None:
        with self._lock:
            self._sessions.discard(session or "")
