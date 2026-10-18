"""
Определение цели сканирования.

Пользователь пишет просто `cast scan <что-то>`, а cast сам понимает, что это:

  alpine:3.19, nginx      образ (любое имя без ./ — всегда образ)
  12b1e6c27fd6            ID запущенного контейнера (если такой есть среди запущенных)
  Dockerfile              Dockerfile (Dockerfile, Dockerfile.*, *.Dockerfile, Containerfile)
  ., ./app, /srv/app, ~/x папка
  host                    Docker-хост (эта машина)

Явные формы нужны, только когда автоопределение не подходит:
  cast scan image X | container X (имя или ID) | dockerfile ПУТЬ | fs ПУТЬ | host

Слова host, image, container, dockerfile, fs зарезервированы.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

RESERVED_WORDS = ("host", "image", "container", "dockerfile", "fs")
KINDS = ("image", "container", "dockerfile", "fs", "host")

KIND_TITLES = {
    "image": "образ",
    "container": "запущенный контейнер",
    "dockerfile": "Dockerfile",
    "fs": "папка",
    "host": "Docker-хост",
}

_DOCKERFILE_NAME_RE = re.compile(
    r"(?i)(dockerfile(\..+)?|.+\.dockerfile|containerfile(\..+)?|.+\.containerfile)"
)
_HEX_ID_RE = re.compile(r"^[0-9a-f]{12,64}$")


class TargetError(ValueError):
    """Цель указана неверно. Сообщение написано для пользователя."""


@dataclass
class Target:
    kind: str
    value: str
    container_name: str | None = None   # для kind == "container"
    image_ref: str | None = None        # для контейнера: ID его образа (для Trivy)
    image_name: str | None = None       # для контейнера: имя образа, как в docker ps
    notes: list[str] = field(default_factory=list)
    image_missing: bool = False         # образа нет локально: Trivy скачает его сам

    @property
    def label(self) -> str:
        if self.kind == "host":
            return "Docker-хост (эта машина)"
        if self.kind == "container":
            return f"{self.container_name or self.value} (контейнер, образ {self.image_name or '?'})"
        return self.value


def run_docker(*args: str) -> subprocess.CompletedProcess | None:
    """Вызов docker CLI. Вынесено отдельно, чтобы подменять в тестах.
    None — docker не установлен или не отвечает."""
    try:
        return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None


def is_dockerfile_name(name: str) -> bool:
    return bool(_DOCKERFILE_NAME_RE.fullmatch(name))


def _inspect_container(ref: str) -> Target | None:
    proc = run_docker(
        "inspect", "--type", "container", "--format",
        "{{.Name}}|{{.Config.Image}}|{{.Image}}", ref,
    )
    if proc is None or proc.returncode != 0 or "|" not in proc.stdout:
        return None
    name, image_name, image_id = proc.stdout.strip().split("|", 2)
    return Target(
        kind="container",
        value=ref,
        container_name=name.lstrip("/"),
        image_name=image_name,
        image_ref=image_id,
    )


def _running_container_by_id(token: str) -> Target | None:
    proc = run_docker("ps", "--no-trunc", "--format", "{{.ID}}")
    if proc is None or proc.returncode != 0:
        return None
    for full_id in proc.stdout.split():
        if full_id.startswith(token):
            return _inspect_container(full_id)
    return None


def _image_exists_locally(ref: str) -> bool | None:
    """True/False, либо None, если узнать не удалось (нет docker или прав)."""
    proc = run_docker("image", "inspect", "--format", "{{.Id}}", ref)
    if proc is None:
        return None
    if proc.returncode == 0:
        return True
    if "permission denied" in (proc.stderr or "").lower():
        return None
    return False


def _path_target(token: str) -> Target:
    path = Path(token).expanduser()
    if path.is_dir():
        return Target("fs", str(path))
    if path.is_file():
        if is_dockerfile_name(path.name):
            return Target("dockerfile", str(path))
        raise TargetError(
            f"«{token}» — файл с нестандартным именем. Если это Dockerfile, укажите явно: "
            f"cast scan dockerfile {token}"
        )
    raise TargetError(f"путь «{token}» не найден")


def _auto(token: str) -> Target:
    # 1. явный путь: ., .., ./x, ../x, /x, ~/x
    if token in (".", "..") or token.startswith(("./", "../", "/", "~")):
        return _path_target(token)

    # 2. существующий файл с именем Dockerfile (в т.ч. docker/Dockerfile.dev)
    path = Path(token)
    if path.is_file():
        if is_dockerfile_name(path.name):
            return Target("dockerfile", token)
        raise TargetError(
            f"«{token}» — файл, но не похож на Dockerfile. Если это Dockerfile с другим "
            f"именем, укажите явно: cast scan dockerfile {token}"
        )

    # 3. ID запущенного контейнера
    if _HEX_ID_RE.match(token):
        container = _running_container_by_id(token)
        if container:
            container.value = token
            return container

    # 4. иначе — образ
    target = Target("image", token)
    exists = _image_exists_locally(token)
    if exists is False:
        target.image_missing = True
        target.notes.append(
            f"образа «{token}» нет на этой машине — Trivy попробует скачать его из реестра "
            "(Docker Hub). Если имя написано с ошибкой, скачивание не получится."
        )
    if path.is_dir():
        target.notes.append(
            f"в текущей папке есть папка «{token}». Для неё нужно писать cast scan ./{token}; "
            "без «./» cast считает это именем образа."
        )
    return target


def resolve_target(tokens: list[str]) -> Target:
    if not tokens:
        raise TargetError("не указана цель. Пример: cast scan alpine:3.19")

    first = tokens[0]

    if first == "host":
        if len(tokens) > 1:
            raise TargetError("после «host» ничего указывать не нужно: cast scan host")
        return Target("host", "host")

    if first in ("image", "container", "dockerfile", "fs"):
        if len(tokens) != 2:
            example = {"image": "alpine:3.19", "container": "имя_или_ID", "dockerfile": "путь/к/файлу", "fs": "./папка"}[first]
            raise TargetError(f"после «{first}» нужно указать одну цель: cast scan {first} {example}")
        value = tokens[1]
        if first == "image":
            target = Target("image", value)
            if _image_exists_locally(value) is False:
                target.image_missing = True
                target.notes.append(
                    f"образа «{value}» нет на этой машине — Trivy попробует скачать его из реестра."
                )
            return target
        if first == "container":
            target = _inspect_container(value)
            if target is None:
                raise TargetError(
                    f"контейнер «{value}» не найден (или нет доступа к Docker — попробуйте sudo). "
                    "Список: docker ps"
                )
            return target
        if first == "dockerfile":
            if not Path(value).expanduser().is_file():
                raise TargetError(f"файл «{value}» не найден")
            return Target("dockerfile", value)
        if not Path(value).expanduser().is_dir():
            raise TargetError(f"папка «{value}» не найдена")
        return Target("fs", value)

    if len(tokens) > 1:
        raise TargetError(
            f"лишний аргумент «{tokens[1]}». Цель одна. Если имя содержит пробелы, "
            "возьмите его в кавычки."
        )
    return _auto(first)
