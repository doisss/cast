"""
Определение цели сканирования.

Пользователь пишет просто `cast scan <что-то>`, а cast сам понимает, что это:

  alpine:3.19, nginx      образ (любое имя без ./ — всегда образ)
  12b1e6c27fd6            ID запущенного контейнера (если такой есть среди запущенных)
  Dockerfile              Dockerfile (Dockerfile, Dockerfile.*, *.Dockerfile, Containerfile)
  deploy.yaml, main.tf    конфигурация: Kubernetes, Terraform, Helm, CloudFormation,
                          docker-compose (тип файла — по имени и содержимому)
  alpine.tar              архив образа (docker save): .tar/.tar.gz/.tgz с manifest.json
  sbom.cdx.json           SBOM: CycloneDX или SPDX (по содержимому файла)
  disk.qcow2              образ диска ВМ: .vmdk/.qcow2/.vhd/.vhdx/.img/.raw
  ., ./app, /srv/app, ~/x папка; если внутри есть etc/os-release (в т.ч. /) — корневая ФС,
                          если Chart.yaml — Helm-чарт
  https://..., git@...    git-репозиторий
  host                    Docker-хост (текущая машина)
  cluster                 кластер Kubernetes (текущий контекст kubeconfig)

Порядок: зарезервированное слово → URL → путь (./ ../ / ~) → существующий файл
→ ID запущенного контейнера → имя образа. Токен с расширением файла (alpine.tar,
deploy.yaml), которого нет на диске, — ошибка «файл не найден», а не образ.

Явные формы нужны, только когда автоопределение не подходит:
  cast scan image X | container X (имя или ID) | dockerfile ПУТЬ | fs ПУТЬ | host
          | config ПУТЬ | rootfs ПУТЬ | archive ФАЙЛ | sbom ФАЙЛ | vm ФАЙЛ | repo URL | cluster

Слова host, cluster, image, container, dockerfile, fs, config, rootfs, archive, sbom, vm,
repo зарезервированы.
"""

from __future__ import annotations

import json
import re
import subprocess
import tarfile
from dataclasses import dataclass, field
from pathlib import Path

RESERVED_WORDS = ("host", "cluster", "image", "container", "dockerfile", "fs",
                  "config", "rootfs", "archive", "sbom", "vm", "repo")
KINDS = ("image", "container", "dockerfile", "fs", "host",
         "archive", "config", "rootfs", "repo", "sbom", "vm", "cluster")

KIND_TITLES = {
    "image": "образ",
    "container": "запущенный контейнер",
    "dockerfile": "Dockerfile",
    "fs": "папка",
    "host": "Docker-хост",
    "archive": "архив образа",
    "config": "конфигурация",
    "rootfs": "корневая ФС",
    "repo": "git-репозиторий",
    "sbom": "SBOM",
    "vm": "образ диска ВМ",
    "cluster": "кластер Kubernetes",
}

# явная форма «cast scan СЛОВО ЦЕЛЬ»: пример цели для сообщения об ошибке
_EXPLICIT_EXAMPLES = {
    "image": "alpine:3.19", "container": "имя_или_ID", "dockerfile": "путь/к/файлу",
    "fs": "./папка", "config": "deploy.yaml", "rootfs": "/", "archive": "alpine.tar",
    "sbom": "sbom.cdx.json", "vm": "disk.qcow2", "repo": "https://github.com/user/repo",
}

_URL_PREFIXES = ("https://", "http://", "git@")
_ARCHIVE_SUFFIXES = (".tar", ".tar.gz", ".tgz")
_VM_SUFFIXES = (".vmdk", ".qcow2", ".vhd", ".vhdx", ".img", ".raw")
# расширения файлов, которые cast умеет проверять: такой токен без файла — опечатка в пути
_FILE_SUFFIXES = (_ARCHIVE_SUFFIXES + _VM_SUFFIXES
                  + (".tf", ".yaml", ".yml", ".json", ".spdx", ".cdx"))
_COMPOSE_NAME_RE = re.compile(r"(?i)(docker-)?compose(\..+)?\.ya?ml")
_SBOM_SNIFF_BYTES = 64 * 1024 * 1024   # больше не читаем: SBOM такого размера редкость

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
    subtype: str | None = None          # config: Kubernetes/Terraform/...; sbom: CycloneDX/SPDX

    @property
    def label(self) -> str:
        if self.kind == "host":
            return "Docker-хост (текущая машина)"
        if self.kind == "container":
            return f"{self.container_name or self.value} (контейнер, образ {self.image_name or '?'})"
        if self.kind == "cluster":
            return "кластер Kubernetes (текущий контекст kubeconfig)"
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


def _has_image_manifest(path: Path) -> bool:
    """Архив образа (docker save, OCI-layout) содержит manifest.json или index.json в корне."""
    try:
        with tarfile.open(path) as tar:
            names = {m.name.lstrip("./") for m in tar.getmembers()}
    except (tarfile.TarError, OSError, EOFError):
        return False
    return bool(names & {"manifest.json", "index.json"})


def _sniff_text(path: Path) -> tuple[str, dict | None]:
    """Текст файла (если он текстовый) и разобранный JSON, если это JSON."""
    try:
        if path.stat().st_size > _SBOM_SNIFF_BYTES:
            return "", None
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return "", None
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    return text, data if isinstance(data, dict) else None


def classify_file(path: Path) -> tuple[str, str | None] | None:
    """Что это за файл: (вид цели, подтип) или None, если cast не понял."""
    name = path.name
    low = name.lower()
    if is_dockerfile_name(name):
        return "dockerfile", None
    if low.endswith(_ARCHIVE_SUFFIXES):
        return ("archive", None) if _has_image_manifest(path) else None
    if low.endswith(_VM_SUFFIXES):
        return "vm", None
    if low.endswith((".tf", ".tf.json")):
        return "config", "Terraform"
    if low in ("chart.yaml", "chart.yml"):
        return "config", "Helm"
    if _COMPOSE_NAME_RE.fullmatch(name):
        return "config", "docker-compose"

    text, data = _sniff_text(path)
    if not text:
        return None
    if data is not None:
        if data.get("bomFormat") == "CycloneDX":
            return "sbom", "CycloneDX"
        if "spdxVersion" in data or "SPDXVersion" in data:
            return "sbom", "SPDX"
        if "AWSTemplateFormatVersion" in data or _is_cfn_resources(data.get("Resources")):
            return "config", "CloudFormation"
        if "apiVersion" in data and "kind" in data:
            return "config", "Kubernetes"
        return None
    if re.search(r"(?m)^SPDXVersion:", text):
        return "sbom", "SPDX"
    if re.search(r"(?m)^AWSTemplateFormatVersion:", text) or re.search(r"(?m)^\s+Type:\s*['\"]?AWS::", text):
        return "config", "CloudFormation"
    if re.search(r"(?m)^apiVersion:", text) and re.search(r"(?m)^kind:", text):
        return "config", "Kubernetes"
    return None


def _is_cfn_resources(resources) -> bool:
    return isinstance(resources, dict) and any(
        isinstance(r, dict) and str(r.get("Type", "")).startswith("AWS::") for r in resources.values()
    )


def _file_target(token: str, path: Path) -> Target:
    kind_sub = classify_file(path)
    if kind_sub is None:
        low = path.name.lower()
        if low.endswith(_ARCHIVE_SUFFIXES):
            thought = "tar-архив, но не образ: внутри нет manifest.json или index.json"
        else:
            thought = ("файл, но не похож ни на Dockerfile, ни на конфигурацию (Kubernetes, "
                       "Terraform, Helm, CloudFormation, docker-compose), ни на SBOM "
                       "(CycloneDX, SPDX), ни на образ диска ВМ")
        raise TargetError(
            f"«{token}» — {thought}. Если cast ошибся, укажите вид явно: "
            f"cast scan dockerfile {token} (Dockerfile с другим именем), "
            f"cast scan config {token}, cast scan sbom {token}, cast scan archive {token}, "
            f"cast scan vm {token}"
        )
    kind, subtype = kind_sub
    target = Target(kind, token, subtype=subtype)
    if subtype == "Helm":
        target.value = str(path.parent)     # Trivy проверяет чарт целиком, по папке
    if subtype == "docker-compose":
        target.notes.append(_COMPOSE_NOTE)
    return target


_COMPOSE_NOTE = (
    "в Trivy нет проверок для docker-compose (его trivy config не разбирает), поэтому "
    "отчёт по этому файлу будет пустым. Пустой отчёт не значит, что ошибок нет."
)


def _dir_target(token: str, path: Path) -> Target:
    if (path / "etc" / "os-release").is_file():
        return Target("rootfs", token)
    if (path / "Chart.yaml").is_file():
        return Target("config", token, subtype="Helm")
    return Target("fs", str(path))


def _path_target(token: str) -> Target:
    path = Path(token).expanduser()
    if path.is_dir():
        return _dir_target(token, path)
    if path.is_file():
        return _file_target(token, path)
    raise TargetError(f"путь «{token}» не найден")


def _auto(token: str) -> Target:
    # 1. адрес git-репозитория
    if token.startswith(_URL_PREFIXES):
        return Target("repo", token)

    # 2. явный путь: ., .., ./x, ../x, /x, ~/x
    if token in (".", "..") or token.startswith(("./", "../", "/", "~")):
        return _path_target(token)

    # 3. существующий файл: вид — по имени и содержимому (в т.ч. docker/Dockerfile.dev)
    path = Path(token)
    if path.is_file():
        return _file_target(token, path)

    # 4. похоже на имя файла, но файла нет: это опечатка в пути, а не образ «alpine.tar»
    if token.lower().endswith(_FILE_SUFFIXES):
        raise TargetError(
            f"файл «{token}» не найден. Если это всё же имя образа, укажите явно: "
            f"cast scan image {token}"
        )

    # 5. ID запущенного контейнера
    if _HEX_ID_RE.match(token):
        container = _running_container_by_id(token)
        if container:
            container.value = token
            return container

    # 6. иначе — образ
    target = Target("image", token)
    exists = _image_exists_locally(token)
    if exists is False:
        target.image_missing = True
        target.notes.append(
            f"образа «{token}» нет на текущей машине — Trivy попробует скачать его из реестра "
            "(Docker Hub). Если имя написано с ошибкой, скачивание не получится."
        )
    if path.is_dir():
        target.notes.append(
            f"в текущей папке есть папка «{token}». Для неё нужно писать cast scan ./{token}; "
            "без «./» cast считает это именем образа."
        )
    return target


def _explicit(word: str, value: str) -> Target:
    """Явная форма: cast scan config deploy.yaml и т.п. Вид не угадываем, только проверяем,
    что цель существует; подтип (Kubernetes, CycloneDX) — для заголовка, если узнали."""
    path = Path(value).expanduser()
    if word == "repo":
        return Target("repo", value)
    if word == "rootfs":
        if not path.is_dir():
            raise TargetError(f"папка «{value}» не найдена")
        return Target("rootfs", value)
    if word == "config":
        if path.is_dir():
            return Target("config", value, subtype="Helm" if (path / "Chart.yaml").is_file() else None)
        if not path.is_file():
            raise TargetError(f"файл «{value}» не найден")
        kind_sub = classify_file(path)
        subtype = kind_sub[1] if kind_sub and kind_sub[0] == "config" else None
        target = Target("config", str(path.parent) if subtype == "Helm" else value, subtype=subtype)
        if subtype == "docker-compose":
            target.notes.append(_COMPOSE_NOTE)
        return target
    if not path.is_file():
        raise TargetError(f"файл «{value}» не найден")
    subtype = None
    if word == "sbom":
        kind_sub = classify_file(path)
        subtype = kind_sub[1] if kind_sub and kind_sub[0] == "sbom" else None
    return Target(word, value, subtype=subtype)


def resolve_target(tokens: list[str]) -> Target:
    if not tokens:
        raise TargetError("не указана цель. Пример: cast scan alpine:3.19")

    first = tokens[0]

    if first in ("host", "cluster"):
        if len(tokens) > 1:
            raise TargetError(f"после «{first}» ничего указывать не нужно: cast scan {first}")
        return Target(first, first)

    if first in _EXPLICIT_EXAMPLES:
        if len(tokens) != 2:
            raise TargetError(
                f"после «{first}» нужно указать одну цель: cast scan {first} {_EXPLICIT_EXAMPLES[first]}"
            )
        value = tokens[1]
        if first == "image":
            target = Target("image", value)
            if _image_exists_locally(value) is False:
                target.image_missing = True
                target.notes.append(
                    f"образа «{value}» нет на текущей машине — Trivy попробует скачать его из реестра."
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
        if first == "fs":
            if not Path(value).expanduser().is_dir():
                raise TargetError(f"папка «{value}» не найдена")
            return Target("fs", value)
        return _explicit(first, value)

    if len(tokens) > 1:
        raise TargetError(
            f"лишний аргумент «{tokens[1]}». Цель одна. Если имя содержит пробелы, "
            "возьмите его в кавычки."
        )
    return _auto(first)
