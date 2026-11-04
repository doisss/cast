"""
Что на этой машине можно проверить: для «Что проверить?» в вебе.

Docker и Kubernetes спрашиваются как обычно (docker ps, docker images, kubeconfig),
а файлы ищутся обходом домашней папки и папки, где запущен cast web. Вид файла
определяет та же classify_file, что и `cast scan ПУТЬ`, поэтому веб покажет ровно
то, что cast потом сможет проверить. Обход ограничен по глубине, числу папок и
времени: служебные папки (.cache, node_modules, виртуальные окружения) пропускаются.
"""

from __future__ import annotations

import os
import pwd
import re
import threading
import time
from pathlib import Path

from cast.targets import _FILE_SUFFIXES, classify_file, is_dockerfile_name, run_docker

MAX_DEPTH = 7
MAX_DIRS = 20000
MAX_SECONDS = 8.0
MAX_TEXT_SIZE = 5 * 1024 * 1024    # yaml/json больше этого — не конфигурация
_SKIP_DIRS = {"node_modules", "__pycache__", "venv", ".venv", "env", "site-packages", "dist-packages",
              "proc", "sys", "Trash", "snap"}
# файлы зависимостей: папка с ними — проект, Trivy найдёт в ней уязвимые библиотеки
_DEP_FILES = {"requirements.txt", "Pipfile.lock", "poetry.lock", "package-lock.json", "yarn.lock",
              "pnpm-lock.yaml", "go.mod", "Cargo.lock", "pom.xml", "build.gradle", "Gemfile.lock",
              "composer.lock", "packages.lock.json"}
_TEMPLATE_RE = re.compile(r"\{\{")
_NOT_DOCKERFILE = (".json", ".yaml", ".yml", ".md", ".txt", ".log", ".html")

# разделы, в том порядке, как их показывает веб
GROUPS = {
    "dockerfile": "Dockerfile",
    "Kubernetes": "Манифесты Kubernetes",
    "Helm": "Helm-чарты",
    "Terraform": "Terraform",
    "CloudFormation": "CloudFormation",
    "docker-compose": "docker-compose",
    "project": "Папки проектов (зависимости)",
    "git": "Git-репозитории на этой машине",
    "archive": "Архивы образов (docker save)",
    "sbom": "SBOM",
    "vm": "Образы дисков ВМ",
    "rootfs": "Распакованные ОС (корневая ФС)",
}


def user_home() -> Path:
    """Домашняя папка того, кто запустил cast web (и под sudo — его, а не root)."""
    name = os.environ.get("SUDO_USER")
    if os.geteuid() == 0 and name and name != "root":
        try:
            return Path(pwd.getpwnam(name).pw_dir)
        except KeyError:
            pass
    return Path.home()


def _group_of(path: Path) -> str | None:
    name = path.name
    if is_dockerfile_name(name) and name.lower().endswith(_NOT_DOCKERFILE):
        return None                        # dockerfile.cast.json — отчёт, а не Dockerfile
    if not (is_dockerfile_name(name) or name.lower().endswith(_FILE_SUFFIXES)):
        return None
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if name.lower().endswith((".yaml", ".yml", ".json")) and size > MAX_TEXT_SIZE:
        return None
    try:
        kind_sub = classify_file(path)
    except OSError:
        return None
    if kind_sub is None:
        return None
    kind, subtype = kind_sub
    return subtype if kind == "config" else kind


def scan_files(roots: list[Path], max_seconds: float = MAX_SECONDS) -> tuple[dict[str, list[str]], bool]:
    """Обход папок. Возвращает {раздел: [пути]} и признак, что обход прервали по лимиту."""
    found: dict[str, list[str]] = {key: [] for key in GROUPS}
    seen: set[str] = set()
    deadline = time.monotonic() + max_seconds
    dirs_left = MAX_DIRS
    cut = False
    stack = [(root.resolve(), 0) for root in roots if root.is_dir()]
    while stack:
        folder, depth = stack.pop()
        if str(folder) in seen:
            continue
        seen.add(str(folder))
        dirs_left -= 1
        if dirs_left < 0 or time.monotonic() > deadline:
            cut = True
            break
        try:
            entries = list(os.scandir(folder))
        except OSError:
            continue
        names = {e.name for e in entries}
        if "Chart.yaml" in names:                  # чарт — целиком, шаблоны внутри не отдельно
            found["Helm"].append(str(folder))
            continue
        if (folder / "etc" / "os-release").is_file() and folder != Path("/"):
            found["rootfs"].append(str(folder))
            continue
        if ".git" in names:
            found["git"].append(str(folder))
        if names & _DEP_FILES:
            found["project"].append(str(folder))
        for entry in entries:
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir():
                    if depth < MAX_DEPTH and not entry.name.startswith(".") and entry.name not in _SKIP_DIRS:
                        stack.append((Path(entry.path), depth + 1))
                    continue
            except OSError:
                continue
            group = _group_of(Path(entry.path))
            if group == "Kubernetes" and _is_template(Path(entry.path)):
                continue
            if group in found:
                found[group].append(entry.path)
    for paths in found.values():
        paths.sort(key=str.lower)
    return found, cut


def _is_template(path: Path) -> bool:
    """Шаблон Helm вне чарта ({{ .Values }}) — не манифест, Trivy его не разберёт."""
    try:
        with path.open(errors="replace") as fh:
            return bool(_TEMPLATE_RE.search(fh.read(64 * 1024)))
    except OSError:
        return False


def docker_items() -> dict:
    containers, images = [], []
    ps = run_docker("ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}")
    ok = ps is not None and ps.returncode == 0
    if ok:
        for line in ps.stdout.splitlines():
            name, image, status = (line.split("\t") + ["", ""])[:3]
            if name:
                containers.append({"name": name, "image": image, "status": status})
    im = run_docker("images", "--format", "{{.Repository}}:{{.Tag}}\t{{.Size}}")
    if im is not None and im.returncode == 0:
        for line in im.stdout.splitlines():
            ref, _, size = line.partition("\t")
            if ref and "<none>" not in ref:
                images.append({"ref": ref, "size": size})
    return {"docker": ok, "containers": containers, "images": images}


def kube_context() -> tuple[bool, str]:
    """Есть ли kubeconfig и какой в нём текущий контекст (строка current-context)."""
    paths = os.environ.get("KUBECONFIG", "").split(os.pathsep) if os.environ.get("KUBECONFIG") else []
    paths.append(str(user_home() / ".kube" / "config"))
    for raw in paths:
        path = Path(raw) if raw else None
        if path and path.is_file():
            try:
                match = re.search(r"(?m)^current-context:\s*['\"]?([^'\"\s]+)", path.read_text(errors="replace"))
            except OSError:
                match = None
            return True, match.group(1) if match else ""
    return False, ""


class Discovery:
    """Поиск в фоне: страница открывается сразу, список приходит, когда готов."""

    def __init__(self, roots_fn=None):
        self._roots_fn = roots_fn or (lambda: [user_home(), Path.cwd()])
        self._lock = threading.Lock()
        self._data: dict | None = None
        self._running = False

    def get(self, refresh: bool = False) -> dict:
        with self._lock:
            if (refresh or self._data is None) and not self._running:
                self._running = True
                threading.Thread(target=self._run, daemon=True, name="cast-web-discover").start()
            data = dict(self._data or {})
            data["running"] = self._running
            return data

    def _run(self) -> None:
        started = time.monotonic()
        try:
            roots = self._roots_fn()
            files, cut = scan_files(roots)
            kube, context = kube_context()
            data = {"files": files, "cut": cut, "roots": [str(r) for r in roots],
                    "docker": docker_items(), "kube": kube, "context": context,
                    "seconds": round(time.monotonic() - started, 1), "error": ""}
        except Exception as exc:   # поиск не должен ронять веб
            data = {"files": {}, "cut": False, "roots": [], "docker": {"docker": False, "containers": [],
                    "images": []}, "kube": False, "context": "", "seconds": 0, "error": str(exc)}
        with self._lock:
            self._data, self._running = data, False
