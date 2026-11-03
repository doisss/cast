"""
Мелкие кроссплатформенные помощники.

Главное правило отсюда: никогда не хардкодить "trivy" или "trivy.exe" напрямую
в коде сканеров — всегда искать бинарник через shutil.which, который сам
разбирается с PATHEXT на Windows и с правами на выполнение на Unix.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path


class BinaryNotFoundError(RuntimeError):
    """Поднимается, когда внешний инструмент (trivy / docker-bench-security.sh)
    не найден в PATH. Сообщение сразу подсказывает, что делать."""

    def __init__(self, binary_name: str, install_hint: str):
        super().__init__(
            f"Не найден исполняемый файл '{binary_name}' в PATH.\n"
            f"Подсказка по установке: {install_hint}"
        )
        self.binary_name = binary_name


def find_binary(name: str, install_hint: str = "") -> str:
    """Находит бинарник по имени (без расширения — .exe добавится сам на Windows).
    Бросает понятную ошибку, если не найден, вместо невнятного FileNotFoundError
    из subprocess где-то в середине пайплайна."""
    path = shutil.which(name)
    if path is None:
        raise BinaryNotFoundError(name, install_hint)
    return path


def find_all_binaries(name: str) -> list[str]:
    """Все копии программы в PATH по порядку, без повторов: ссылка на тот же файл
    (~/.local/bin/trivy → ~/.sarbar/bin/trivy) считается одной копией. Первая —
    та, которую запустит find_binary."""
    found: list[str] = []
    seen: set[Path] = set()
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        path = shutil.which(name, path=folder) if folder else None
        if path is None:
            continue
        real = Path(path).resolve()
        if real not in seen:
            seen.add(real)
            found.append(path)
    return found


def ensure_dir(path: Path) -> Path:
    """Создаёт директорию (и родителей), если их ещё нет. Возвращает тот же путь —
    удобно для цепочек вида ensure_dir(out_dir) / "report.json"."""
    path.mkdir(parents=True, exist_ok=True)
    return path
