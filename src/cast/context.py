"""
Контекст приложения — то, что делает приоритизацию "умной", а не просто
копией CVSS-балла из базы.

MVP-версия: смотрим requirements.txt и считаем, что любой пакет оттуда
реально используется приложением. Это не идеально (requirements.txt может
содержать неиспользуемые зависимости), но это осязаемое и честное начало —
в выводах ВКР можно явно написать, как это можно улучшить (например,
статическим анализом реальных import-ов в коде через ast).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# requests==2.28.0 / requests>=2.28 / requests[security] ; версию не парсим —
# для контекста важен только факт "пакет используется"
_PKG_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)")


def normalize_name(name: str) -> str:
    """Имена Python-пакетов сравниваются по PEP 503: регистр не важен, а
    '-', '_' и '.' равнозначны (typing_extensions == typing-extensions)."""
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


@dataclass
class ScanContext:
    """Передаётся в scoring.py, чтобы приоритизация могла учитывать
    реальный контекст приложения, а не работать вслепую."""

    used_packages: set[str] = field(default_factory=set)

    def is_used(self, package_name: str | None) -> bool:
        if not package_name:
            return False
        return normalize_name(package_name) in {normalize_name(p) for p in self.used_packages}

    @classmethod
    def empty(cls) -> "ScanContext":
        return cls(used_packages=set())

    @classmethod
    def from_requirements_file(cls, path: Path) -> "ScanContext":
        packages: set[str] = set()
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.split("#", 1)[0].strip()
            # пропускаем пустые строки, опции (-r, -e, --hash ...) и ссылки (git+https://...)
            if not line or line.startswith("-") or "://" in line:
                continue
            match = _PKG_NAME_RE.match(line)
            if match:
                packages.add(normalize_name(match.group(1)))
        return cls(used_packages=packages)
