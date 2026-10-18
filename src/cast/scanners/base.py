"""
Контракт для любого сканера-плагина.

Если в будущем захочется добавить Grype или что угодно ещё —
достаточно реализовать этот интерфейс, и всё остальное (pipeline.py,
дедупликация, скоринг, отчёты) не придётся трогать вообще.
Это и есть "оркестрация": pipeline не знает деталей каждого инструмента,
он знает только, что у любого Scanner есть .name и .scan_image(image).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from contextlib import contextmanager

from cast.models import Finding


class ProgressUI:
    """Что движок может показать пользователю по ходу работы. По умолчанию — ничего;
    cli.py подставляет свою реализацию с индикатором."""

    def say(self, text: str) -> None:
        """Что делается прямо сейчас («анализирую пакеты образа alpine»)."""

    def progress(self, fraction: float, label: str = "") -> None:
        """Полоса загрузки: доля 0..1 и подпись («58 МиБ / 128 МиБ, 1,1 МиБ/с»)."""

    @contextmanager
    def live(self):
        """Отдать терминал самому инструменту (например, чтобы он нарисовал полосу загрузки)."""
        yield


class ScannerError(RuntimeError):
    """Инструмент запустился, но упал или вернул непонятный вывод.
    Pipeline ловит эту ошибку и продолжает работу с остальными сканерами —
    один упавший инструмент не должен ронять всё сканирование."""


class Scanner(ABC):
    name: str
    scope: str = "image"
    """Что именно проверяет движок:
    "image"       — конкретный образ (Trivy): результат зависит от имени образа;
    "environment" — окружение Docker на этой машине (Docker Bench): результат
                    одинаков для любого образа и к образу не относится."""
    targets: set[str] = {"image"}
    """Какие цели движок умеет проверять: image, container, dockerfile, fs, host."""
    default_targets: set[str] = {"image"}
    """Для каких целей он запускается сам, без флага -e."""
    description: str = ""
    """Одна строка для `cast engines`."""
    progress_hint: str = ""
    """Фраза для индикатора, пока движок не сообщил ничего точнее (через self.ui.say)."""
    ui: ProgressUI = ProgressUI()
    """Подставляется pipeline перед запуском; движок сообщает через него о фазах работы."""

    @abstractmethod
    def is_available(self) -> bool:
        """Установлен ли инструмент в системе. Вызывается до scan_image,
        чтобы можно было красиво предупредить пользователя и пропустить шаг,
        а не упасть посреди работы."""

    def scan_image(self, image: str) -> list[Finding]:
        """Запускает внешний инструмент над образом и возвращает список находок
        уже в единой схеме (см. models.Finding). Движки, которые умеют и другие
        цели, переопределяют scan_target."""
        raise ScannerError(f"{self.name} не умеет проверять образы")

    def scan_target(self, target) -> list[Finding]:
        """Проверка цели произвольного типа (см. cast.targets.Target).
        По умолчанию движок умеет только образы — это старый интерфейс scan_image."""
        if target.kind == "image":
            return self.scan_image(target.value)
        raise ScannerError(f"{self.name} не умеет проверять цель типа «{target.kind}»")

    def version(self) -> str | None:
        """Версия установленного инструмента (для cast engines)."""
        return None

    def path(self) -> str | None:
        """Где лежит инструмент (для cast engines)."""
        return None
