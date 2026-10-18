"""
HTML-отчёт — итоговый артефакт для приложения к ВКР и для демонстрации
на защите. Генерируется из тех же самых данных ScanResult, что и консоль
и JSON — меняется только "как нарисовать", сама логика анализа не дублируется.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from cast.pipeline import ScanResult
from cast.report.sections import build_sections, container_image_note

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def render_html(result: ScanResult) -> str:
    env = Environment(
        loader=FileSystemLoader(_TEMPLATES_DIR),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html.jinja")
    return template.render(
        result=result,
        sections=build_sections(result),
        status_counts=result.counts_by_status,
        note=container_image_note(result),
    )


def write(result: ScanResult, path: Path) -> None:
    path.write_text(render_html(result), encoding="utf-8")
