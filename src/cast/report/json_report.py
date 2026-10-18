"""
Машиночитаемый отчёт. Пригодится и для последующей обработки (например,
скрипт, который падает с ненулевым кодом, если есть critical), и для
будущей интеграции с БД/веб-интерфейсом — всё это будет просто читать
тот же самый JSON.
"""

from __future__ import annotations

import json
from pathlib import Path

from cast.pipeline import ScanResult


def to_dict(result: ScanResult) -> dict:
    target = result.target
    return {
        "image": result.image,
        "target": (
            {"kind": target.kind, "value": target.value,
             "container": target.container_name, "image": target.image_name}
            if target else None
        ),
        "summary": result.counts_by_severity,
        "status_summary": result.counts_by_status,
        "image_scan_failed": result.image_scan_failed,
        "engines": [
            {
                "name": r.name,
                "scope": r.scope,
                "status": r.status,
                "detail": r.detail,
                "findings": r.findings,
            }
            for r in result.runs
        ],
        "skipped_scanners": [
            {"scanner": name, "reason": reason} for name, reason in result.skipped_scanners
        ],
        "findings": [f.to_dict() for f in result.findings],
    }


def write(result: ScanResult, path: Path) -> None:
    path.write_text(
        json.dumps(to_dict(result), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
