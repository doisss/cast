"""
Подсказка к «Как исправить» у правил Kubernetes: путь из текста Trivy в виде куска YAML.

Trivy пишет совет обычной фразой, например
    Change 'containers[].securityContext.privileged' to 'false'.
Отдельного поля с путём в JSON нет, поэтому путь достаём из самой фразы и
рисуем, как это выглядит в файле:
    containers:
      - securityContext:
          privileged: false
Текст Trivy при этом показывается как есть. Если путь в тексте не один, не в
кавычках или его нет совсем, подсказки нет (ничего не придумываем). У правил
Terraform и CloudFormation путей в тексте нет, поэтому подсказка только для KSV.
"""

from __future__ import annotations

import re

_PATH = re.compile(r"'(?:set )?([^'\s]*\.[^'\s]*)'")
_VALUE = re.compile(r"\bto '?([A-Za-z_]+)'?\.?\s*$")
UNKNOWN_VALUE = "<значение>"


def _path_and_value(remediation: str) -> tuple[str, str] | None:
    paths = _PATH.findall(remediation)
    if len(paths) != 1:
        return None
    path = paths[0]                        # (?:set ) в _PATH — опечатка Trivy: "Set 'set containers[]..."
    path = re.sub(r"^spec\.", "", path)    # путь Trivy от описания пода; spec. только путает
    if not re.fullmatch(r"[A-Za-z]+(\[\*?\])?(\.[A-Za-z]+(\[\*?\])?)+", path):
        return None
    m = _VALUE.search(remediation)
    # «to an integer > 10000», «to a non-default namespace» — это не значение, а условие
    value = m.group(1) if m and m.group(1) not in ("a", "an") else UNKNOWN_VALUE
    return path, value


def _yaml(path: str, value: str) -> list[str]:
    lines: list[str] = []
    indent, list_item = 0, False
    parts = path.split(".")
    for i, part in enumerate(parts):
        name = part.replace("[*]", "").replace("[]", "")
        prefix = " " * indent + ("- " if list_item else "")
        if list_item:
            indent += 2
            list_item = False
        if i == len(parts) - 1:
            lines.append(f"{prefix}{name}: {value}")
        else:
            lines.append(f"{prefix}{name}:")
            indent += 2
            list_item = part.endswith("]")
    return lines


def yaml_hint(check_id: str, remediation: str | None) -> list[str]:
    """Строки куска YAML или пустой список, если путь из текста однозначно не достаётся."""
    if not remediation or not check_id.upper().startswith("KSV"):
        return []
    found = _path_and_value(remediation)
    return _yaml(*found) if found else []
