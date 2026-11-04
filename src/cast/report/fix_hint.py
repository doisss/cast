"""
Подсказка к «Как исправить» у правил Kubernetes: путь из текста Trivy в виде куска YAML.

Trivy пишет совет обычной фразой, например
    Change 'containers[].securityContext.privileged' to 'false'.
Отдельного поля с путём в JSON нет, поэтому путь достаём из самой фразы и
рисуем, как это выглядит в файле:
    containers:
      - securityContext:
          privileged: false
Текст Trivy при этом показывается как есть. Путь бывает и без кавычек:
    Add 'ALL' to containers[].securityContext.capabilities.drop.
Если путей в тексте несколько или нет совсем, подсказки нет (ничего не
придумываем). У правил Terraform и CloudFormation путей в тексте нет, поэтому
подсказка только для KSV.

Чтобы было видно, куда это вписать, подсказка привязывается к файлу (hint_lines):
- контейнер берётся из Message Trivy («Container 'web' of …») и пишется
  строкой «- name: web», как в файле, а не прочерком перед первым ключом;
- по строкам кода, которые прислал Trivy, отмечается, какие строки уже есть,
  какие дописать и где поменять значение («← сейчас true»).
Если Trivy строк не прислал, отметок нет: угадывать не из чего.
"""

from __future__ import annotations

import re

_PATH = re.compile(r"'(?:set )?([^'\s]*\.[^'\s]*)'")
# путь без кавычек: containers[].securityContext.capabilities.drop (точка в конце — конец фразы)
_BARE_PATH = re.compile(r"(?<![\w'.])([A-Za-z]+(?:\[\*?\])?(?:\.[A-Za-z]+(?:\[\*?\])?)+)(?![\w'])")
_VALUE = re.compile(r"\bto '?([A-Za-z_]+)'?\.?\s*$")
_ADD_VALUE = re.compile(r"^Add '([A-Za-z_]+)' to ")      # «Add 'ALL' to …drop» — значение до пути
# поля Kubernetes, которые в YAML — список: значение пишется пунктом «- ALL»
_LIST_FIELDS = {"drop", "add"}
UNKNOWN_VALUE = "<ваше значение>"
_CONTAINER = re.compile(r"\bcontainer ['\"]([^'\"]+)['\"]", re.I)

# состояние строки подсказки относительно файла
EXISTS, ADD, CHANGE, PLAIN = "exists", "add", "change", "plain"


def _path_and_value(remediation: str) -> tuple[str, str] | None:
    paths = _PATH.findall(remediation)
    if not paths:
        paths = _BARE_PATH.findall(remediation)
    if len(paths) != 1:
        return None
    path = paths[0]                        # (?:set ) в _PATH — опечатка Trivy: "Set 'set containers[]..."
    path = re.sub(r"^spec\.", "", path)    # путь Trivy от описания пода; spec. только путает
    if not re.fullmatch(r"[A-Za-z]+(\[\*?\])?(\.[A-Za-z]+(\[\*?\])?)+", path):
        return None
    m = _ADD_VALUE.search(remediation) or _VALUE.search(remediation)
    # «to an integer > 10000», «to a non-default namespace» — это не значение, а условие
    value = m.group(1) if m and m.group(1) not in ("a", "an") else UNKNOWN_VALUE
    return path, value


def _nodes(path: str, value: str, container: str | None) -> list[dict]:
    """Путь как цепочка строк YAML: ключи, пункт списка «- name: web» и значение."""
    nodes: list[dict] = []
    parts = path.split(".")
    for i, part in enumerate(parts):
        name = part.replace("[*]", "").replace("[]", "")
        last = i == len(parts) - 1
        if last and name in _LIST_FIELDS:
            nodes.append({"kind": "key", "key": name})
            nodes.append({"kind": "item", "value": value})
        elif last:
            nodes.append({"kind": "leaf", "key": name, "value": value})
        else:
            nodes.append({"kind": "key", "key": name})
            if part.endswith("]"):
                nodes.append({"kind": "entry", "name": container})
    return nodes


def _render(nodes: list[dict]) -> list[str]:
    lines: list[str] = []
    indent, dash = 0, False
    for node in nodes:
        prefix = " " * indent + ("- " if dash else "")
        if dash:
            indent += 2
            dash = False
        kind = node["kind"]
        if kind == "entry":
            if node["name"]:
                lines.append(f"{prefix}- name: {node['name']}")
                indent += 2
            else:
                dash = True          # имени нет — прочерк перед следующим ключом, как раньше
            continue
        if kind == "item":
            lines.append(f"{prefix}- {node['value']}")
        elif kind == "leaf":
            lines.append(f"{prefix}{node['key']}: {node['value']}")
        else:
            lines.append(f"{prefix}{node['key']}:")
            indent += 2
            continue
    return lines


def _find(node: dict, content: str) -> re.Match | None:
    kind = node["kind"]
    if kind == "entry":
        return re.match(rf"\s*-?\s*name\s*:\s*['\"]?{re.escape(node['name'])}['\"]?\s*$", content)
    if kind == "item":
        return re.match(rf"\s*-\s*['\"]?{re.escape(node['value'])}['\"]?\s*$", content)
    return re.match(rf"\s*(?:-\s+)?{re.escape(node['key'])}\s*:\s*(.*?)\s*$", content)


def _states(nodes: list[dict], code_lines: list[dict]) -> list[tuple[str, str | None]]:
    """Для каждой строки: есть ли она в строках кода Trivy (по порядку сверху вниз).
    Всё, что выше самой глубокой найденной строки, тоже есть: «- name: web» без
    «containers:» над ним не бывает."""
    contents = [line["content"] for line in code_lines]
    found: dict[int, re.Match] = {}
    pos = -1
    for i, node in enumerate(nodes):
        if node["kind"] == "entry" and not node["name"]:
            continue
        for j in range(pos + 1, len(contents)):
            m = _find(node, contents[j])
            if m:
                found[i], pos = m, j
                break
    deepest = max(found, default=-1)
    states: list[tuple[str, str | None]] = []
    for i, node in enumerate(nodes):
        if node["kind"] == "entry" and not node["name"]:
            continue
        if node["kind"] == "leaf" and i in found:
            old = found[i].group(1).strip("'\"")
            states.append((EXISTS, None) if old == node["value"] else (CHANGE, old))
        elif i <= deepest:
            states.append((EXISTS, None))
        else:
            states.append((ADD, None))
    return states


def hint_lines(check_id: str, remediation: str | None, message: str | None = None,
               code_lines: list[dict] | None = None) -> list[tuple[str, str, str | None]]:
    """Строки подсказки: (текст, состояние, прежнее значение для CHANGE).
    Пустой список, если путь из текста однозначно не достаётся."""
    if not remediation or not check_id.upper().startswith("KSV"):
        return []
    found = _path_and_value(remediation)
    if not found:
        return []
    m = _CONTAINER.search(message or "")
    nodes = _nodes(*found, m.group(1) if m else None)
    texts = _render(nodes)
    if not code_lines:
        return [(t, PLAIN, None) for t in texts]
    return [(t, state, old) for t, (state, old) in zip(texts, _states(nodes, code_lines))]


def yaml_hint(check_id: str, remediation: str | None, message: str | None = None) -> list[str]:
    """Строки куска YAML или пустой список, если путь из текста однозначно не достаётся."""
    return [text for text, _, _ in hint_lines(check_id, remediation, message)]
