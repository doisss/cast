"""Вывод ошибок конфигурации: место в файле, код один раз, таблица правил, кусок YAML."""

import json
from io import StringIO

import pytest
from rich.console import Console

from cast.pipeline import run_scan
from cast.report import console as console_report
from cast.report import json_report
from cast.report.fix_hint import yaml_hint
from cast.scanners.trivy import TrivyScanner
from cast.targets import Target

_LINES = [
    {"Number": 14, "Content": "        - name: web", "IsCause": True, "FirstCause": True},
    {"Number": 15, "Content": "          image: nginx:1.25", "IsCause": True},
    {"Number": 16, "Content": "          securityContext:", "IsCause": True},
    {"Number": 17, "Content": "            privileged: true", "IsCause": True, "LastCause": True},
]


def _mis(check_id, severity, resolution, start=14, end=17, lines=_LINES):
    return {"ID": check_id, "Title": f"title {check_id}", "Severity": severity, "Status": "FAIL",
            "Resolution": resolution,
            "CauseMetadata": {"StartLine": start, "EndLine": end, "Code": {"Lines": lines}}}


RAW = json.dumps({"Results": [{"Target": "deploy.yaml", "Class": "config", "Misconfigurations": [
    _mis("KSV-0017", "HIGH", "Change 'containers[].securityContext.privileged' to 'false'."),
    _mis("KSV-0012", "MEDIUM", "Set 'containers[].securityContext.runAsNonRoot' to true."),
    _mis("KSV-0104", "MEDIUM", "Specify seccomp either by annotation or by seccomp profile type"),
    _mis("KSV-0110", "LOW", "Set 'metadata.namespace' to a non-default namespace.", 3, 4,
         [{"Number": 3, "Content": "metadata:", "IsCause": True},
          {"Number": 4, "Content": "  name: web", "IsCause": True}]),
]}]})


def test_trivy_keeps_line_range_and_code():
    findings = TrivyScanner()._parse(RAW)
    assert findings[0].location == "deploy.yaml:14-17"
    assert findings[0].code_lines[3] == {"number": 17, "content": "            privileged: true",
                                         "is_cause": True}
    assert findings[3].location == "deploy.yaml:3-4"


def test_single_line_place_has_no_range():
    raw = json.dumps({"Results": [{"Target": "a.tf", "Misconfigurations": [
        _mis("AWS-0107", "HIGH", "Set a more restrictive CIDR range", 9, 9, [])]}]})
    assert TrivyScanner()._parse(raw)[0].location == "a.tf:9"


@pytest.mark.parametrize("check_id, text, expected", [
    ("KSV-0017", "Change 'containers[].securityContext.privileged' to 'false'.",
     ["containers:", "  - securityContext:", "      privileged: false"]),
    # опечатка самого Trivy: слово set внутри кавычек
    ("KSV-0001", "Set 'set containers[].securityContext.allowPrivilegeEscalation' to 'false'.",
     ["containers:", "  - securityContext:", "      allowPrivilegeEscalation: false"]),
    ("KSV-0020", "Set 'containers[].securityContext.runAsUser' to an integer > 10000.",
     ["containers:", "  - securityContext:", "      runAsUser: <ваше значение>"]),
    ("KSV-0110", "Set 'metadata.namespace' to a non-default namespace.",
     ["metadata:", "  namespace: <ваше значение>"]),
    # путь без кавычек, значение — до пути, drop в YAML — список
    ("KSV-0003", "Add 'ALL' to containers[].securityContext.capabilities.drop.",
     ["containers:", "  - securityContext:", "      capabilities:", "        drop:", "          - ALL"]),
])
def test_yaml_hint_from_trivy_path(check_id, text, expected):
    assert yaml_hint(check_id, text) == expected


@pytest.mark.parametrize("check_id, text", [
    ("KSV-0106", "Set 'spec.containers[*].securityContext.capabilities.drop' to 'ALL' and only add "
                 "'NET_BIND_SERVICE' to 'spec.containers[*].securityContext.capabilities.add'."),
    ("KSV-0104", "Specify seccomp either by annotation or by seccomp profile type"),
    ("AWS-0107", "Set a more restrictive CIDR range"),
    ("AWS-0001", "Set 'aws_s3_bucket.versioning' to 'true'."),   # не Kubernetes: YAML не рисуем
    ("KSV-0017", None),
])
def test_no_hint_when_path_is_not_clear(check_id, text):
    assert yaml_hint(check_id, text) == []


class _Fake(TrivyScanner):
    def is_available(self):
        return True

    def scan_target(self, target):
        return self._parse(RAW)


def _render(target):
    result = run_scan(target, scanners=[_Fake()])
    buf = StringIO()
    console_report.render(result, console=Console(file=buf, width=200, force_terminal=False))
    return result, buf.getvalue()


def test_config_findings_grouped_by_place_with_code_once():
    result, out = _render(Target("config", "deploy.yaml", subtype="Kubernetes"))
    assert out.count("privileged: true") == 1          # код места показан один раз
    assert "▌ deploy.yaml:14-17  3 шт." in out
    assert "▌ deploy.yaml:3-4  1 шт." in out
    assert out.index("deploy.yaml:14-17") < out.index("deploy.yaml:3-4")   # сначала место с HIGH
    assert "в файле:" not in out and "privileged: false" in out
    # текст Trivy остаётся как есть
    assert "Change 'containers[].securityContext.privileged' to 'false'." in out
    assert "Приоритет" not in out and "Источник" not in out
    assert json_report.to_dict(result)["findings"][0]["code_lines"]


def test_place_without_lines_is_whole_file():
    raw = json.dumps({"Results": [{"Target": "node", "Misconfigurations": [
        _mis("KCV-0001", "HIGH", "x", None, None, [])]}]})

    class NoCode(_Fake):
        def scan_target(self, target):
            return self._parse(raw)

    result = run_scan(Target("config", "deploy.yaml"), scanners=[NoCode()])
    buf = StringIO()
    console_report.render(result, console=Console(file=buf, width=140, force_terminal=False))
    assert "▌ node — весь файл" in buf.getvalue()
    assert "Trivy не прислал строки кода" not in buf.getvalue()


def test_other_targets_keep_the_table():
    class Folder(_Fake):
        pass

    result = run_scan(Target("fs", "."), scanners=[Folder()])
    buf = StringIO()
    console_report.render(result, console=Console(file=buf, width=200, force_terminal=False))
    out = buf.getvalue()
    assert "Что не так" not in out and "▌" not in out   # обычная таблица, не группы по месту
    assert "Приоритет" not in out and "Источник" not in out   # остались в JSON и HTML


def test_top_hides_rows_but_not_the_real_count_of_a_place():
    result = run_scan(Target("config", "deploy.yaml", subtype="Kubernetes"), scanners=[_Fake()])
    buf = StringIO()
    console_report.render(result, console=Console(file=buf, width=200, force_terminal=False), top=2)
    out = buf.getvalue()
    assert "▌ deploy.yaml:14-17  3 шт." in out and "(в таблице 2, остальные скрыты --top)" in out
    assert "deploy.yaml:3-4" not in out          # у этого места все строки скрыты
    assert "и ещё 2" in out
