"""Report formats: HTML escaping, SARIF schema conformance, JSON completeness."""
from __future__ import annotations

import json

from sarbar.model import Finding
from sarbar.report import (render_console, render_console_rich, render_html,
                           render_json, render_sarif, to_dict)


def _res(findings=(), **kw):
    base = {
        "target": "app:latest", "target_kind": "image", "image_ref": None,
        "profile": "default",
        "plan": {"engines": ["trivy"], "why": "auto mode", "profile": "default",
                 "target": "x", "kind": "image", "offline": False},
        "scanners_used": ["trivy"], "scanner_status": {"trivy": "ok"},
        "degraded": False, "offline": False,
        "diagnostics": [], "warnings": [],
        "findings": list(findings),
        "risk": {"score": 42.0, "level": "medium", "counts": {"HIGH": 1},
                 "max_cvss": 7.5, "reasons": ["HIGH:1x -> +10.0"]},
        "verdict": "fail", "policy_reasons": ["high findings 1 >= threshold 1"],
    }
    base.update(kw)
    return base


VULN = Finding("CVE-2024-1111", "Prototype pollution", "CRITICAL", target="app",
               package="lodash", installed_version="4.17.20",
               fixed_version="4.17.21", cvss=9.1, engine="trivy",
               category="vuln", references=["https://nvd"],
               locations=["app/package-lock.json"])


# ---------------------------------------------------------------- json

def test_json_is_parseable_and_complete():
    d = json.loads(render_json(_res([VULN])))
    assert d["tool"] == "sarbar"
    assert d["version"]
    assert d["verdict"] == "fail"
    assert d["findings"][0]["check_id"] == "CVE-2024-1111"
    assert d["findings"][0]["fingerprint"]
    assert d["findings"][0]["occurrences"] == 1


def test_json_uses_scanner_terms_not_engine_terms():
    """0.3.0 renamed engines -> scanners throughout the output."""
    d = json.loads(render_json(_res([VULN])))
    assert "scanners_used" in d and "scanner_status" in d
    assert "engines_used" not in d
    assert "engine_status" not in d


def test_json_includes_diagnostics_and_degraded_flag():
    d = json.loads(render_json(_res(degraded=True, diagnostics=["x failed"])))
    assert d["degraded"] is True
    assert d["diagnostics"] == ["x failed"]
    assert "our_checks_run" not in d, "own checks were removed in 0.4.0"


def test_to_dict_handles_missing_optional_keys():
    minimal = {"target": "x", "target_kind": "fs", "profile": "default",
               "plan": {}, "scanners_used": [], "risk": _res()["risk"],
               "verdict": "pass", "policy_reasons": [], "findings": []}
    d = to_dict(minimal)
    assert d["degraded"] is False and d["image_ref"] is None


# ---------------------------------------------------------------- sarif

def test_sarif_is_version_2_1_0():
    d = json.loads(render_sarif(_res([VULN])))
    assert d["version"] == "2.1.0"
    assert d["runs"][0]["tool"]["driver"]["name"] == "sarbar"
    assert d["runs"][0]["tool"]["driver"]["informationUri"]


def test_sarif_rules_are_deduplicated():
    """Regression: one rule per finding produced `uniqueItems` violations."""
    a = Finding("CVE-2024-1111", "t", "HIGH", target="x", package="lodash",
                installed_version="4.17.20", engine="trivy", category="vuln")
    b = Finding("CVE-2024-1111", "t", "HIGH", target="x", package="h2",
                installed_version="2.0.0", engine="grype", category="vuln")
    d = json.loads(render_sarif(_res([a, b])))
    rules = d["runs"][0]["tool"]["driver"]["rules"]
    results = d["runs"][0]["results"]
    assert len(rules) == 1
    assert len(results) == 2
    assert {r["ruleIndex"] for r in results} == {0}


def test_sarif_results_reference_rule_index():
    d = json.loads(render_sarif(_res([VULN])))
    r = d["runs"][0]["results"][0]
    assert r["ruleId"] == "CVE-2024-1111"
    assert r["ruleIndex"] == 0
    assert r["level"] == "error"
    assert r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] \
        == "app/package-lock.json"


def test_sarif_level_mapping():
    levels = {}
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"):
        f = Finding("C-" + sev, "t", sev, target="x", engine="e", category="vuln")
        levels[sev] = json.loads(render_sarif(_res([f])))["runs"][0]["results"][0]["level"]
    assert levels["CRITICAL"] == "error"
    assert levels["HIGH"] == "error"
    assert levels["MEDIUM"] == "warning"
    assert set(levels.values()) <= {"error", "warning", "note"}


def test_sarif_rules_have_required_shape():
    rule = json.loads(render_sarif(_res([VULN])))["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["id"] and rule["name"]
    assert rule["shortDescription"]["text"]
    assert rule["properties"]["severity"] == "CRITICAL"


def test_sarif_handles_no_findings():
    d = json.loads(render_sarif(_res([])))
    assert d["runs"][0]["results"] == []
    assert d["runs"][0]["tool"]["driver"]["rules"] == []


# ---------------------------------------------------------------- html

def test_html_escapes_every_external_field():
    """I-7: package names and scanner titles come from outside sarbar."""
    hostile = Finding(
        "CVE-1", "<img src=x onerror=alert(1)>", "HIGH",
        target="<b>t</b>", package="<script>alert(2)</script>",
        installed_version="1.0'\"", engine="trivy", category="vuln",
        description="<svg onload=alert(3)>",
    )
    out = render_html(_res([hostile], target="<script>alert(4)</script>"))
    for live in ("<script>", "<img ", "<svg ", "</script>"):
        assert live not in out, live
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in out
    assert "&lt;img src=x onerror=alert(1)&gt;" in out
    assert "onload=alert(3)" not in out


def test_html_escapes_target_in_title_tag():
    out = render_html(_res([], target="<script>alert(1)</script>"))
    assert "<title>sarbar report — <script>" not in out
    assert "&lt;script&gt;" in out


def test_html_escapes_diagnostics_and_warnings():
    out = render_html(_res([], diagnostics=["<b>boom</b>"], warnings=["<i>warn</i>"]))
    assert "<b>boom</b>" not in out and "<i>warn</i>" not in out


def test_html_shows_degraded_banner():
    out = render_html(_res([], degraded=True,
                           diagnostics=["trivy not used [failed]: boom"]))
    assert "DEGRADED RUN" in out
    assert "Diagnostics" in out


def test_html_renders_empty_findings():
    assert "No findings." in render_html(_res([]))


def test_html_is_well_formed_document():
    out = render_html(_res([VULN]))
    assert out.strip().startswith("<!doctype html>")
    assert out.strip().endswith("</html>")
    assert out.count("<table") == out.count("</table>")
    assert out.count("<tbody>") == out.count("</tbody>")


def test_html_shows_occurrence_count():
    many = Finding("CAST-SECRET-001", "Possible AWS access key", "HIGH",
                   target="app", engine="sarbar-checks", category="secret",
                   locations=["a.py", "b.py", "c.py"])
    assert "x3" in render_html(_res([many]))


def test_html_escapes_ampersands_in_fixed_version():
    f = Finding("C", "t", "HIGH", target="x", engine="e", category="vuln",
                fixed_version="1.0&2.0")
    assert "1.0&amp;2.0" in render_html(_res([f]))


def test_html_shows_scanner_column_heading():
    out = render_html(_res([VULN]))
    assert "Scanners" in out and "Engines" not in out


# ---------------------------------------------------------------- console

def test_console_plain_lists_findings_and_reasons():
    out = render_console(_res([VULN]), show_explain=True)
    assert "CVE-2024-1111" in out
    assert "lodash:4.17.20" in out
    assert "risk reasons:" in out and "policy:" in out
    assert "auto mode" in out


def test_console_uses_scanner_wording():
    out = render_console(_res([VULN]))
    assert "scanners: trivy" in out
    assert "engines:" not in out


def test_console_plain_shows_diagnostics():
    out = render_console(_res([], degraded=True,
                              diagnostics=["trivy not used [failed]"]))
    assert "diagnostic: trivy not used [failed]" in out
    assert "DEGRADED" in out


def test_console_plain_shows_warnings():
    out = render_console(_res([], warnings=["falco is not a real scan"]))
    assert "warning: falco is not a real scan" in out


def test_console_plain_empty():
    assert "No findings." in render_console(_res([]))


def test_console_rich_falls_back_when_rich_missing(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name.startswith("rich"):
            raise ImportError("blocked for test")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    out = render_console_rich(_res([VULN]))
    assert "CVE-2024-1111" in out


def test_console_rich_returns_empty_string_when_it_prints(capsys):
    out = render_console_rich(_res([VULN]))
    assert out == ""
    assert "CVE-2024-1111" in capsys.readouterr().out