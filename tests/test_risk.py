"""Risk score methodology and policy thresholds."""
from __future__ import annotations

import pytest

from sarbar.model import Finding
from sarbar.policy import load_profile
from sarbar.risk import WEIGHTS, apply_policy, level_of, score_findings


def f(sev, cat="vuln", cvss=0.0, pkg="p", ver="1"):
    return Finding("CVE-X", "t", sev, target="t", engine="e", category=cat,
                   cvss=cvss, package=pkg, installed_version=ver)


# ---------------------------------------------------------------- score

def test_empty_is_zero():
    r = score_findings([])
    assert r.score == 0.0 and r.level == "ok"


def test_severity_ordering():
    crit = score_findings([f("CRITICAL")])
    high = score_findings([f("HIGH")])
    med = score_findings([f("MEDIUM")])
    low = score_findings([f("LOW")])
    assert crit.score > high.score > med.score > low.score > 0


def test_single_critical_is_25():
    assert score_findings([f("CRITICAL")]).score == 25.0
    assert score_findings([f("HIGH")]).score == 10.0
    assert score_findings([f("MEDIUM")]).score == 3.0
    assert score_findings([f("LOW")]).score == 1.0


def test_info_and_unknown_carry_no_weight():
    assert score_findings([f("INFO")]).score == 0.0
    assert score_findings([f("UNKNOWN")]).score == 0.0


def test_diminishing_returns():
    """The n-th finding counts w/sqrt(n): 2 criticals < 2x25."""
    one = score_findings([f("CRITICAL")] * 1).score
    two = score_findings([f("CRITICAL")] * 2).score
    assert one == 25.0
    assert 25.0 < two < 50.0
    assert two == pytest.approx(25.0 + 25.0 / 2 ** 0.5, abs=0.05)


def test_class_cap_saturates():
    assert score_findings([f("CRITICAL")] * 5).score == 60.0
    assert score_findings([f("CRITICAL")] * 500).score == 60.0
    assert score_findings([f("HIGH")] * 10).score == 40.0


def test_cap_is_announced_in_reasons():
    r = score_findings([f("CRITICAL")] * 9)
    assert any("class cap" in reason for reason in r.reasons)


def test_cvss_lift():
    assert score_findings([f("LOW", cvss=10.0)]).score == pytest.approx(1.0 + 15.0)
    assert score_findings([f("LOW", cvss=4.0)]).score == pytest.approx(1.0 + 6.0)


def test_cvss_lift_uses_the_maximum():
    fs = [f("LOW", cvss=2.0), f("LOW", cvss=9.0), f("LOW", cvss=1.0)]
    assert score_findings(fs).max_cvss == 9.0


def test_category_penalties():
    assert score_findings([f("LOW", cat="secret")]).score == pytest.approx(6.0)
    assert score_findings([f("LOW", cat="runtime")]).score == pytest.approx(6.0)


def test_score_is_capped_at_100():
    many = [f("CRITICAL") for _ in range(50)] + [f("HIGH") for _ in range(50)]
    assert score_findings(many).score == 100.0


def test_every_score_is_explained():
    r = score_findings([f("CRITICAL"), f("HIGH"), f("LOW", cat="secret", cvss=7.7)])
    joined = "; ".join(r.reasons)
    assert "CRITICAL" in joined and "HIGH" in joined
    assert "max CVSS" in joined and "leaked secret" in joined


@pytest.mark.parametrize("score,level", [
    (100, "critical"), (80, "critical"), (79.9, "high"),
    (60, "high"), (59.9, "medium"), (30, "medium"),
    (29.9, "low"), (5, "low"), (4.9, "ok"), (0, "ok"),
])
def test_levels(score, level):
    assert level_of(score) == level


def test_weights_cover_every_severity():
    from sarbar.model import SEVERITIES
    assert set(WEIGHTS) == set(SEVERITIES)


# ---------------------------------------------------------------- policy

def test_default_fails_on_one_critical():
    verdict, reasons = apply_policy([f("CRITICAL")], score_findings([f("CRITICAL")]),
                                    load_profile("default"))
    assert verdict == "fail"
    assert any("critical findings" in r for r in reasons)


def test_clean_target_passes():
    verdict, reasons = apply_policy([], score_findings([]), load_profile("default"))
    assert verdict == "pass"
    assert "within policy thresholds" in reasons


def test_default_ignores_high():
    fs = [f("HIGH")] * 10
    verdict, _ = apply_policy(fs, score_findings(fs), load_profile("default"))
    assert verdict == "pass"


def test_ci_fails_on_five_high():
    fs = [f("HIGH")] * 5
    verdict, _ = apply_policy(fs, score_findings(fs), load_profile("ci"))
    assert verdict == "fail"


def test_secret_threshold_fails_the_run():
    """Regression: two HIGH secret findings used to pass with exit 0."""
    fs = [f("HIGH", cat="secret"), f("HIGH", cat="secret")]
    verdict, reasons = apply_policy(fs, score_findings(fs), load_profile("default"))
    assert verdict == "fail"
    assert any("leaked secret" in r for r in reasons)


def test_secret_threshold_can_be_disabled():
    fs = [f("HIGH", cat="secret")]
    pol = load_profile("report")
    verdict, _ = apply_policy(fs, score_findings(fs), pol)
    assert verdict == "pass"


def test_score_threshold():
    # 2 criticals (42.7) + a low (1.0) + cvss lift (13.5) crosses the strict gate of 40
    fs = [f("CRITICAL"), f("CRITICAL"), f("LOW", cvss=9.0)]
    risk = score_findings(fs)
    assert risk.score > 40.0, risk.reasons
    verdict, reasons = apply_policy(fs, risk, load_profile("strict"))
    assert verdict == "fail"
    assert any("risk score" in r for r in reasons)


def test_score_threshold_below_gate_passes():
    fs = [f("LOW")]
    verdict, _ = apply_policy(fs, score_findings(fs), load_profile("strict"))
    assert verdict == "pass"


def test_none_thresholds_fall_back_to_defaults():
    """A policy object missing attributes must not crash or silently pass."""
    class Bare:
        pass
    verdict, reasons = apply_policy([f("CRITICAL")], score_findings([f("CRITICAL")]), Bare())
    assert verdict == "fail"
    assert any("critical findings" in r for r in reasons)


def test_negative_one_means_never():
    class Never:
        fail_on_critical = -1
        fail_on_high = -1
        fail_on_secret = -1
        fail_score = -1.0
    fs = [f("CRITICAL"), f("HIGH"), f("HIGH", cat="secret")]
    verdict, _ = apply_policy(fs, score_findings(fs), Never())
    assert verdict == "pass"