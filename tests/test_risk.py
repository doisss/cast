from sarbar.model import Finding
from sarbar.policy import load_profile
from sarbar.risk import apply_policy, score_findings


def test_score_grows_with_severity():
    low = [Finding("X", "t", "LOW", target="t", engine="e", category="vuln")]
    crit = [Finding("Y", "t", "CRITICAL", target="t", engine="e", category="vuln")]
    assert score_findings(crit).score > score_findings(low).score
    assert score_findings([]).score == 0


def test_policy_fail_on_critical():
    pol = load_profile("default")
    f = [Finding("CVE-1", "t", "CRITICAL", target="t", engine="e", category="vuln")]
    verdict, _ = apply_policy(f, score_findings(f), pol)
    assert verdict == "fail"


def test_policy_pass_clean():
    pol = load_profile("default")
    verdict, _ = apply_policy([], score_findings([]), pol)
    assert verdict == "pass"
