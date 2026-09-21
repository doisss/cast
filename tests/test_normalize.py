from sarbar.model import Finding
from sarbar.normalize import dedup, normalize_all


def _f(cid="CVE-1", pkg="p", ver="1", eng="trivy", sev="HIGH"):
    return Finding(cid, "t", sev, target="t", package=pkg,
                   installed_version=ver, engine=eng, category="vuln")


def test_dedup_merges_engines():
    a, b = _f(eng="trivy"), _f(eng="grype")
    out = dedup([a, b])
    assert len(out) == 1
    assert sorted(out[0].engines_seen) == ["grype", "trivy"]


def test_dedup_keeps_distinct():
    out = dedup([_f(cid="CVE-1"), _f(cid="CVE-2")])
    assert len(out) == 2


def test_sort_critical_first():
    out = normalize_all([_f(cid="L", sev="LOW"), _f(cid="C", sev="CRITICAL")])
    assert out[0].severity == "CRITICAL"
