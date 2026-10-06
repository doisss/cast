"""Dedup and correlation."""
from __future__ import annotations

from sarbar.model import Finding
from sarbar.normalize import correlate, dedup, normalize_all


def v(check_id="CVE-1", pkg="p", ver="1", eng="trivy", sev="HIGH", cat="vuln",
      cvss=0.0, target="t"):
    return Finding(check_id, "title", sev, target=target, package=pkg,
                   installed_version=ver, engine=eng, category=cat, cvss=cvss)


def r(check_id, sev="HIGH", pkg="", cat="runtime", title="rt", target="c",
      description="", version=""):
    return Finding(check_id, title, sev, target=target, package=pkg, category=cat,
                   description=description, installed_version=version)


# ---------------------------------------------------------------- dedup

def test_same_finding_from_two_engines_merges():
    a, b = v(eng="trivy"), v(eng="grype")
    out = dedup([a, b])
    assert len(out) == 1
    assert sorted(out[0].engines_seen) == ["grype", "trivy"]


def test_distinct_check_ids_stay_separate():
    assert len(dedup([v(check_id="CVE-1"), v(check_id="CVE-2")])) == 2


def test_distinct_packages_stay_separate():
    assert len(dedup([v(pkg="lodash"), v(pkg="h2")])) == 2


def test_distinct_versions_stay_separate():
    assert len(dedup([v(ver="1.0"), v(ver="2.0")])) == 2


def test_distinct_targets_do_not_merge():
    """Regression risk: target is part of the fingerprint."""
    assert len(dedup([v(target="a"), v(target="b")])) == 2


def test_worst_severity_wins():
    out = dedup([v(sev="LOW"), v(sev="CRITICAL")])
    assert out[0].severity == "CRITICAL"


def test_highest_cvss_wins():
    out = dedup([v(cvss=5.0), v(cvss=9.9)])
    assert out[0].cvss == 9.9


def test_fixed_version_is_backfilled():
    a = v()
    a.fixed_version = ""
    b = v()
    b.fixed_version = "1.2.3"
    assert dedup([a, b])[0].fixed_version == "1.2.3"


def test_references_are_merged_and_deduped():
    a, b = v(), v()
    a.references = ["u1", "u2"]
    b.references = ["u2", "u3"]
    assert dedup([a, b])[0].references == ["u1", "u2", "u3"]


def test_locations_are_merged():
    a, b = v(), v()
    a.locations = ["f1"]
    b.locations = ["f2"]
    merged = dedup([a, b])[0]
    assert sorted(merged.locurrences) if False else merged.occurrences == 2
    assert sorted(merged.locations) == ["f1", "f2"]


def test_description_is_backfilled():
    a, b = v(), v()
    a.description = ""
    b.description = "d"
    assert dedup([a, b])[0].description == "d"


def test_result_is_sorted_worst_first():
    out = normalize_all([v(check_id="L", sev="LOW"), v(check_id="C", sev="CRITICAL"),
                         v(check_id="H", sev="HIGH")])
    assert [f.severity for f in out] == ["CRITICAL", "HIGH", "LOW"]


def test_rows_without_check_id_are_dropped():
    bad = Finding("", "t", "HIGH", target="x", engine="e", category="vuln")
    assert normalize_all([bad]) == []


def test_fingerprint_is_stable():
    assert v().fingerprint == v().fingerprint
    assert v().fingerprint != v(ver="2").fingerprint


# ---------------------------------------------------------------- correlate

def test_runtime_matching_package_and_version():
    fs = [v(pkg="openssl", ver="3.1.4"),
          r("FALCO-x", pkg="openssl")]
    fs[1].installed_version = "3.1.4"
    out = correlate(fs)
    assert "same package+version" in out[1].description


def test_runtime_matching_package_only():
    fs = [v(pkg="openssl", ver="3.1.4"), r("FALCO-x", pkg="openssl")]
    out = correlate(fs)
    assert "package also vulnerable" in out[1].description


def test_runtime_finding_without_package_matches_on_text():
    """Falco alerts carry no package field; correlation must still work."""
    fs = [v(pkg="openssl"),
          r("FALCO-Write-below", pkg="",
            title="Write below /usr/lib/openssl/conf", description="alert")]
    out = correlate(fs)
    assert "mentions vulnerable package openssl" in out[1].description


def test_runtime_finding_without_match_is_untouched():
    fs = [v(pkg="openssl"),
          r("FALCO-x", pkg="", title="unrelated event", description="alert")]
    assert correlate(fs)[1].description == "alert"


def test_correlation_is_a_noop_without_vulns():
    fs = [r("FALCO-x", pkg="openssl", description="alert")]
    assert correlate(fs)[0].description == "alert"


def test_correlation_never_adds_or_removes_findings():
    fs = [v(pkg="openssl"), r("FALCO-x", pkg="openssl"), v(check_id="CVE-2", pkg="zlib")]
    assert len(correlate(fs)) == 3