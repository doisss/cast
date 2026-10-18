from unittest.mock import patch

import pytest

from cast.models import Severity
from cast.scanners.base import ScannerError
from cast.scanners.trivy import TrivyScanner, _explain_failure
from tests.fixtures_trivy import SAMPLE_TRIVY_JSON


def test_parse_converts_trivy_json_to_findings():
    scanner = TrivyScanner()
    findings = scanner._parse(SAMPLE_TRIVY_JSON)

    assert len(findings) == 2

    critical = next(f for f in findings if f.check_id == "CVE-2024-3094")
    assert critical.package == "xz-utils"
    assert critical.severity == Severity.CRITICAL
    assert critical.source_tool == "trivy"
    assert critical.layer == "sha256:aaa111"
    assert critical.fixed_version == "5.4.5"

    medium = next(f for f in findings if f.check_id == "CVE-2023-9876")
    assert medium.severity == Severity.MEDIUM
    assert medium.package == "requests"


def test_parse_invalid_json_raises_scanner_error():
    scanner = TrivyScanner()
    with pytest.raises(ScannerError):
        scanner._parse("это не json")


def test_scan_image_wraps_subprocess_call():
    scanner = TrivyScanner()
    with patch("cast.scanners.trivy.find_binary", return_value="/usr/bin/trivy"):
        with patch.object(scanner, "_run_trivy", return_value=SAMPLE_TRIVY_JSON) as run_mock:
            findings = scanner.scan_image("myapp:1.4.2")

    run_mock.assert_called_once_with("/usr/bin/trivy", "myapp:1.4.2")
    assert len(findings) == 2


def test_parse_records_package_type():
    findings = TrivyScanner()._parse(SAMPLE_TRIVY_JSON)
    by_id = {f.check_id: f for f in findings}
    assert by_id["CVE-2024-3094"].pkg_type == "debian"
    assert by_id["CVE-2023-9876"].pkg_type == "python-pkg"


def test_docker_permission_error_is_explained_humanly():
    stderr = (
        "FATAL ... docker error: unable to inspect the image (x:1): permission denied "
        "while trying to connect to the docker API at unix:///var/run/docker.sock"
    )
    message = _explain_failure(1, stderr)
    assert "sudo" in message and "docker" in message
    assert len(message) < 250


def test_unknown_image_error_is_explained():
    assert "образ не найден" in _explain_failure(1, 'unable to find the specified image "x:1"')
