"""Упрощённый, но структурно верный пример JSON-вывода `trivy image --format json`."""

SAMPLE_TRIVY_JSON = """
{
  "SchemaVersion": 2,
  "ArtifactName": "myapp:1.4.2",
  "Results": [
    {
      "Target": "myapp:1.4.2 (debian 12.4)",
      "Class": "os-pkgs",
      "Type": "debian",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-3094",
          "PkgName": "xz-utils",
          "InstalledVersion": "5.4.1",
          "FixedVersion": "5.4.5",
          "Severity": "CRITICAL",
          "Title": "xz-utils: backdoor in liblzma",
          "Description": "Malicious code was discovered in the upstream tarballs.",
          "Layer": {"Digest": "sha256:aaa111"}
        }
      ]
    },
    {
      "Target": "myapp:1.4.2 (python-pkg)",
      "Class": "lang-pkgs",
      "Type": "python-pkg",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2023-9876",
          "PkgName": "requests",
          "InstalledVersion": "2.25.0",
          "FixedVersion": "2.31.0",
          "Severity": "MEDIUM",
          "Title": "requests: improper cert validation",
          "Description": "Some description.",
          "Layer": {"Digest": "sha256:bbb222"}
        }
      ]
    }
  ]
}
"""
