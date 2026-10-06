"""Realistic scanner payloads, shaped like the tools actually emit them."""

# trivy >= 0.50 `trivy image|fs|config --format json`
TRIVY_JSON = {
    "SchemaVersion": 2,
    "ArtifactName": "app:latest",
    "Results": [
        {
            "Target": "app (alpine 3.19)",
            "Class": "os-pkgs",
            "Type": "alpine",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-1111",
                    "PkgName": "openssl",
                    "InstalledVersion": "3.1.4-r5",
                    "FixedVersion": "3.1.4-r6",
                    "Severity": "CRITICAL",
                    "Title": "openssl: out-of-bounds read",
                    "Description": "x" * 900,
                    "CVSS": {"nvd": {"V3Score": 9.1, "V3Vector": "AV:N"},
                             "redhat": {"V3Score": 7.5}},
                    "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-1111",
                },
                {
                    "VulnerabilityID": "CVE-2024-2222",
                    "PkgName": "busybox",
                    "InstalledVersion": "1.36.1-r15",
                    "FixedVersion": "",
                    "Severity": "MEDIUM",
                    "Title": "busybox: use after free",
                    "Description": "y" * 900,
                    "CVSS": {"nvd": {"V3Score": 6.5}},
                    "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-2222",
                },
            ],
            "Misconfigurations": [
                {
                    "ID": "DS002",
                    "Title": "Image user should not be root",
                    "Severity": "HIGH",
                    "Description": "Running containers with 'root' user can lead to a container escape situation.",
                    "PrimaryURL": "https://avd.aquasec.com/misconfig/ds002",
                }
            ],
            "Secrets": [
                {
                    "RuleID": "aws-access-key-id",
                    "Title": "AWS Access Key ID",
                    "StartLine": 3,
                    "Target": "app/config.py",
                }
            ],
        }
    ],
}

# grype >= 0.7x: `matches[].vulnerability.cvss` is a LIST, not an object
GRYPE_JSON = {
    "matches": [
        {
            "vulnerability": {
                "id": "CVE-2024-1111",
                "severity": "Critical",
                "description": "openssl: out-of-bounds read",
                "cvss": [
                    {"version": "3.1", "vector": "AV:N", "metrics": "9.8", "type": "NVD"},
                    {"version": "3.1", "vector": "AV:N", "metrics": "7.5", "type": "Red Hat"},
                ],
                "fix": {"versions": ["3.1.4-r6"]},
                "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1111"],
            },
            "artifact": {"name": "openssl", "version": "3.1.4-r5", "type": "apk"},
        },
        {
            "vulnerability": {
                "id": "CVE-2024-3333",
                "severity": "Low",
                "description": "minor issue",
                "cvss": [],
            },
            "artifact": {"name": "musl", "version": "1.2.4-r2", "type": "apk"},
        },
    ]
}

# dockle: `details[]` with level INFO/WARN/ERROR
DOCKLE_JSON = {
    "summary": {"fatal": 0, "warn": 1, "info": 1, "pass": 4, "skip": 0},
    "details": [
        {"code": "CIS-DI-0001", "title": "Avoid 'latest' tag", "level": "WARN",
         "desc": "Specify the image tag"},
        {"code": "CIS-DI-0002", "title": "Avoid use of root user", "level": "ERROR",
         "desc": "Last user should not be root"},
        {"code": "CIS-DI-0010", "title": "No healthcheck", "level": "INFO",
         "desc": "HEALTHCHECK instruction missing"},
    ],
}

# falco json_output=true: newline-delimited JSON with a real priority vocabulary
FALCO_NDJSON = "\n".join([
    '{"output":"Write below binary dir (user=root container_id=abc file_path=/usr/bin/x)","priority":"Warning","rule":"Write below binary dir","source":"syscall","time":"2026-01-01T00:00:00Z"}',
    '{"output":"Contact K8S API server (container=k8s_client)","priority":"Notice","rule":"Contact K8S API server","source":"syscall","time":"2026-01-01T00:00:01Z"}',
    '{"output":"Unexpected outbound connection","priority":"Emergency","rule":"Outbound Connection","source":"network","time":"2026-01-01T00:00:02Z"}',
    '{"output":"Terminal shell in container (user=root)","priority":"Informational","rule":"Terminal shell in container","source":"syscall","time":"2026-01-01T00:00:03Z"}',
    'not json at all',
    '{"output":"Alert","priority":"Alert","rule":"Core dumped","source":"syscall"}',
])

# trivy prints progress/banner lines before the JSON document
TRIVY_NOISY = (
    "2026-10-04T10:54:38-04:00  INFO  [vulndb] Need to update DB\n"
    "2026-10-04T10:54:38-04:00  INFO  [vulndb] Downloading vulnerability DB...\n"
    '{"SchemaVersion":2,"Results":[]}'
)

TRIVY_FATAL = (
    "2026-10-04T10:54:38-04:00  INFO  Need to update DB\n"
    "FATAL   unable to initialize DB: failed to download vulnerability DB\n"
)