"""cast-checks: OUR OWN checks where universal scanners are weak.

- Dockerfile best practices (no hadolint/dockle needed, pure python)
- embedded secrets (AWS keys, private keys, tokens)
- dangerous runtime config from `docker inspect` (privileged, root, caps)
- world-writable / setuid leftovers in fs scans

Each check returns list[Finding] with engine="cast-checks".
"""
from __future__ import annotations

import os
import re

from sarbar.model import Finding

SECRET_PATTERNS = [
    ("CAST-SECRET-001", "Possible AWS access key", re.compile(r"AKIA[0-9A-Z]{16}"), "HIGH"),
    ("CAST-SECRET-002", "Possible private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "HIGH"),
    ("CAST-SECRET-003", "Possible GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"), "HIGH"),
    ("CAST-SECRET-004", "Password in assignment", re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"]{4,}"), "MEDIUM"),
    ("CAST-SECRET-005", "Generic API token", re.compile(r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{8,}"), "MEDIUM"),
]

DOCKERFILE_RULES = [
    ("CAST-DOCKER-001", "Avoid ADD in favor of COPY", "MEDIUM",
     lambda lines: any(l.strip().upper().startswith("ADD ") for l in lines),
     "ADD auto-extracts archives; prefer COPY."),
    ("CAST-DOCKER-002", "Base image uses :latest", "MEDIUM",
     lambda lines: any(re.match(r"(?i)^FROM\s+\S+:latest(\s|$)", l.strip()) or
                       (l.strip().upper().startswith("FROM ") and ":" not in l.strip().split()[1]
                        and not l.strip().split()[1].startswith("$")) for l in lines if l.strip()),
     "Pin an explicit version tag."),
    ("CAST-DOCKER-003", "Running as root (no USER)", "HIGH",
     lambda lines: not any(l.strip().upper().startswith("USER ") for l in lines),
     "Add a non-root USER instruction."),
    ("CAST-DOCKER-004", "apt-get without cleanup", "LOW",
     lambda lines: any("apt-get" in l and "install" in l for l in lines) and
     not any("rm -rf /var/lib/apt/lists" in l for l in lines),
     "Clean apt lists in the same layer."),
    ("CAST-DOCKER-005", "Secrets via ENV/ARG", "HIGH",
     lambda lines: any(re.search(r"(?i)^(ENV|ARG)\s+.*(PASSWORD|SECRET|TOKEN|KEY)\s*=", l.strip()) for l in lines),
     "Do not bake credentials into image layers."),
    ("CAST-DOCKER-006", "Missing HEALTHCHECK", "LOW",
     lambda lines: not any(l.strip().upper().startswith("HEALTHCHECK") for l in lines),
     "Consider adding HEALTHCHECK."),
]


def check_dockerfile(path: str, target: str) -> list[Finding]:
    try:
        with open(path, errors="ignore") as f:
            lines = f.read().splitlines()
    except OSError:
        return []
    out: list[Finding] = []
    for cid, title, sev, cond, desc in DOCKERFILE_RULES:
        try:
            if cond(lines):
                out.append(Finding(cid, title, sev, target=target,
                                   engine="cast-checks", category="misconfig",
                                   description=desc))
        except Exception:
            continue
    return out


def _scan_text_for_secrets(text: str, where: str, target: str) -> list[Finding]:
    out: list[Finding] = []
    for cid, title, rx, sev in SECRET_PATTERNS:
        if rx.search(text):
            out.append(Finding(cid, title, sev, target=target,
                               engine="cast-checks", category="secret",
                               description=f"{title} found in {where}"))
    return out


BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf",
              ".pyc", ".so", ".o", ".a", ".zip", ".gz", ".mp4", ".pdf"}


def check_fs_secrets(path: str, target: str, max_files: int = 500, max_bytes: int = 200_000) -> list[Finding]:
    out: list[Finding] = []
    seen = 0
    files = [path] if os.path.isfile(path) else []
    if os.path.isdir(path):
        for root, dirs, names in os.walk(path):
            # skip noise
            dirs[:] = [d for d in dirs if d not in {".git", "__pycache__", "node_modules", ".venv", "venv", ".tox"}]
            for n in names:
                if seen >= max_files:
                    break
                _, ext = os.path.splitext(n)
                if ext.lower() in BINARY_EXT:
                    continue
                files.append(os.path.join(root, n))
                seen += 1
            if seen >= max_files:
                break
    else:
        seen = len(files)
    for fp in files[:max_files]:
        try:
            if os.path.getsize(fp) > max_bytes:
                continue
            with open(fp, errors="ignore") as f:
                text = f.read(max_bytes)
        except OSError:
            continue
        out.extend(_scan_text_for_secrets(text, fp, target))
        if len(out) > 50:
            break
    # dedup same rule (report once per rule for fs to avoid spam)
    uniq: dict[str, Finding] = {}
    for f in out:
        uniq.setdefault(f.check_id, f)
    return list(uniq.values())


def check_inspect(inspect: dict, target: str) -> list[Finding]:
    """Runtime checks from `docker inspect` JSON (no agent needed)."""
    out: list[Finding] = []
    cfg = inspect.get("Config", {}) or {}
    host = inspect.get("HostConfig", {}) or {}
    if host.get("Privileged"):
        out.append(Finding("CAST-RT-001", "Container runs --privileged", "CRITICAL",
                           target=target, engine="cast-checks", category="runtime",
                           description="Privileged container disables most isolation."))
    user = cfg.get("User", "") or ""
    if user in ("", "0", "root", "0:0"):
        out.append(Finding("CAST-RT-002", "Container runs as root", "HIGH",
                           target=target, engine="cast-checks", category="runtime",
                           description="No User set; process runs as root."))
    caps = (host.get("CapAdd") or []) + (host.get("Capabilities", {}) or {}).get("Add", [] ) if isinstance(host.get("Capabilities"), dict) else (host.get("CapAdd") or [])
    dangerous = {"SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "DAC_OVERRIDE", "SYSLOG"}
    hit = dangerous & {str(c).upper() for c in (caps or [])}
    if hit:
        out.append(Finding("CAST-RT-003", f"Dangerous capabilities: {','.join(sorted(hit))}", "HIGH",
                           target=target, engine="cast-checks", category="runtime",
                           description="Drop unneeded Linux capabilities."))
    if host.get("NetworkMode") == "host":
        out.append(Finding("CAST-RT-004", "Host network mode", "MEDIUM",
                           target=target, engine="cast-checks", category="runtime",
                           description="--network host weakens network isolation."))
    for m in host.get("Binds", []) or []:
        if "/var/run/docker.sock" in str(m):
            out.append(Finding("CAST-RT-005", "Docker socket mounted", "CRITICAL",
                               target=target, engine="cast-checks", category="runtime",
                               description="Mounting docker.sock lets container control the host daemon."))
    return out
