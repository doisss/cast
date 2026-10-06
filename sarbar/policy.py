"""Policies / profiles. Policy is OUR artifact: fail/pass rules + risk thresholds.

Profiles are shipped inside the package (`sarbar/policies/*.yaml`) so they reach
an installed copy, and the tool works without PyYAML: the embedded table below is
the authoritative fallback, YAML is an optional overlay (SPEC.md I-11).

Every threshold can be overridden per run via `--fail-on`.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


POLICY_FIELDS = (
    "engines_image", "engines_container", "engines_dockerfile", "engines_fs",
    "fail_on_critical", "fail_on_high", "fail_on_secret",
    "fail_score", "fail_on_degraded",
)


@dataclass
class Policy:
    name: str
    engines_image: list = field(default_factory=lambda: ["trivy"])
    engines_container: list = field(default_factory=lambda: ["trivy"])
    engines_dockerfile: list = field(default_factory=lambda: ["trivy"])
    engines_fs: list = field(default_factory=lambda: ["trivy"])
    fail_on_critical: int = 1        # fail if criticals >= this (-1 = never)
    fail_on_high: int = -1
    fail_on_secret: int = 1          # fail if leaked-secret findings >= this (-1 = never)
    fail_score: float = 80.0         # fail if risk.score >= this (-1 = never)
    # I-1: a run where no external scanner produced results must not pass silently
    fail_on_degraded: bool = True
    offline: bool = False           # use the local database, no network


BUILTIN_PROFILES: dict[str, dict] = {
    "default": {
        "engines_image": ["trivy"],
        # falco needs root and an event driver, so it is not part of the
        # everyday profile. It stays in ci/strict for deliberate use.
        "engines_container": ["trivy"],
        "engines_dockerfile": ["trivy"],
        "engines_fs": ["trivy"],
        "fail_on_critical": 1,
        "fail_on_high": -1,
        "fail_on_secret": 1,
        "fail_score": 80.0,
        "fail_on_degraded": True,
    },
    "ci": {
        "engines_image": ["trivy", "grype"],
        "engines_container": ["trivy", "grype", "falco"],
        "engines_dockerfile": ["trivy"],
        "engines_fs": ["trivy", "grype"],
        "fail_on_critical": 1,
        "fail_on_high": 5,
        "fail_on_secret": 1,
        "fail_score": 60.0,
        "fail_on_degraded": True,
    },
    "strict": {
        "engines_image": ["trivy", "grype", "dockle"],
        "engines_container": ["trivy", "grype", "falco"],
        # dockle is the optional second opinion on Dockerfiles; its absence is
        # reported in diagnostics but does not degrade the run, because trivy
        # config already covers it.
        "engines_dockerfile": ["trivy", "dockle"],
        "engines_fs": ["trivy", "grype"],
        "fail_on_critical": 1,
        "fail_on_high": 1,
        "fail_on_secret": 1,
        "fail_score": 40.0,
        "fail_on_degraded": True,
    },
    "offline": {
        "engines_image": [],
        "engines_container": [],
        "engines_dockerfile": [],
        "engines_fs": [],
        "fail_on_critical": 1,
        "fail_on_high": -1,
        "fail_on_secret": 1,
        "fail_score": 80.0,
        "fail_on_degraded": False,
    },
    "report": {
        "engines_image": ["trivy"],
        "engines_container": ["trivy"],
        "engines_dockerfile": ["trivy"],
        "engines_fs": ["trivy"],
        "fail_on_critical": -1,
        "fail_on_high": -1,
        "fail_on_secret": -1,
        "fail_score": -1.0,
        "fail_on_degraded": False,
    },
}


def _policies_dir() -> str:
    """Packaged profiles directory (falls back to a source checkout layout)."""
    here = os.path.join(os.path.dirname(__file__), "policies")
    if os.path.isdir(here):
        return here
    return os.path.join(os.path.dirname(os.path.dirname(__file__)), "policies")


def _yaml_overlay(name: str) -> dict:
    """Read policies/<name>.yaml if PyYAML is present and the file exists.

    Missing PyYAML is not an error: the embedded table is authoritative.
    A malformed file IS reported, never silently ignored.
    """
    path = os.path.join(_policies_dir(), f"{name}.yaml")
    if not os.path.isfile(path):
        return {}
    try:
        import yaml  # type: ignore
    except ImportError:
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except Exception as ex:
        import sys
        print(f"warning: cannot parse {path}: {ex}", file=sys.stderr)
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if k in POLICY_FIELDS}


def load_profile(name: str = "default", offline: bool = False) -> Policy:
    """Build a policy.

    `offline` is recorded on the policy but no longer clears the engine lists.
    Offline means "use the vulnerability database we already have on disk", so
    the scanner still runs. Clearing the engines here would make --offline
    useless: it would report nothing and pass.
    """
    data = dict(BUILTIN_PROFILES.get(name, BUILTIN_PROFILES["default"]))
    data.update(_yaml_overlay(name))
    p = Policy(
        name=name,
        engines_image=list(data.get("engines_image") or []),
        engines_container=list(data.get("engines_container") or []),
        engines_dockerfile=list(data.get("engines_dockerfile") or []),
        engines_fs=list(data.get("engines_fs") or []),
        fail_on_critical=int(data.get("fail_on_critical", 1)),
        fail_on_high=int(data.get("fail_on_high", -1)),
        fail_on_secret=int(data.get("fail_on_secret", 1)),
        fail_score=float(data.get("fail_score", 80.0)),
        fail_on_degraded=bool(data.get("fail_on_degraded", True)),
    )
    p.offline = offline
    return p


def engines_for(policy: Policy, kind: str) -> list:
    return {
        "image": policy.engines_image,
        "container": policy.engines_container,
        "dockerfile": policy.engines_dockerfile,
        "fs": policy.engines_fs,
    }.get(kind, policy.engines_image)