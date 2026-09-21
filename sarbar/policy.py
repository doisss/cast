"""Policies / profiles. Policy is OUR artifact: fail/pass rules + risk thresholds.

Profiles live in policies/*.yaml but code works without PyYAML
(embedded fallback) so the tool runs offline with zero deps.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Policy:
    name: str
    engines_image: list = field(default_factory=lambda: ["trivy"])
    engines_container: list = field(default_factory=lambda: ["trivy"])
    engines_dockerfile: list = field(default_factory=lambda: ["dockle"])
    engines_fs: list = field(default_factory=lambda: ["trivy"])
    run_cast_checks: bool = True
    fail_on_critical: int = 1        # fail if criticals >= this (-1 = never)
    fail_on_high: int = -1
    fail_score: float = 80.0         # fail if risk.score >= this (-1 = never)
    offline: str = "fallback"        # fallback | strict


BUILTIN_PROFILES: dict[str, dict] = {
    "default": {
        "engines_image": ["trivy"],
        "engines_container": ["trivy"],
        "engines_dockerfile": ["dockle"],
        "engines_fs": ["trivy"],
        "run_cast_checks": True,
        "fail_on_critical": 1,
        "fail_on_high": -1,
        "fail_score": 80.0,
    },
    "ci": {
        "engines_image": ["trivy", "grype"],
        "engines_container": ["trivy", "grype"],
        "engines_dockerfile": ["dockle"],
        "engines_fs": ["trivy", "grype"],
        "run_cast_checks": True,
        "fail_on_critical": 1,
        "fail_on_high": 5,
        "fail_score": 60.0,
    },
    "strict": {
        "engines_image": ["trivy", "grype", "dockle"],
        "engines_container": ["trivy", "grype"],
        "engines_dockerfile": ["dockle"],
        "engines_fs": ["trivy", "grype"],
        "run_cast_checks": True,
        "fail_on_critical": 1,
        "fail_on_high": 1,
        "fail_score": 40.0,
    },
    "offline": {
        "engines_image": [],
        "engines_container": [],
        "engines_dockerfile": [],
        "engines_fs": [],
        "run_cast_checks": True,
        "fail_on_critical": 1,
        "fail_on_high": -1,
        "fail_score": 80.0,
    },
}


def load_profile(name: str = "default", offline: bool = False) -> Policy:
    data = BUILTIN_PROFILES.get(name, BUILTIN_PROFILES["default"]).copy()
    # try to overlay policies/<name>.yaml if PyYAML exists (optional)
    try:
        import yaml  # type: ignore
        import os
        here = os.path.join(os.path.dirname(os.path.dirname(__file__)), "policies", f"{name}.yaml")
        if os.path.exists(here):
            with open(here) as f:
                overlay = yaml.safe_load(f) or {}
            data.update({k: v for k, v in overlay.items() if v is not None})
    except Exception:
        pass
    p = Policy(
        name=name,
        engines_image=data.get("engines_image", ["trivy"]),
        engines_container=data.get("engines_container", ["trivy"]),
        engines_dockerfile=data.get("engines_dockerfile", ["dockle"]),
        engines_fs=data.get("engines_fs", ["trivy"]),
        run_cast_checks=data.get("run_cast_checks", True),
        fail_on_critical=data.get("fail_on_critical", 1),
        fail_on_high=data.get("fail_on_high", -1),
        fail_score=data.get("fail_score", 80.0),
    )
    if offline:
        p.engines_image, p.engines_container = [], []
        p.engines_dockerfile, p.engines_fs = [], []
    return p


def engines_for(policy: Policy, kind: str) -> list:
    return {
        "image": policy.engines_image,
        "container": policy.engines_container,
        "dockerfile": policy.engines_dockerfile,
        "fs": policy.engines_fs,
    }.get(kind, policy.engines_image)
