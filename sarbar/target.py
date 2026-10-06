"""Target detection: image vs container vs Dockerfile vs filesystem.

The user states a goal, never a scanner:
  sarbar scan alpine:3.19    -> image         (static analysis of an image)
  sarbar scan abc123def456   -> container     (running container)
  sarbar scan ./Dockerfile   -> dockerfile    (linted by `trivy config`)
  sarbar scan ./app          -> filesystem    (secrets + dependency vulns)

Which scanner actually runs for a kind is decided by the profile, not here
(`policy.engines_for`). This module only answers "what did the user mean".

Ambiguity is resolved in favour of the filesystem and the documented runtime
mode, and the decision is recorded in `detail` so a report can explain it.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from enum import Enum


class TargetKind(str, Enum):
    IMAGE = "image"
    CONTAINER = "container"
    DOCKERFILE = "dockerfile"
    FS = "fs"


@dataclass
class Target:
    raw: str
    kind: TargetKind
    detail: str = ""


_CONTAINER_RE = re.compile(r"^[a-fA-F0-9]{6,64}$")
_ARCHIVE_EXT = (".tar", ".tar.gz", ".tgz", ".oci")
_DOCKERFILE_NAMES = {"dockerfile", "containerfile"}


def detect_target(raw: str, docker_ps_ids: set | None = None) -> Target:
    raw = raw.strip()
    if not raw:
        return Target(raw, TargetKind.IMAGE, detail="empty target")

    expanded = os.path.expanduser(raw)

    # 1. A real filesystem path always wins.
    if os.path.exists(expanded):
        base = os.path.basename(expanded.rstrip("/")).lower()
        if os.path.isfile(expanded):
            if base in _DOCKERFILE_NAMES or base.startswith("dockerfile"):
                return Target(raw, TargetKind.DOCKERFILE)
            if raw.lower().endswith(_ARCHIVE_EXT):
                return Target(raw, TargetKind.IMAGE, detail="image archive")
            return Target(raw, TargetKind.FS, detail="single file")
        return Target(raw, TargetKind.FS, detail="directory")

    # 2. A name that looks like a Dockerfile but was not found on disk. Checked
    #    before the generic missing-path branch so "./Dockerfile" keeps its intent.
    base = os.path.basename(raw).lower()
    if base in _DOCKERFILE_NAMES or base.startswith("dockerfile"):
        return Target(raw, TargetKind.DOCKERFILE, detail="dockerfile not found on disk")

    # 3. Explicit path syntax that does not exist: still a path intent, so the
    #    caller can report a precise "no such path" instead of scanning an image
    #    called "./typo".
    if raw.startswith(("./", "../", "/", "~/")) or raw in (".", ".."):
        return Target(raw, TargetKind.FS, detail="path does not exist")

    # 4. A running container, confirmed by docker.
    if docker_ps_ids and raw in docker_ps_ids:
        return Target(raw, TargetKind.CONTAINER, detail="matches a running container")

    # 5. Container-id shape. Ambiguous with a short image tag, so the documented
    #    runtime mode wins; resolution against docker happens in the
    #    orchestrator and a miss is reported as an error, never as a pass.
    if _CONTAINER_RE.match(raw) and ":" not in raw and "/" not in raw and "." not in raw:
        return Target(raw, TargetKind.CONTAINER, detail="container-id shape, unverified")

    return Target(raw, TargetKind.IMAGE, detail="image reference")