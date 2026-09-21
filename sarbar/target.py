"""Target detection: image vs container vs Dockerfile vs filesystem.

User never tells us the scanner — they give a GOAL:
  sarbar scan alpine:3.19    -> image (static analysis)
  sarbar scan abc123def456   -> running container (runtime + link to image)
  sarbar scan ./Dockerfile   -> dockerfile (own lint + dockle)
  sarbar scan ./app          -> filesystem (secrets + fs vulns)
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


def detect_target(raw: str, docker_ps_ids: set | None = None) -> Target:
    raw = raw.strip()
    # 1. Real filesystem path wins.
    if os.path.exists(raw):
        base = os.path.basename(raw.rstrip("/"))
        if os.path.isfile(raw) and ("dockerfile" in base.lower() or base == "Containerfile"):
            return Target(raw, TargetKind.DOCKERFILE)
        if os.path.isfile(raw) and base.lower().endswith((".tar", ".tar.gz", ".tgz")):
            # image archive — treat as image input
            return Target(raw, TargetKind.IMAGE, detail="archive")
        if os.path.isdir(raw):
            # dir containing a Dockerfile is still fs scan (we scan both inside)
            return Target(raw, TargetKind.FS)
        # any other file -> fs
        return Target(raw, TargetKind.FS)
    # name looks like Dockerfile without file existing (typo guard)
    if raw.lower().endswith("dockerfile"):
        return Target(raw, TargetKind.DOCKERFILE)
    if raw.startswith("./") or raw.startswith("/") or raw.startswith("../"):
        # explicit path that does not exist -> fs (engine will report error)
        return Target(raw, TargetKind.FS)
    # 2. Running container id / name.
    if docker_ps_ids and raw in docker_ps_ids:
        return Target(raw, TargetKind.CONTAINER)
    if _CONTAINER_RE.match(raw) and ":" not in raw and "/" not in raw and "." not in raw:
        # 12-char short id or 64-char long id, hex only -> container.
        # NOTE: ambiguous with short image tag without registry; container wins
        # because `scan <container-id>` is the documented runtime mode.
        return Target(raw, TargetKind.CONTAINER)
    # 3. Everything else is an image reference.
    return Target(raw, TargetKind.IMAGE)
