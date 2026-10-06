"""Engine adapters. Each wraps an EXISTING scanner binary (Trivy/Grype/Dockle/Falco).

Contract: run(target, kind) -> EngineResult (already normalized findings + a
status describing whether the engine actually worked).

Why EngineResult instead of a bare list
---------------------------------------
The previous contract returned `list[Finding]` and reported failure by returning
an empty list. That is indistinguishable from "scanned successfully, found
nothing", so the orchestrator counted a broken engine as a working one, printed
PASS, and suppressed the built-in checks. Every failure mode is now explicit:
`ok`, `unavailable`, `failed`, `timeout`, `unsupported`.

Binary resolution
-----------------
`resolve()` returns an absolute path. Adapters must execute that path, never a
bare name: the tools may live in ~/.sarbar/bin, which is not on PATH, and
`shutil.which` alone silently reported them as available while every call
failed with ENOENT.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field

from sarbar.model import Finding, normalize_severity

# sarbar's own bin directory (populated by `sarbar setup`)
SARBAR_BIN = os.path.expanduser("~/.sarbar/bin")

STATUS_OK = "ok"
STATUS_UNAVAILABLE = "unavailable"
STATUS_FAILED = "failed"
STATUS_TIMEOUT = "timeout"
STATUS_UNSUPPORTED = "unsupported"


@dataclass
class EngineResult:
    findings: list = field(default_factory=list)
    status: str = STATUS_OK
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status == STATUS_OK


def resolve(name: str) -> str | None:
    """Absolute path to an engine binary, or None.

    Search order: PATH, then ~/.sarbar/bin. Callers MUST exec the returned path.
    """
    found = shutil.which(name)
    if found:
        return os.path.abspath(found)
    candidate = os.path.join(SARBAR_BIN, name)
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return candidate
    return None


def _find_binary(name: str) -> str | None:
    """Backwards-compatible alias for resolve()."""
    return resolve(name)


class Engine:
    name = "base"
    # Engines that need root and a kernel driver cannot produce findings in a
    # short-lived subprocess; the orchestrator uses this to warn instead of
    # pretending the engine contributed coverage.
    needs_root = False
    supports: tuple = ()
    # Can this scanner work with no network at all? trivy can once its
    # vulnerability database is cached locally; falco needs no network anyway.
    supports_offline = True

    # Offline flags are NOT the same for every trivy subcommand, and passing a
    # flag a subcommand does not have makes trivy exit 1 with "unknown flag".
    # Measured against trivy 0.75:
    #   image / fs     --skip-db-update, --offline-scan, --skip-check-update
    #   config         --skip-check-update only. `trivy config` has no
    #                   vulnerability database at all, so --skip-db-update and
    #                   --offline-scan are simply unknown to it.
    OFFLINE_FLAGS = {
        "image": ("--skip-db-update", "--offline-scan", "--skip-check-update"),
        "fs": ("--skip-db-update", "--offline-scan", "--skip-check-update"),
        "container": ("--skip-db-update", "--offline-scan", "--skip-check-update"),
        "dockerfile": ("--skip-check-update",),
    }

    def resolve(self) -> str | None:
        return resolve(self.name)

    def is_available(self) -> bool:
        """True only when the binary exists AND actually executes."""
        path = self.resolve()
        if not path:
            return False
        try:
            p = subprocess.run([path, "--version"], capture_output=True,
                               text=True, timeout=20)
            return p.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def run(self, target: str, kind: str, offline: bool = False) -> EngineResult:
        raise NotImplementedError


def _ran_falco(out: str) -> bool:
    """Did falco actually start?

    Falco prints "Falco version: ..." or "Falco initialized with configuration
    files" before it does anything. If neither appears, whatever produced the
    output was not falco — most often `sudo -n` refusing to run — and no
    observation was made. Treating that as "0 events" would call a container
    clean when nothing looked at it, which is the exact failure this tool exists
    to prevent (SPEC.md I-1).
    """
    return "falco version" in out[:800].lower()


def _run_cmd(cmd: list[str], timeout: int = 300) -> tuple[int, str]:
    """Run cmd, return (returncode, combined output). 124 = timeout, 127 = ENOENT."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return 127, ""
    except PermissionError:
        return 126, ""
    except subprocess.TimeoutExpired as ex:
        # Keep whatever falco printed before it was killed: discarding it loses
        # the only evidence of why it never produced events. Note that even with
        # text=True, TimeoutExpired carries bytes, not str — a Python quirk.
        parts = []
        for chunk in (getattr(ex, "stdout", None), getattr(ex, "stderr", None)):
            if isinstance(chunk, bytes):
                parts.append(chunk.decode("utf-8", "replace"))
            elif isinstance(chunk, str):
                parts.append(chunk)
        return 124, "".join(parts)


def _load_json(out: str) -> dict | None:
    """Extract the first JSON object from noisy scanner output."""
    start = out.find("{")
    if start < 0:
        return None
    try:
        data = json.loads(out[start:])
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _cvss_of(obj: dict) -> float:
    """Best-effort CVSS extraction across trivy / grype / nvd shapes.

    grype reports `cvss` as a LIST of {metrics|type, vector} objects, which the
    previous dict-only implementation silently scored as 0.0.
    """
    if not isinstance(obj, dict):
        return 0.0

    def _num(v):
        try:
            f = float(v)
        except (TypeError, ValueError):
            return 0.0
        return f if f > 0 else 0.0

    # grype: cvss is a list of objects
    for entry in obj.get("cvss") or []:
        if isinstance(entry, dict):
            for k in ("metrics", "score", "baseScore", "V3Score", "value"):
                got = _num(entry.get(k))
                if got:
                    return got
        elif isinstance(entry, (int, float)) and entry > 0:
            return float(entry)

    # trivy: CVSS is a dict keyed by vendor, each holding V3Score/V2Score
    v = obj.get("CVSS")
    if isinstance(v, dict):
        best = 0.0
        for sub in ("V3Score", "v3Score", "V2Score", "score", "baseScore"):
            got = _num(v.get(sub))
            if got:
                return got
        for nested in v.values():
            if isinstance(nested, dict):
                for sub in ("V3Score", "v3Score", "V2Score", "baseScore", "score"):
                    got = _num(nested.get(sub))
                    best = max(best, got)
        if best:
            return best

    for key in ("cvssScore", "cvss_score", "score", "baseScore", "V3Score", "baseSeverity"):
        got = _num(obj.get(key))
        if got:
            return got
    return 0.0


class TrivyEngine(Engine):
    name = "trivy"
    supports = ("image", "fs", "dockerfile", "container")
    supports_offline = True

    # Where trivy keeps the vulnerability database. `sarbar offline` fills it,
    # after which --skip-db-update keeps the scan off the network.
    DB_DIR = "~/.cache/trivy/db"
    DB_META = "~/.cache/trivy/db/metadata.json"

    # Trivy exits non-zero for "found vulnerabilities" as well as for hard
    # errors, so the presence of a JSON document decides success.
    JSON_MARKER = "SchemaVersion"

    @classmethod
    def db_present(cls) -> bool:
        return os.path.isdir(os.path.expanduser(cls.DB_DIR)) and \
            os.path.isfile(os.path.expanduser(cls.DB_META))

    def download_db(self) -> tuple[bool, str]:
        """Fetch the vulnerability database now, so later scans need no network."""
        path = self.resolve()
        if not path:
            return False, "trivy is not installed; run `sarbar setup`"
        code, out = _run_cmd([path, "image", "--download-db-only",
                              "--cache-dir", os.path.expanduser("~/.cache/trivy")],
                             timeout=900)
        if self.db_present():
            return True, f"database present in {os.path.expanduser(self.DB_DIR)}"
        tail = " ".join(out.split())[-250:]
        return False, f"could not download the database (exit {code}): {tail}"

    def run(self, target: str, kind: str, offline: bool = False) -> EngineResult:
        path = self.resolve()
        if not path:
            return EngineResult(status=STATUS_UNAVAILABLE, detail="binary not found")
        base = [path]
        if kind in ("image", "container"):
            base += ["image", "--quiet", "--format", "json",
                     "--scanners", "vuln,misconfig,secret"]
        elif kind == "fs":
            base += ["fs", "--quiet", "--format", "json",
                     "--scanners", "vuln,misconfig,secret"]
        elif kind == "dockerfile":
            base += ["config", "--quiet", "--format", "json"]
        else:
            return EngineResult(status=STATUS_UNSUPPORTED, detail=f"kind={kind}")
        if offline:
            # keep whatever is already on disk and never call out
            base += list(self.OFFLINE_FLAGS.get(kind, ()))
        base.append(target)
        code, out = _run_cmd(base)
        if code == 124:
            return EngineResult(status=STATUS_TIMEOUT, detail="trivy timed out")
        if code == 127:
            return EngineResult(status=STATUS_UNAVAILABLE, detail="binary vanished")
        if self.JSON_MARKER not in out:
            # No JSON at all: a hard error such as an unusable database.
            tail = " ".join(out.split())[-300:]
            hint = ""
            if "no such file" in out.lower() or "database" in out.lower() or \
                    "unable to initialize db" in out.lower():
                hint = (" No vulnerability database. Fetch it once with "
                        "`sarbar offline <target>`.")
            return EngineResult(status=STATUS_FAILED,
                                detail=f"trivy exit={code}, no report: {tail}{hint}")
        data = _load_json(out)
        if data is None:
            tail = " ".join(out.split())[-300:]
            return EngineResult(status=STATUS_FAILED,
                                detail=f"trivy exit={code}, unreadable report: {tail}")
        return EngineResult(findings=self.parse(data, target), status=STATUS_OK)

    def parse(self, data: dict, target: str) -> list[Finding]:
        out: list[Finding] = []
        for res in data.get("Results") or []:
            for v in res.get("Vulnerabilities") or []:
                out.append(Finding(
                    check_id=v.get("VulnerabilityID", "UNKNOWN"),
                    title=v.get("Title") or v.get("VulnerabilityID", ""),
                    severity=v.get("Severity", "UNKNOWN"),
                    target=target,
                    package=v.get("PkgName", ""),
                    installed_version=v.get("InstalledVersion", ""),
                    fixed_version=v.get("FixedVersion", ""),
                    cvss=_cvss_of(v),
                    description=(v.get("Description") or "")[:500],
                    engine="trivy", category="vuln",
                    references=[v["PrimaryURL"]] if v.get("PrimaryURL") else [],
                ))
            for m in res.get("Misconfigurations") or []:
                out.append(Finding(
                    check_id=m.get("ID", "MISCONFIG"),
                    title=m.get("Title") or m.get("ID", ""),
                    severity=m.get("Severity", "MEDIUM"),
                    target=target,
                    description=(m.get("Description") or "")[:500],
                    engine="trivy", category="misconfig",
                    references=[m["PrimaryURL"]] if m.get("PrimaryURL") else [],
                ))
            for s in res.get("Secrets") or []:
                loc = s.get("Target") or ""
                if s.get("StartLine"):
                    loc = f"{loc}:{s['StartLine']}"
                out.append(Finding(
                    check_id=s.get("RuleID", "SECRET"),
                    title=s.get("Title") or "Embedded secret",
                    severity="HIGH", target=target,
                    description=f"Secret in {loc}" if loc else "Embedded secret",
                    engine="trivy", category="secret",
                    locations=[loc] if loc else [],
                ))
        return out


class GrypeEngine(Engine):
    name = "grype"
    supports = ("image", "fs", "container")

    def run(self, target: str, kind: str) -> EngineResult:
        if kind == "dockerfile":
            return EngineResult(status=STATUS_UNSUPPORTED, detail="grype has no dockerfile mode")
        path = self.resolve()
        if not path:
            return EngineResult(status=STATUS_UNAVAILABLE, detail="binary not found")
        ref = f"dir:{target}" if kind == "fs" else target
        code, out = _run_cmd([path, "-o", "json", ref])
        if code == 124:
            return EngineResult(status=STATUS_TIMEOUT, detail="grype timed out")
        if code == 127:
            return EngineResult(status=STATUS_UNAVAILABLE, detail="binary vanished")
        data = _load_json(out)
        if data is None:
            tail = " ".join(out.split())[-300:]
            return EngineResult(status=STATUS_FAILED,
                                detail=f"grype exit={code}, no JSON report: {tail}")
        return EngineResult(findings=self.parse(data, target), status=STATUS_OK)

    def parse(self, data: dict, target: str) -> list[Finding]:
        out: list[Finding] = []
        for m in data.get("matches") or []:
            vuln = m.get("vulnerability") or {}
            art = m.get("artifact") or {}
            fix = vuln.get("fix") or {}
            versions = fix.get("versions") if isinstance(fix, dict) else None
            fixed = versions[0] if isinstance(versions, list) and versions else ""
            out.append(Finding(
                check_id=vuln.get("id", "UNKNOWN"),
                title=vuln.get("description") or vuln.get("id", "")[:200],
                severity=vuln.get("severity", "UNKNOWN"),
                target=target,
                package=art.get("name", ""),
                installed_version=art.get("version", ""),
                fixed_version=fixed,
                cvss=_cvss_of(vuln),
                description=(vuln.get("description") or "")[:500],
                engine="grype", category="vuln",
                references=vuln.get("urls") or [],
            ))
        return out


class DockleEngine(Engine):
    name = "dockle"
    supports = ("image", "dockerfile")

    def run(self, target: str, kind: str) -> EngineResult:
        if kind not in self.supports:
            return EngineResult(status=STATUS_UNSUPPORTED, detail=f"kind={kind}")
        path = self.resolve()
        if not path:
            return EngineResult(status=STATUS_UNAVAILABLE, detail="binary not found")
        code, out = _run_cmd([path, "-f", "json", target])
        if code == 124:
            return EngineResult(status=STATUS_TIMEOUT, detail="dockle timed out")
        if code == 127:
            return EngineResult(status=STATUS_UNAVAILABLE, detail="binary vanished")
        data = _load_json(out)
        if data is None:
            tail = " ".join(out.split())[-300:]
            return EngineResult(status=STATUS_FAILED,
                                detail=f"dockle exit={code}, no JSON report: {tail}")
        return EngineResult(findings=self.parse(data, target), status=STATUS_OK)

    def parse(self, data: dict, target: str) -> list[Finding]:
        out: list[Finding] = []
        details = data.get("details") or data.get("assessments") or []
        for d in details:
            code_ = str(d.get("code", "DOCKLE"))
            out.append(Finding(
                check_id=code_,
                title=d.get("title") or code_,
                severity=d.get("level", "MEDIUM"),
                target=target, engine="dockle", category="misconfig",
                description=(d.get("desc") or "")[:500],
            ))
        return out


# Where falco 0.45 looks for its plugins, in order. A per-user install cannot
# write to the first two, which is why the adapter passes an absolute
# library_path instead of relying on the search order.
FALCO_PLUGIN_DIRS = (
    "/usr/share/falco/plugins",
    "/usr/local/share/falco/plugins",
    "~/.local/share/falco/plugins",
    "~/.sarbar/share/falco/plugins",
)


class FalcoEngine(Engine):
    """Falco runtime behaviour monitoring.

    Command line, verified against `falco --help` for 0.42.x:

      -c <file>     configuration. Falco refuses to start without it, and it
                    ships in /etc/falco inside the official package.
      -r <file>     rule file. Also mandatory.
      -M <seconds>  stop after N seconds. This is a *duration*, not an event
                    count.
      -U            unbuffered, so events are readable before the process ends.
      -o json_output=true, -o json_include_output_property=true

    `-A` was removed in Falco 0.42 ("Option 'A' does not exist"); the previous
    version passed it and therefore failed immediately with zero output while
    still being counted as a working scanner.

    Honest limitation, also stated in every report: Falco is a privileged
    daemon driven by eBPF or a kernel module. A bounded subprocess window is not
    a full runtime analysis, so when the driver is missing or the window yields
    nothing we say exactly that instead of implying the container was clean.
    """
    name = "falco"
    supports = ("container", "image")
    needs_root = True
    WINDOW_SECONDS = 20

    # The proper Linux install puts these in /etc/falco; ~/.sarbar/etc/falco is
    # the fallback used when installing without root.
    CONFIG_CANDIDATES = (
        "/etc/falco/falco.yaml",
        "~/.sarbar/etc/falco/falco.yaml",
    )
    RULES_CANDIDATES = (
        "/etc/falco/falco_rules.yaml",
        "~/.sarbar/etc/falco/falco_rules.yaml",
    )

    @staticmethod
    def running_as_root() -> bool:
        return hasattr(os, "geteuid") and os.geteuid() == 0

    @staticmethod
    def authorise_sudo() -> tuple[bool, str]:
        """Ask for the sudo password on the user's terminal, once.

        `sudo -v` inherits stdio, so the prompt is visible and interactive. It
        also refreshes sudo's timestamp, after which `sudo -n` succeeds for a few
        minutes without asking again. That is why validation and the actual run
        are two separate calls.
        """
        if FalcoEngine.running_as_root():
            return True, "already root"
        if not shutil.which("sudo"):
            return False, "sudo is not installed"
        try:
            done = subprocess.run(["sudo", "-v"], timeout=180)
        except (OSError, subprocess.SubprocessError) as ex:
            return False, f"sudo -v failed: {ex}"
        if done.returncode != 0:
            return False, "the sudo password was not accepted"
        return True, "sudo authorised for this terminal"

    @classmethod
    def _first_existing(cls, candidates: tuple) -> str | None:
        for path in candidates:
            expanded = os.path.expanduser(path)
            if os.path.isfile(expanded):
                return expanded
        return None

    def config_path(self) -> str | None:
        return self._first_existing(self.CONFIG_CANDIDATES)

    def rules_path(self) -> str | None:
        return self._first_existing(self.RULES_CANDIDATES)

    def build_command(self, seconds: int | None = None,
                      sudo: bool = False) -> list[str] | None:
        """Full argv, or None when a mandatory file is missing.

        `sudo` prefixes `sudo -n`, which only succeeds right after credentials
        were validated with `sudo -v`. That split is deliberate: the password
        prompt must go to the user's terminal, the JSON output must be captured.
        """
        path = self.resolve()
        if not path:
            return None
        config = self.config_path()
        rules = self.rules_path()
        if not config or not rules:
            return None
        cmd = []
        if sudo:
            cmd += ["sudo", "-n"]
        cmd += [
            path,
            "-c", config,
            "-r", rules,
        ]
        plugin = self.container_plugin()
        if plugin:
            # Two things are needed, and both were discovered the hard way:
            #   1. falco 0.45 ships load_plugins: [] — the container plugin is
            #      NOT enabled by default, so falco exits with "Plugin
            #      requirement not satisfied, must load one of: container".
            #   2. library_path in the shipped config is the bare filename
            #      libcontainer.so, resolved against /usr/share/falco/plugins.
            #      A per-user install cannot write there, so the absolute path
            #      must be passed instead.
            # The index is read from the config rather than assumed, because a
            # user config may list other plugins first.
            index = self.plugin_index(config)
            cmd += ["-o", f"plugins[{index}].library_path={plugin}",
                    "-o", "load_plugins=container"]
        cmd += [
            "-o", "json_output=true",
            "-o", "json_include_output_property=true",
            "-M", str(seconds or self.WINDOW_SECONDS),
            "-U",
        ]
        return cmd

    # Kept as a class attribute purely as an injection seam: the test suite
    # redirects it into a temp directory so it never reads or writes the real
    # home. The shipped value lives in the module constant below, which is what
    # should be asserted on.
    PLUGIN_DIRS = FALCO_PLUGIN_DIRS

    @classmethod
    def container_plugin(cls) -> str | None:
        """Absolute path of libcontainer.so, or None when it is not installed.

        Falco 0.45 has no command-line flag for the plugin search path, so if the
        plugin is not where falco looks by default the path has to be passed as
        an absolute library_path. Returning None here means falco will be run
        without the plugin and will report why.
        """
        for base in cls.PLUGIN_DIRS:
            path = os.path.join(os.path.expanduser(base), "libcontainer.so")
            if os.path.isfile(path):
                return path
        return None

    @staticmethod
    def plugin_index(config: str | None) -> int:
        """Position of the `container` entry in the config's plugins: list.

        Hard-coded 0 would silently point at a different plugin in a config that
        lists another one first, which would then load the wrong .so.
        """
        if not config or not os.path.isfile(config):
            return 0
        index = 0
        try:
            with open(config, encoding="utf-8", errors="replace") as fh:
                in_block = False
                for line in fh:
                    bare = line.split("#", 1)[0]
                    if re.match(r"^\s*plugins\s*:\s*$", bare):
                        in_block = True
                        continue
                    if in_block and re.match(r"^\S", bare):
                        break          # a new top-level key: the block ended
                    m = re.match(r"^\s*-\s*name\s*:\s*(\S+)", bare)
                    if in_block and m:
                        if m.group(1).strip("\"'") == "container":
                            return index
                        index += 1
        except OSError:
            pass
        return 0

    def run(self, target: str, kind: str, offline: bool = False,
            allow_sudo: bool = True) -> EngineResult:
        if kind not in self.supports:
            return EngineResult(status=STATUS_UNSUPPORTED, detail=f"kind={kind}")
        path = self.resolve()
        if not path:
            return EngineResult(status=STATUS_UNAVAILABLE, detail="binary not found")

        config = self.config_path()
        rules = self.rules_path()
        if not config:
            return EngineResult(
                status=STATUS_UNAVAILABLE,
                detail="no falco.yaml found. Run `sudo sarbar setup --system` for "
                       "the proper layout; without root it lands in "
                       "~/.sarbar/etc/falco")
        if not rules:
            return EngineResult(status=STATUS_UNAVAILABLE,
                                detail=f"no falco_rules.yaml next to {config}")

        # falco reads kernel events, which needs root. Ask once on the user's
        # terminal, then reuse sudo's timestamp for the actual run.
        use_sudo = False
        if not self.running_as_root():
            if not allow_sudo:
                return EngineResult(
                    status=STATUS_UNAVAILABLE,
                    detail="falco needs root to read kernel events, and "
                           "--no-sudo was given")
            ok, why = self.authorise_sudo()
            if not ok:
                return EngineResult(
                    status=STATUS_UNAVAILABLE,
                    detail=f"falco needs root: {why}. Install the driver once "
                           f"with `sudo sarbar setup --driver`, or pass --no-sudo "
                           f"to skip falco")
            use_sudo = True

        cmd = self.build_command(sudo=use_sudo)
        if cmd is None:
            return EngineResult(status=STATUS_UNAVAILABLE,
                                detail="cannot build command")

        code, out = _run_cmd(cmd, timeout=self.WINDOW_SECONDS + 10)

        if code in (126, 127):
            return EngineResult(status=STATUS_UNAVAILABLE,
                                detail=f"{path} is not executable")

        # Falco writes diagnostics to stdout/stderr and exits when the driver is
        # missing. Recognise that explicitly instead of calling it "0 events".
        low = out.lower()
        if ("plugin requirement not satisfied" in low
                or ("driver" in low and "not loaded" in low)
                or "you must specify at least one rules file" in low
                or "must create a config file" in low
                or "unable to load the driver" in low
                or "libpman" in low
                or "ring buffer map type is not supported" in low
                or "initialization issues during scap_init" in low
                or "operation not permitted" in low
                or "a terminal is required to read the password" in low
                or "permission denied" in low):
            reason = " ".join(out.split())[-200:]
            return EngineResult(
                status=STATUS_UNAVAILABLE,
                detail="falco has no event source: it needs root plus an eBPF "
                       "driver, installed once with "
                       "`sudo sarbar setup --driver`. "
                       f"falco says: {reason}")

        # Did falco actually run at all? A `sudo -n` refusal produces output that
        # is entirely sudo's, and reading that as "0 events" is exactly the silent
        # pass this tool exists to prevent: the container would be called clean
        # when nothing observed it. Checked after the specific diagnostics so a
        # genuine falco error is still reported as itself.
        if not _ran_falco(out):
            reason = " ".join(out.split())[-200:]
            via_sudo = " (the command ran through sudo -n)" if use_sudo else ""
            hint = (" Re-authenticate first: sudo -v" if use_sudo
                    else " Run `falco --version` and see what it says.")
            return EngineResult(
                status=STATUS_UNAVAILABLE,
                detail=f"falco did not run at all{via_sudo}, so nothing was "
                       f"observed.{hint} It said: {reason or '(nothing)'}")

        findings = self.parse(out, target)
        if code == 124 and not findings:
            return EngineResult(
                status=STATUS_TIMEOUT,
                detail=f"no events within {self.WINDOW_SECONDS}s. Even with the "
                       "driver loaded, a short window is not a full runtime "
                       "analysis — treat this as 'not observed', not 'clean'")
        if not findings:
            tail = " ".join(out.split())[-200:]
            return EngineResult(status=STATUS_OK,
                                detail=f"0 events in {self.WINDOW_SECONDS}s: {tail}")
        return EngineResult(findings=findings, status=STATUS_OK)

    def parse(self, out: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            rule = str(data.get("rule", "UNKNOWN"))
            # falco priorities are Emergency/Alert/Critical/Error/Warning/Notice/
            # Informational; normalize_severity maps all of them.
            severity = normalize_severity(data.get("priority", "WARNING"))
            text = data.get("output") or rule
            findings.append(Finding(
                check_id="FALCO-" + rule.replace(" ", "-"),
                title=text,
                severity=severity,
                target=target, engine="falco", category="runtime",
                description=text[:500],
                references=[data["source"]] if isinstance(data.get("source"), str) else [],
            ))
        return findings


ENGINES: dict[str, Engine] = {
    "trivy": TrivyEngine(),
    "grype": GrypeEngine(),
    "dockle": DockleEngine(),
    "falco": FalcoEngine(),
}


def get_engine(name: str) -> Engine | None:
    return ENGINES.get(name)