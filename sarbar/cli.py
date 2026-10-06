"""CLI: sarbar (aliases: cast, scan). UX layer only — all logic lives in core modules.

Commands
--------
scan       scan an image, container, Dockerfile or directory
offline    one-time: fetch the vulnerability database locally, then scan without
           network. Same as `scan --offline`, spelled as a command.
pipeline   alias of scan for CI; identical flags, exit 1 when policy fails
history    previously recorded runs
engines    which scanner binaries are available and runnable
setup      install the scanner binaries

Exit codes
----------
0  scan finished, verdict = pass
1  scan finished, verdict = fail
2  bad input, or a target that cannot be resolved (never a silent pass)
"""
from __future__ import annotations

import argparse
import os
import sys

from sarbar import __version__
from sarbar import history as hist
from sarbar import report as rep
from sarbar.engines import ENGINES
from sarbar.orchestrator import (TargetError, docker_available, list_docker_ids,
                                 run_scan, validate_target)
from sarbar.policy import BUILTIN_PROFILES, load_profile
from sarbar.history import db_path
from sarbar.target import detect_target


EXIT_OK = 0
EXIT_POLICY_FAIL = 1
EXIT_USAGE = 2

CAST_DESCRIPTION = """\
CAST — Container Automated Security Testing.

An orchestrator over existing scanners: it picks the right tool for the target,
normalises every result into one finding model, scores the risk, applies a
policy and reports a single verdict. It has no vulnerability database of its
own.

  `sarbar` is the command name; `cast` is an alias for it.
"""

EXAMPLES = """\
examples:
  sarbar scan alpine:3.19           image          static analysis
  sarbar scan nginx:latest          image          another tag or registry
  sarbar scan abc123def456          container      running container id or name
  sarbar scan ./Dockerfile          dockerfile     lint one Dockerfile
  sarbar scan .                     directory      everything under the cwd
  sarbar offline .                  directory      scan with no network, local DB

  sarbar scan . --profile ci                    stricter gates, two engines
  sarbar scan . -e trivy -ex                    force one scanner, show the plan
  sarbar scan . --format sarif -o out.sarif      report for GitHub Code Scanning
  sarbar pipeline . --profile strict             CI: exit 1 when policy fails

  sarbar offline alpine:3.19                     fetch the vuln DB once
  sarbar setup                                   install trivy and falco
  sarbar engines                                 what is available and runnable
  sarbar history --limit 10                      past runs
"""


class UsageError(Exception):
    """Bad input. Exit code 2."""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sarbar",
        description=CAST_DESCRIPTION,
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-v", "--version", action="version",
                   version=f"sarbar {__version__}", help="print version and exit")
    sub = p.add_subparsers(dest="cmd", required=True, metavar="COMMAND")

    def add_scan(sp):
        sp.add_argument("target",
                        help="image[:tag] | container-id | ./Dockerfile | ./dir")
        sp.add_argument("-p", "--profile", default="default",
                        choices=sorted(BUILTIN_PROFILES),
                        help="risk/policy profile (default: default)")
        sp.add_argument("-e", "--engine", default=None,
                        choices=sorted([*ENGINES, "none"]),
                        help="force a single scanner; 'none' = no scanner at all")
        sp.add_argument("-f", "--format", dest="fmt", default="console",
                        choices=["console", "json", "sarif", "html"],
                        help="report format (default: console)")
        sp.add_argument("-o", "--output", default=None,
                        help="write the report to a file")
        sp.add_argument("-ex", "--explain", action="store_true", dest="explain",
                        help="print why these scanners were chosen")
        sp.add_argument("--offline", action="store_true",
                        help="no network: use the locally stored database")
        sp.add_argument("--no-sudo", action="store_true",
                        help="never ask for a sudo password; scanners that need "
                             "root (falco) are skipped with a note")
        sp.add_argument("--no-history", action="store_true",
                        help="do not record this run")
        sp.add_argument("--fail-on", default=None, metavar="SPEC",
                        help="override policy thresholds, e.g. "
                             "'critical=1,high=5,secret=0,score=60,degraded=off'")

    def add_sub(name, help_text, epilog=None):
        sp = sub.add_parser(name, help=help_text,
                            epilog=epilog or EXAMPLES,
                            formatter_class=argparse.RawDescriptionHelpFormatter)
        add_scan(sp)
        return sp

    add_sub("scan", "scan an image, container, Dockerfile or directory")
    off = add_sub("offline",
            "scan with no network, using the locally stored database",
            epilog=EXAMPLES + """
offline mode:
  the first run downloads the vulnerability database; later runs need no
  network at all. A scan that cannot reach its database is reported as an
  error, never as a clean result.
""")
    # the subcommand *is* the flag: force it on
    off.set_defaults(offline=True)
    add_sub("pipeline", "CI: scan and exit 1 when the policy fails")

    hist = sub.add_parser("history", help="show previously recorded runs",
                          epilog=EXAMPLES,
                          formatter_class=argparse.RawDescriptionHelpFormatter)
    hist.add_argument("--limit", "-n", type=int, default=20,
                      help="how many runs to list, newest first (default: 20)")
    return p


def _apply_fail_on(pol, spec: str | None):
    """Parse --fail-on. Raises UsageError instead of crashing with a traceback."""
    if not spec:
        return pol
    numeric = {"critical": int, "high": int, "secret": int}
    valid = sorted([*numeric, "score", "degraded"])
    for kv in spec.split(","):
        kv = kv.strip()
        if not kv:
            continue
        if "=" not in kv:
            raise UsageError(f"--fail-on: expected key=value, got '{kv}'")
        k, v = (x.strip() for x in kv.split("=", 1))
        k = k.lower()
        if k == "score":
            try:
                pol.fail_score = float(v)
            except ValueError:
                raise UsageError(f"--fail-on: score expects a number, got '{v}'")
        elif k == "degraded":
            if v.lower() in ("off", "false", "0", "no"):
                pol.fail_on_degraded = False
            elif v.lower() in ("on", "true", "1", "yes"):
                pol.fail_on_degraded = True
            else:
                raise UsageError(f"--fail-on: degraded expects on/off, got '{v}'")
        elif k in numeric:
            try:
                setattr(pol, f"fail_on_{k}", numeric[k](v))
            except ValueError:
                raise UsageError(f"--fail-on: {k} expects an integer, got '{v}'")
        else:
            raise UsageError(
                f"--fail-on: unknown key '{k}'. Valid keys: " + ", ".join(valid))
    return pol


def _write(out: str, dest: str | None) -> None:
    if dest:
        try:
            with open(dest, "w", encoding="utf-8") as fh:
                fh.write(out)
        except OSError as ex:
            raise UsageError(f"cannot write report to {dest}: {ex}")
        print(f"Report saved to {dest}")
    else:
        print(out)


def _do_scan(args) -> int:
    pol = load_profile(args.profile, offline=args.offline)
    _apply_fail_on(pol, args.fail_on)

    target = detect_target(args.target, list_docker_ids())
    target_error: str | None = None
    try:
        validate_target(target)
    except TargetError as ex:
        target_error = str(ex)

    res = run_scan(target, pol, forced_engine=args.engine, offline=args.offline,
                   allow_sudo=not args.no_sudo, target_error=target_error)

    if args.fmt == "console":
        if args.output:
            # rich prints straight to stdout, so a file target uses plain text
            _write(rep.render_console(res, show_explain=args.explain), args.output)
        else:
            out = rep.render_console_rich(res, show_explain=args.explain)
            if out:
                print(out)
    else:
        rendered = {"json": rep.render_json, "sarif": rep.render_sarif,
                    "html": rep.render_html}[args.fmt](res)
        _write(rendered, args.output)

    if not args.no_history:
        try:
            rid = hist.save(res)
            if args.fmt == "console" and not args.output:
                print(f"(recorded run #{rid} in {db_path()})")
        except Exception as ex:
            print(f"(history save failed: {ex})", file=sys.stderr)

    if target_error:
        print(f"error: {target_error}", file=sys.stderr)
        return EXIT_USAGE
    return EXIT_POLICY_FAIL if res["verdict"] == "fail" else EXIT_OK


def main(argv: list | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        build_parser().print_help()
        return EXIT_USAGE

    # These two need their own arguments, so they are dispatched before the
    # main parser sees them.
    if argv[0] == "setup":
        from sarbar.setup import run_setup
        return run_setup(argv[1:])
    if argv[0] == "engines":
        return _cmd_engines()

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.cmd == "history":
        runs = hist.list_runs(args.limit)
        if not runs:
            print("no runs recorded yet")
        for r in runs:
            print(f"#{r['id']} {r['target']} [{r['kind']}/{r['profile']}] "
                  f"score={r['score']} verdict={r['verdict']} engines={r['engines']}")
        return EXIT_OK

    try:
        return _do_scan(args)
    except UsageError as ex:
        print(f"error: {ex}", file=sys.stderr)
        return EXIT_USAGE
    except TargetError as ex:
        print(f"error: {ex}", file=sys.stderr)
        return EXIT_USAGE


def _cmd_engines() -> int:
    print(f"{'engine':<8} {'state':<8} detail")
    from sarbar.setup import engine_status
    for name in ENGINES:
        state, detail = engine_status(name)
        print(f"{name:<8} {state:<8} {detail}")
    print()
    print(f"docker daemon: {'usable' if docker_available() else 'not usable'}")
    print(f"database cache: {_db_note()}")
    return EXIT_OK


def _db_note() -> str:
    return os.path.expanduser("~/.cache/trivy") + " (populated by `sarbar offline`)"


if __name__ == "__main__":
    raise SystemExit(main())