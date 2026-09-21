"""CLI: sarbar (alias: cast). Only UX layer — all logic lives in core modules."""
from __future__ import annotations

import argparse
import os
import sys

from sarbar import __version__
from sarbar import history as hist
from sarbar import report as rep
from sarbar.engines import ENGINES
from sarbar.orchestrator import list_docker_ids, run_scan
from sarbar.policy import BUILTIN_PROFILES, load_profile
from sarbar.target import detect_target


EXAMPLES = """examples:
  sarbar scan alpine:3.19            scan an image (static analysis)
  sarbar scan abc123def456           scan a running container (runtime + image link)
  sarbar scan ./Dockerfile           lint a Dockerfile (+ dockle if installed)
  sarbar scan ./app                  scan a directory (fs vulns + secret search)
  sarbar scan nginx:latest --profile ci
  sarbar pipeline ./app              CI shortcut: exit 1 when policy fails
  sarbar scan ./app --engine trivy --explain
  sarbar scan ./app --offline        no network: builtin checks + marked mock data
  sarbar history --limit 10
  sarbar engines
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sarbar",
                                description="CAST — Container Automated Security Testing (orchestrator + policy + report)",
                                epilog=EXAMPLES,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"sarbar {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_scan(sp):
        sp.add_argument("target", help="image[:tag] | <container-id> | ./Dockerfile | ./app-dir")
        sp.add_argument("--profile", default="default", choices=sorted(BUILTIN_PROFILES),
                        help="risk/policy profile (default: default)")
        sp.add_argument("--engine", default=None, choices=sorted([*ENGINES, "none"]),
                        help="aggregator mode: force one engine, report/policy stay ours")
        sp.add_argument("--format", dest="fmt", default="console",
                        choices=["console", "json", "sarif", "html"])
        sp.add_argument("-o", "--output", default=None, help="write report to file")
        sp.add_argument("--offline", action="store_true", help="no network: local engines + cast-checks only")
        sp.add_argument("--no-cast-checks", action="store_true", help="disable own cast-checks")
        sp.add_argument("--explain", action="store_true", help="show why these engines were chosen")
        sp.add_argument("--no-history", action="store_true", help="do not save run to local history")
        sp.add_argument("--fail-on", default=None,
                        help="override policy, e.g. 'critical=1,high=5,score=60' (for CI)")

    s = sub.add_parser("scan", help="scan an image, container, Dockerfile or directory",
                       epilog=EXAMPLES,
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    add_scan(s)
    # `cast scan ...` compat: binary alias handles it; keep `pipeline` as CI shortcut
    pl = sub.add_parser("pipeline", help="CI shortcut: scan fs dir / Dockerfile, exit 1 on policy fail",
                        epilog=EXAMPLES,
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    add_scan(pl)

    h = sub.add_parser("history", help="show local scan history")
    h.add_argument("--limit", type=int, default=20)

    e = sub.add_parser("engines", help="list engine adapters and availability")
    e.add_argument("--offline", action="store_true", help="show offline plan")

    return p


def _apply_fail_on(pol, spec: str | None):
    if not spec:
        return pol
    for kv in spec.split(","):
        if "=" not in kv:
            continue
        k, v = kv.split("=", 1)
        k, v = k.strip(), float(v.strip())
        if k == "critical":
            pol.fail_on_critical = int(v)
        elif k == "high":
            pol.fail_on_high = int(v)
        elif k == "score":
            pol.fail_score = v
    return pol


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    parser = build_parser()
    if not argv:
        # bare `sarbar`: show full help instead of a one-line argparse error
        parser.print_help()
        return 2
    args = parser.parse_args(argv)

    if args.cmd == "history":
        for r in hist.list_runs(args.limit):
            print(f"#{r['id']} {r['target']} [{r['kind']}/{r['profile']}] "
                  f"score={r['score']} verdict={r['verdict']} engines={r['engines']}")
        return 0

    if args.cmd == "engines":
        for name, eng in ENGINES.items():
            print(f"{name:<8} available={'yes' if eng.is_available() else 'no (fallback/mock offline)'}")
        print("cast-checks  available=yes (builtin, always offline-capable)")
        return 0

    # scan / pipeline
    target = detect_target(args.target, list_docker_ids())
    if args.cmd == "pipeline" and target.kind.value == "image" and os.path.exists(args.target):
        pass
    pol = load_profile(args.profile, offline=args.offline)
    _apply_fail_on(pol, args.fail_on)
    res = run_scan(target, pol, forced_engine=args.engine, offline=args.offline,
                   no_cast_checks=args.no_cast_checks)

    out = {"console": rep.render_console(res, show_explain=args.explain),
           "json": rep.render_json(res),
           "sarif": rep.render_sarif(res),
           "html": rep.render_html(res)}[args.fmt]
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
    else:
        print(out)

    if not args.no_history:
        try:
            rid = hist.save(res)
            if args.fmt == "console":
                print(f"(saved run #{rid} to ~/.sarbar/history.db)")
        except Exception as ex:
            print(f"(history save failed: {ex})", file=sys.stderr)

    return 1 if res["verdict"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
