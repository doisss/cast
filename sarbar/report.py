"""Reporters: one UX whatever the engine. console / json / sarif / html.

Every field that originates outside sarbar (package names, scanner titles, target
paths) is escaped before it reaches HTML (SPEC.md I-7).
"""
from __future__ import annotations

import datetime
import html
import json


SEV_COLOR = {
    "CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
    "LOW": "blue", "INFO": "dim", "UNKNOWN": "dim",
}

SEV_CSS = {
    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
    "LOW": "low", "INFO": "info", "UNKNOWN": "info",
}

SARIF_LEVEL = {
    "CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
    "LOW": "note", "INFO": "note", "UNKNOWN": "note",
}


def _where(f) -> str:
    """Primary location for a finding, if the check recorded one."""
    return f.locations[0] if getattr(f, "locations", None) else ""


def _occurrence_suffix(f) -> str:
    n = getattr(f, "occurrences", 1)
    return f"  (x{n} locations)" if n > 1 else ""


# --------------------------------------------------------------------------
# console
# --------------------------------------------------------------------------

def render_console(res: dict, show_explain: bool = False) -> str:
    L: list[str] = []
    L.append(f"sarbar scan {res['target']}  (kind={res['target_kind']}, profile={res['profile']})")
    if show_explain:
        L.append(f"plan: {res['plan']['why']}")
    if res.get("image_ref"):
        L.append(f"container -> image: {res['image_ref']}")
    engines = ", ".join(res["scanners_used"]) or "(none)"
    L.append(f"scanners: {engines}" + ("  [DEGRADED]" if res.get("degraded") else ""))
    L.append(f"risk: {res['risk']['score']} ({res['risk']['level']})  verdict: {res['verdict'].upper()}")
    counts = res["risk"]["counts"]
    if counts:
        L.append("counts: " + " ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    L.append("-" * 100)
    findings = res["findings"]
    if not findings:
        L.append("No findings.")
    for f in findings:
        pkg = f"{f.package}:{f.installed_version}" if f.package else "-"
        loc = _where(f)
        L.append(f"{f.severity:<8} {f.check_id:<24} {pkg:<30} {(f.fixed_version or '-'):<16} "
                 f"[{','.join(f.engines_seen)}] {f.title}{_occurrence_suffix(f)}")
        if loc:
            L.append(f"{'':.<8} at {loc}")
    L.append("-" * 100)
    L.append("risk reasons: " + ("; ".join(res["risk"]["reasons"]) or "-"))
    L.append("policy: " + "; ".join(res["policy_reasons"]))
    for w in res.get("warnings") or []:
        L.append(f"warning: {w}")
    for d in res.get("diagnostics") or []:
        L.append(f"diagnostic: {d}")
    return "\n".join(L)


def render_console_rich(res: dict, show_explain: bool = False) -> str:
    """Rich console output. Falls back to plain text when rich is absent.

    Prints directly to stdout and returns "" so the CLI does not double-print.
    """
    try:
        from rich import box
        from rich.console import Console
        from rich.table import Table
    except ImportError:
        return render_console(res, show_explain)

    console = Console()

    header = Table(box=box.ROUNDED, show_header=False, expand=True)
    header.add_column("Key", style="cyan")
    header.add_column("Value", style="white")
    header.add_row("Target", f"[bold]{res['target']}[/bold]")
    header.add_row("Kind", res["target_kind"])
    header.add_row("Profile", res["profile"])
    if res.get("image_ref"):
        header.add_row("Container -> Image", res["image_ref"])
    header.add_row("Scanners", ", ".join(res["scanners_used"]) or "(none)")
    header.add_row("Mode", "[yellow]DEGRADED — no external scanner produced results[/yellow]"
                   if res.get("degraded") else "[green]normal[/green]")
    header.add_row("Risk", f"[bold]{res['risk']['score']}[/bold] ({res['risk']['level']})")
    header.add_row("Verdict", f"[bold]{'FAIL' if res['verdict'] == 'fail' else 'PASS'}[/bold]")
    console.print(header)

    if show_explain:
        console.print(f"\n[cyan]Plan:[/cyan] {res['plan']['why']}")

    counts = res["risk"]["counts"]
    if counts:
        console.print("\n[cyan]Counts:[/cyan] " +
                      "  ".join(f"[bold]{k}[/bold]={v}" for k, v in sorted(counts.items())))

    findings = res["findings"]
    if not findings:
        console.print("\n[green]No findings.[/green]")
    else:
        table = Table(box=box.SIMPLE_HEAD, expand=True, show_lines=False)
        table.add_column("Severity", style="bold", width=10)
        table.add_column("ID", width=24)
        table.add_column("Package", width=26)
        table.add_column("Fixed", width=14)
        table.add_column("Scanners", width=14)
        table.add_column("Title", overflow="fold")
        for f in findings:
            color = SEV_COLOR.get(f.severity, "white")
            pkg = f"{f.package}:{f.installed_version}" if f.package else "-"
            table.add_row(
                f"[{color}]{f.severity}[/{color}]",
                f.check_id,
                pkg,
                f.fixed_version or "-",
                ",".join(f.engines_seen),
                f.title + _occurrence_suffix(f),
            )
        console.print(table)

    if res["risk"]["reasons"]:
        console.print(f"\n[cyan]Risk reasons:[/cyan] {'; '.join(res['risk']['reasons'])}")
    console.print(f"[cyan]Policy:[/cyan] {'; '.join(res['policy_reasons'])}")

    for w in res.get("warnings") or []:
        console.print(f"[yellow]warning:[/yellow] {w}")
    for d in res.get("diagnostics") or []:
        console.print(f"[dim]diagnostic: {d}[/dim]")
    return ""


# --------------------------------------------------------------------------
# structured formats
# --------------------------------------------------------------------------

def to_dict(res: dict) -> dict:
    return {
        "tool": "sarbar",
        "version": _version(),
        "scanned_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "target": res["target"],
        "target_kind": res["target_kind"],
        "image_ref": res.get("image_ref"),
        "profile": res["profile"],
        "plan": res["plan"],
        "scanners_used": res["scanners_used"],
        "scanner_status": res.get("scanner_status", {}),
        "degraded": res.get("degraded", False),
        "offline": res.get("offline", False),
        "coverage": res.get("coverage", {}),
        "diagnostics": res.get("diagnostics", []),
        "warnings": res.get("warnings", []),
        "risk": res["risk"],
        "verdict": res["verdict"],
        "policy_reasons": res["policy_reasons"],
        "findings": [f.to_dict() for f in res["findings"]],
    }


def _version() -> str:
    try:
        from sarbar import __version__
        return __version__
    except Exception:
        return "unknown"


def render_json(res: dict) -> str:
    return json.dumps(to_dict(res), indent=2, ensure_ascii=False)


def render_sarif(res: dict) -> str:
    """SARIF 2.1.0.

    rules[] is deduplicated by rule id: emitting one rule per finding produced
    `uniqueItems` violations on the official schema as soon as two packages
    shared a CVE, which GitHub Code Scanning rejects (SPEC.md I-8).
    """
    rules: list[dict] = []
    rule_index: dict[str, int] = {}
    results: list[dict] = []

    for f in res["findings"]:
        if f.check_id not in rule_index:
            rule_index[f.check_id] = len(rules)
            rules.append({
                "id": f.check_id,
                "name": f.check_id,
                "shortDescription": {"text": f.title[:200]},
                "properties": {"severity": f.severity, "category": f.category,
                               "engines": sorted(f.engines_seen)},
            })
        msg = f.title
        if f.package:
            msg += f" ({f.package} {f.installed_version})".rstrip()
        result = {
            "ruleId": f.check_id,
            "ruleIndex": rule_index[f.check_id],
            "level": SARIF_LEVEL.get(f.severity, "note"),
            "message": {"text": msg},
            "properties": {
                "engine": ",".join(f.engines_seen) or f.engine,
                "cvss": f.cvss,
                "target": f.target,
                "occurrences": f.occurrences,
            },
        }
        loc = _where(f)
        if loc:
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": loc},
                    "region": {"startLine": 1},
                }
            }]
        results.append(result)

    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "sarbar",
                "informationUri": "https://github.com/doisss/cast",
                "version": _version(),
                "rules": rules,
            }},
            "results": results,
        }],
    }, indent=2, ensure_ascii=False)


# --------------------------------------------------------------------------
# html
# --------------------------------------------------------------------------

def _e(value) -> str:
    """HTML-escape any value, quotes included."""
    return html.escape("" if value is None else str(value), quote=True)


def render_html(res: dict) -> str:
    rows = []
    for f in res["findings"]:
        rows.append(
            "<tr class='{cls}'>"
            "<td><span class='sev sev-{cls}'>{sev}</span></td>"
            "<td>{cid}</td>"
            "<td>{pkg}</td>"
            "<td>{fix}</td>"
            "<td>{eng}</td>"
            "<td>{title}{occ}{loc}</td>"
            "</tr>".format(
                cls=SEV_CSS.get(f.severity, "info"),
                sev=_e(f.severity),
                cid=_e(f.check_id),
                pkg=_e(f"{f.package} {f.installed_version}".strip() or "-"),
                fix=_e(f.fixed_version or "-"),
                eng=_e(",".join(f.engines_seen)),
                title=_e(f.title),
                occ=_e(f" (x{f.occurrences})" if f.occurrences > 1 else ""),
                loc=_e(f"<br><small>{_where(f)}</small>" if _where(f) else ""),
            )
        )
    rows_html = "".join(rows) or "<tr><td colspan='6'>No findings.</td></tr>"

    counts = res["risk"]["counts"]
    cards = "".join(
        "<div class='card'><div class='card-num'>{v}</div>"
        "<div class='card-label'>{k}</div></div>".format(v=_e(v), k=_e(k))
        for k, v in sorted(counts.items())
    )

    degraded = bool(res.get("degraded"))
    verdict_class = "fail" if res["verdict"] == "fail" else "pass"
    verdict_text = "FAIL" if res["verdict"] == "fail" else "PASS"

    notes = ""
    if degraded:
        notes += ("<div class='note note-fail'><b>DEGRADED RUN.</b> No external "
                  "scanner produced results, so nothing was actually analysed.</div>")
    for w in res.get("warnings") or []:
        notes += f"<div class='note'>{_e(w)}</div>"
    if res.get("diagnostics"):
        diag = "".join(f"<li>{_e(d)}</li>" for d in res["diagnostics"])
        notes += f"<details><summary>Diagnostics ({len(res['diagnostics'])})</summary><ul>{diag}</ul></details>"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>sarbar report — {_e(res['target'])}</title>
<style>
:root {{
  --bg: #0f1117; --card: #1a1d27; --border: #2a2d3a; --text: #e1e4eb;
  --muted: #8b8fa3; --critical: #ff4757; --high: #ff6348; --medium: #ffa502;
  --low: #70a1ff; --info: #a4b0be; --pass: #2ed573; --fail: #ff4757;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: var(--bg); color: var(--text); padding: 2em; line-height: 1.6;
}}
.container {{ max-width: 1200px; margin: 0 auto; }}
h1 {{ font-size: 1.8em; margin-bottom: 0.3em; }}
.subtitle {{ color: var(--muted); margin-bottom: 1.5em; word-break: break-all; }}
.meta, .cards {{ display: flex; gap: 1em; flex-wrap: wrap; margin-bottom: 1.5em; }}
.meta-item, .card {{
  background: var(--card); border: 1px solid var(--border); border-radius: 8px;
  padding: 0.5em 1em;
}}
.meta-item .label, .card-label {{ color: var(--muted); font-size: 0.8em; }}
.card {{ padding: 1em 1.5em; text-align: center; min-width: 100px; }}
.card-num {{ font-size: 2em; font-weight: 700; }}
.card-label {{ text-transform: uppercase; }}
.verdict {{
  display: inline-block; padding: 0.4em 1em; border-radius: 6px;
  font-weight: 700; font-size: 1.1em; margin-bottom: 1em;
}}
.verdict.pass {{ background: rgba(46,213,115,.15); color: var(--pass); border: 1px solid var(--pass); }}
.verdict.fail {{ background: rgba(255,71,87,.15); color: var(--fail); border: 1px solid var(--fail); }}
.note {{
  background: var(--card); border: 1px solid var(--border); border-left: 3px solid var(--medium);
  border-radius: 6px; padding: 0.75em 1em; margin-bottom: 0.75em;
}}
.note-fail {{ border-left-color: var(--fail); }}
details {{ margin-bottom: 1em; color: var(--muted); }}
table {{ width: 100%; border-collapse: collapse; background: var(--card);
        border-radius: 8px; overflow: hidden; }}
th {{ background: var(--border); padding: .75em 1em; text-align: left;
      font-size: .85em; text-transform: uppercase; color: var(--muted); }}
td {{ padding: .6em 1em; border-bottom: 1px solid var(--border); vertical-align: top; }}
tr:last-child td {{ border-bottom: none; }}
tr:hover {{ background: rgba(255,255,255,.03); }}
.sev {{ display: inline-block; padding: .15em .5em; border-radius: 4px;
        font-size: .8em; font-weight: 700; }}
.sev-critical {{ background: rgba(255,71,87,.2); color: var(--critical); }}
.sev-high {{ background: rgba(255,99,72,.2); color: var(--high); }}
.sev-medium {{ background: rgba(255,165,2,.2); color: var(--medium); }}
.sev-low {{ background: rgba(112,161,255,.2); color: var(--low); }}
.sev-info {{ background: rgba(164,176,190,.2); color: var(--info); }}
.risk-bar {{ background: var(--card); border: 1px solid var(--border);
             border-radius: 8px; padding: 1em 1.5em; margin-bottom: 1.5em; }}
.risk-score {{ font-size: 2.5em; font-weight: 700; }}
.risk-level {{ color: var(--muted); font-size: .5em; }}
.reasons {{ margin-top: .5em; color: var(--muted); font-size: .9em; }}
small {{ color: var(--muted); }}
</style>
</head>
<body>
<div class="container">
  <h1>sarbar report</h1>
  <p class="subtitle">Target: <strong>{_e(res['target'])}</strong> &middot;
     Kind: {_e(res['target_kind'])} &middot; Profile: {_e(res['profile'])}</p>

  <div class="meta">
    <div class="meta-item"><div class="label">Scanners</div>
      <div class="value">{_e(', '.join(res['scanners_used']) or '-')}</div></div>
    <div class="meta-item"><div class="label">Degraded</div>
      <div class="value">{'yes' if degraded else 'no'}</div></div>
    <div class="meta-item"><div class="label">Scanned (UTC)</div>
      <div class="value">{_e(datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M'))}</div></div>
  </div>

  <div class="cards">{cards}</div>
  <div class="verdict {verdict_class}">{verdict_text}</div>

  <div class="risk-bar">
    <div class="risk-score">{_e(res['risk']['score'])}
      <span class="risk-level">/ 100 ({_e(res['risk']['level'])})</span></div>
    <div class="reasons">{_e(' &middot; '.join(res['risk']['reasons']) or 'No risk factors')}</div>
  </div>

  {notes}

  <table>
    <thead><tr><th>Severity</th><th>ID</th><th>Package</th><th>Fixed</th>
      <th>Scanners</th><th>Title</th></tr></thead>
    <tbody>{rows_html}</tbody>
  </table>
</div>
</body>
</html>"""