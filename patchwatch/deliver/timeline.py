"""Append-only patch timeline, rendered to Word.

Replaces email entirely. No SMTP, no tenant auth, no credentials, nothing to expire.

How "append" works: every run appends entries to reports/history.json, then the
.docx is REGENERATED IN FULL from that history. The JSON is the source of truth and
the Word file is a rendering of it. That means:

  - no risk of corrupting the document by editing its XML in place
  - the timeline can be restyled later without losing history
  - history.json diffs cleanly in git, so you can see what each run added
  - deleting the .docx is harmless; the next run rebuilds it

Deduplication reuses the same machinery as the email digest: a release appears in
the timeline once, keyed on release_key, unless its advisory was revised - in which
case it appears again as a revision entry, which is a real event and not a repeat.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from ..models import Release
from ..severity import explain
from . import ooxml as ox

SEVERITY_COLOR = {
    "CRITICAL": "8B0000",
    "HIGH": "C2410C",
    "MEDIUM": "A16207",
    "LOW": "4D7C0F",
    "UNKNOWN": "525252",
}
SEVERITY_FILL = {
    "CRITICAL": "FDE8E8",
    "HIGH": "FEF0E7",
    "MEDIUM": "FEF9E7",
    "LOW": "F1F8E9",
    "UNKNOWN": "F5F5F5",
}
ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"]
MAX_CVES_PER_RELEASE = 25


def _worst(vulns) -> str:
    return min((v.severity for v in vulns), key=ORDER.index, default="UNKNOWN")


# ---------------------------------------------------------------- history


def load_history(path: str | Path) -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text(encoding="utf-8")).get("entries", [])
    except (json.JSONDecodeError, OSError):
        return []


def save_history(path: str | Path, entries: list[dict]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps({"entries": entries}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def entry_from_release(release: Release, status: str, analysis: dict) -> dict:
    """Flatten a release into a timeline entry. Stored, not recomputed, so the
    timeline remains an accurate record of what was known AT THE TIME - later
    severity revisions do not silently rewrite history."""
    vulns = sorted(
        release.vulns,
        key=lambda v: (not (v.exploited or v.kev), ORDER.index(v.severity), v.cve_id),
    )
    return {
        "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "release_key": release.release_key,
        "status": status,
        "platform": release.platform,
        "title": release.title,
        "version": release.version,
        "release_date": release.release_date,
        "advisory_url": release.advisory_url,
        "details_unavailable": release.details_unavailable,
        "worst": _worst(release.vulns),
        "cve_count": len(release.vulns),
        "exploited_count": sum(1 for v in release.vulns if v.exploited),
        "kev_count": sum(1 for v in release.vulns if v.kev),
        "cves": [
            {
                "id": v.cve_id,
                "severity": v.severity,
                "component": v.component or "",
                "exploited": v.exploited,
                "kev": v.kev,
                "kev_due": v.kev_due_date,
                "basis": explain(v),
            }
            for v in vulns[:MAX_CVES_PER_RELEASE]
        ],
        "cves_truncated": max(0, len(vulns) - MAX_CVES_PER_RELEASE),
        "intune": analysis.get("intune_recommendations", []),
        "summary": analysis.get("summary", ""),
        "degraded": bool(analysis.get("_degraded")),
    }


def append_entries(history: list[dict], new_entries: list[dict]) -> tuple[list[dict], int]:
    """Skip anything already recorded for the same release at the same revision.

    Keyed on (release_key, status, cve_count) rather than release_key alone, so a
    revised advisory that gained CVEs is recorded as a new event while a re-run
    that found nothing new is not.
    """
    seen = {(e["release_key"], e.get("status"), e.get("cve_count")) for e in history}
    added = 0
    for entry in new_entries:
        key = (entry["release_key"], entry.get("status"), entry.get("cve_count"))
        if key in seen:
            continue
        history.append(entry)
        seen.add(key)
        added += 1
    history.sort(key=lambda e: (e["recorded_at"], e["release_key"]))
    return history, added


# ---------------------------------------------------------------- rendering


def _cve_table(entry: dict) -> str:
    rows = [[
        ox.run("Severity", bold=True), ox.run("CVE", bold=True),
        ox.run("Component", bold=True), ox.run("Basis", bold=True),
    ]]
    shading: list[list[str | None]] = [[None] * 4]

    for c in entry["cves"]:
        flag = " EXPLOITED" if c["exploited"] else (" KEV" if c["kev"] else "")
        due = f' (due {c["kev_due"]})' if c.get("kev_due") else ""
        rows.append([
            ox.run(c["severity"], bold=True, color=SEVERITY_COLOR.get(c["severity"], "525252")),
            ox.run(c["id"], mono=True) + (
                ox.run(flag + due, bold=True, color="8B0000", size=15) if flag else ""),
            ox.run(c["component"] or "-"),
            ox.run(c["basis"], size=16, color="666666"),
        ])
        shading.append([SEVERITY_FILL.get(c["severity"]), None, None, None])

    return ox.table(rows, widths=[1150, 2350, 2250, 4300], shading=shading)


def _entry_block(entry: dict) -> str:
    parts = [
        ox.para([
            ox.run(entry["title"], bold=True),
            ox.run("   "),
            ox.run(f'[{entry["worst"]}]', bold=True,
                   color=SEVERITY_COLOR.get(entry["worst"], "525252")),
        ], style="Heading3"),
        ox.para([
            ox.run(f'{entry["platform"]}  |  released {entry["release_date"]}'
                   f'  |  {entry["cve_count"]} CVEs'),
            ox.run(f'  |  {entry["exploited_count"]} exploited'
                   if entry["exploited_count"] else ""),
            ox.run("  |  ADVISORY REVISED" if entry.get("status") == "changed" else ""),
        ], style="Meta"),
    ]

    if entry.get("details_unavailable"):
        parts.append(ox.para([
            ox.run("Vendor published no CVE detail. The list below is empty because it "
                   "was NOT PUBLISHED, not because nothing was fixed.",
                   italic=True, color="A16207"),
        ]))

    if entry.get("degraded"):
        parts.append(ox.para([
            ox.run("Automated analysis was rejected by the validator; Intune mapping "
                   "needs manual review.", italic=True, color="8B0000"),
        ]))

    if entry.get("summary"):
        parts.append(ox.para(entry["summary"]))

    if entry["cves"]:
        parts.append(_cve_table(entry))
        if entry.get("cves_truncated"):
            parts.append(ox.para([
                ox.run(f'... and {entry["cves_truncated"]} further CVEs - see the advisory.',
                       italic=True, color="666666", size=16)]))

    for rec in entry.get("intune", []):
        parts.append(ox.para([
            ox.run("Intune:  ", bold=True),
            ox.run(f'{rec.get("setting_key")} = {rec.get("value")}', mono=True),
        ]))
        parts.append(ox.para([ox.run(rec.get("policy_path", ""), size=16, color="666666")]))

    parts.append(ox.para([ox.run(entry["advisory_url"], size=16, color="1155CC")]))
    parts.append(ox.para("", border_bottom=True))
    return "".join(parts)


def render(history: list[dict], out_path: str | Path, *, title: str = "OS Security Patch Timeline") -> Path:
    now = datetime.now(timezone.utc)
    body = [
        ox.para(title, style="Title"),
        ox.para([ox.run(f'Generated {now.strftime("%d %B %Y %H:%M UTC")}  |  '
                        f'{len(history)} entries recorded', color="666666")], style="Meta"),
        ox.para("", border_bottom=True),
    ]

    # ---- summary ----
    if history:
        totals = defaultdict(int)
        platforms = defaultdict(int)
        exploited = 0
        for e in history:
            totals[e["worst"]] += 1
            platforms[e["platform"]] += 1
            exploited += e.get("exploited_count", 0)

        body.append(ox.para("Summary", style="Heading1"))
        rows = [[ox.run("Metric", bold=True), ox.run("Value", bold=True)]]
        rows.append([ox.run("Releases recorded"), ox.run(str(len(history)))])
        rows.append([ox.run("Exploited CVEs seen"),
                     ox.run(str(exploited), bold=True,
                            color="8B0000" if exploited else "525252")])
        for sev in ORDER:
            if totals.get(sev):
                rows.append([ox.run(f"Releases at {sev}"), ox.run(str(totals[sev]))])
        for plat in sorted(platforms):
            rows.append([ox.run(f"Releases - {plat}"), ox.run(str(platforms[plat]))])
        body.append(ox.table(rows, widths=[5000, 5050]))

    # ---- timeline, newest first ----
    body.append(ox.para("Timeline", style="Heading1"))
    if not history:
        body.append(ox.para("No releases recorded yet."))
    else:
        by_day: dict[str, list[dict]] = defaultdict(list)
        for e in history:
            by_day[e["recorded_at"][:10]].append(e)

        for day in sorted(by_day, reverse=True):
            entries = sorted(by_day[day],
                             key=lambda e: (ORDER.index(e["worst"]), e["title"]))
            pretty = datetime.strptime(day, "%Y-%m-%d").strftime("%A, %d %B %Y")
            body.append(ox.para(pretty, style="Heading2"))
            body.append(ox.para([
                ox.run(f'{len(entries)} release'
                       f'{"s" if len(entries) != 1 else ""} recorded', color="666666")],
                style="Meta"))
            for entry in entries:
                body.append(_entry_block(entry))

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    ox.write_docx(str(out), "".join(body))
    return out
