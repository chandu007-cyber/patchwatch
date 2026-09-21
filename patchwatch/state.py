"""Pipeline state, committed back to the repo as sorted JSON.

Why a file in git rather than a database:
  - free, and survives runner teardown (Actions cache is evictable, so it is wrong
    for anything you must not lose)
  - every change to what the pipeline believes is a reviewable diff with an author
    and a timestamp, which is an audit trail you would otherwise have to build
  - trivially restorable by reverting a commit

Dedupe is keyed on (platform, release_key), NOT on CVE id. One CVE routinely spans
iOS, iPadOS and macOS in the same week, and each of those is a separate patch action
for a separate fleet.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field, asdict, fields
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 2


def _coerce(cls, data: dict):
    """Build a dataclass from a dict, ignoring unknown keys and filling missing ones."""
    known = {f.name for f in fields(cls)}
    return cls(**{k: v for k, v in data.items() if k in known})


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class ReleaseRecord:
    release_key: str
    platform: str
    title: str
    advisory_url: str
    release_date: str
    content_hash: str
    first_seen: str
    last_seen: str
    cve_ids: list[str] = field(default_factory=list)
    ticket_key: str | None = None
    ticket_url: str | None = None
    delivered_at: str | None = None
    # Set ONLY after the release has been written into an update document. This is
    # what prevents a release appearing in two update docs; it is written after the
    # document is produced, so a failed run re-reports rather than losing it.
    reported_at: str | None = None
    revision: int = 1          # bumped when content_hash changes (Apple retro-edits)
    notes: list[str] = field(default_factory=list)


@dataclass
class CveRecord:
    """CVE-level view, independent of which release carried it."""

    cve_id: str
    severity: str
    severity_source: str
    kev: bool = False
    exploited: bool = False
    first_seen: str = ""
    last_updated: str = ""
    platforms: list[str] = field(default_factory=list)
    alerted: bool = False       # has an urgent alert already fired for this CVE


class State:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.releases: dict[str, ReleaseRecord] = {}
        self.cves: dict[str, CveRecord] = {}
        self.meta: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            self.meta = {"schema_version": SCHEMA_VERSION, "created": utcnow()}
            return
        raw = json.loads(self.path.read_text(encoding="utf-8") or "{}")
        self.meta = raw.get("meta", {"schema_version": SCHEMA_VERSION})
        # Tolerant load: drop keys the current schema no longer has. Without this,
        # a state file written by an older version (e.g. carrying the removed
        # email_sent_at field) raises TypeError and the pipeline cannot start.
        self.releases = {
            k: _coerce(ReleaseRecord, v) for k, v in raw.get("releases", {}).items()
        }
        self.cves = {k: _coerce(CveRecord, v) for k, v in raw.get("cves", {}).items()}

    def save(self) -> None:
        """Atomic write, sorted keys, one line per CVE record.

        meta and releases stay pretty-printed - there are few of them and they are
        read by humans. The cves map is the bulk (hundreds to thousands of entries)
        and is written one record per line: ~10x smaller, and a severity change
        shows up as a single changed line in the diff.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write("{\n")
                fh.write('  "meta": ')
                fh.write(json.dumps(self.meta, indent=2, sort_keys=True).replace("\n", "\n  "))
                fh.write(",\n  \"releases\": ")
                rel = {k: asdict(v) for k, v in sorted(self.releases.items())}
                fh.write(json.dumps(rel, indent=2, sort_keys=True).replace("\n", "\n  "))
                fh.write(",\n  \"cves\": {\n")
                items = sorted(self.cves.items())
                for i, (key, rec) in enumerate(items):
                    line = json.dumps(asdict(rec), sort_keys=True, separators=(",", ":"))
                    comma = "," if i < len(items) - 1 else ""
                    fh.write(f"    {json.dumps(key)}: {line}{comma}\n")
                fh.write("  }\n}\n")
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    # -- release lifecycle ------------------------------------------------

    def classify(self, release: Any) -> str:
        """Return 'new', 'changed', or 'unchanged' for a freshly fetched release.

        'changed' is the case people forget. Apple edits published advisories to add
        CVEs days or weeks later, marking them 'Entry added'. Without a content hash
        those additions are invisible to a pipeline that only checks 'have I seen
        this release key before'.
        """
        existing = self.releases.get(release.release_key)
        if existing is None:
            return "new"
        if existing.content_hash != release.content_hash():
            return "changed"
        return "unchanged"

    def upsert_release(self, release: Any, status: str) -> ReleaseRecord:
        now = utcnow()
        key = release.release_key
        new_hash = release.content_hash()
        cve_ids = sorted({v.cve_id for v in release.vulns})

        if key in self.releases:
            rec = self.releases[key]
            if status == "changed":
                added = sorted(set(cve_ids) - set(rec.cve_ids))
                rec.revision += 1
                rec.notes.append(
                    f"{now}: advisory revised (rev {rec.revision}); "
                    f"added {', '.join(added) if added else 'no new CVEs'}"
                )
                rec.content_hash = new_hash
                rec.cve_ids = cve_ids
                rec.delivered_at = None   # force re-delivery as a ticket update
                rec.reported_at = None    # and re-report it in the next update doc
            rec.last_seen = now
        else:
            rec = ReleaseRecord(
                release_key=key,
                platform=release.platform,
                title=release.title,
                advisory_url=release.advisory_url,
                release_date=release.release_date,
                content_hash=new_hash,
                first_seen=now,
                last_seen=now,
                cve_ids=cve_ids,
            )
            self.releases[key] = rec
        return rec

    def newly_added_cves(self, release: Any) -> list[str]:
        """For a revised advisory: which CVEs were not present last time."""
        rec = self.releases.get(release.release_key)
        if rec is None:
            return sorted({v.cve_id for v in release.vulns})
        return sorted({v.cve_id for v in release.vulns} - set(rec.cve_ids))

    def pending_report(self) -> list[str]:
        """Release keys not yet written into any update document."""
        return [k for k, r in self.releases.items() if not r.reported_at]

    def mark_reported(self, release_keys: list[str]) -> None:
        stamp = utcnow()
        for key in release_keys:
            if key in self.releases:
                self.releases[key].reported_at = stamp
        self.meta["last_update_at"] = stamp

    @property
    def last_update_at(self) -> str | None:
        return self.meta.get("last_update_at")

    def mark_delivered(self, release_key: str, ticket_key: str, ticket_url: str) -> None:
        rec = self.releases.get(release_key)
        if rec:
            rec.ticket_key = ticket_key
            rec.ticket_url = ticket_url
            rec.delivered_at = utcnow()

    # -- cve lifecycle ----------------------------------------------------

    def record_cve(self, vuln: Any) -> CveRecord:
        now = utcnow()
        rec = self.cves.get(vuln.cve_id)
        if rec is None:
            rec = CveRecord(
                cve_id=vuln.cve_id,
                severity=vuln.severity,
                severity_source=vuln.severity_source,
                kev=vuln.kev,
                exploited=vuln.exploited,
                first_seen=now,
                last_updated=now,
                platforms=[vuln.platform],
            )
            self.cves[vuln.cve_id] = rec
        else:
            rec.last_updated = now
            if vuln.platform not in rec.platforms:
                rec.platforms.append(vuln.platform)
                rec.platforms.sort()
            # Severity can be revised upward as KEV/EPSS/NVD catch up. Never downward
            # automatically - a de-escalation should be a human decision.
            from .models import SEVERITY_ORDER

            if SEVERITY_ORDER.index(vuln.severity) < SEVERITY_ORDER.index(rec.severity):
                rec.severity = vuln.severity
                rec.severity_source = vuln.severity_source
            rec.kev = rec.kev or vuln.kev
            rec.exploited = rec.exploited or vuln.exploited
        return rec

    def already_alerted(self, cve_id: str) -> bool:
        rec = self.cves.get(cve_id)
        return bool(rec and rec.alerted)

    def mark_alerted(self, cve_id: str) -> None:
        if cve_id in self.cves:
            self.cves[cve_id].alerted = True

    # -- health -----------------------------------------------------------

    def prune(self, cve_retain_days: int = 180, release_retain_days: int = 400) -> dict[str, int]:
        """Drop records that no longer affect any decision.

        Two things are deliberately NEVER pruned, because losing them causes real harm
        rather than just a bigger file:
          - any CVE that has been alerted on, or is KEV / exploited. Dropping those
            resets the alert-dedupe flag and re-pages the on-call for a CVE they
            already handled.
          - any CVE still referenced by a retained release, regardless of age.

        Release records are kept far longer than the fetch window on purpose. Pruning
        a release makes it look new again on the next run, which files a duplicate
        ticket - the exact failure this state file exists to prevent.
        """
        now = datetime.now(timezone.utc)
        stats = {"cves_pruned": 0, "releases_pruned": 0}

        def age_days(stamp: str) -> float:
            try:
                return (now - datetime.fromisoformat(stamp)).days
            except (ValueError, TypeError):
                return 0.0   # unparseable -> treat as fresh, never prune on a guess

        live_release_keys = set()
        for key, rec in list(self.releases.items()):
            if age_days(rec.last_seen) > release_retain_days and rec.delivered_at:
                del self.releases[key]
                stats["releases_pruned"] += 1
            else:
                live_release_keys.add(key)

        referenced: set[str] = set()
        for key in live_release_keys:
            referenced.update(self.releases[key].cve_ids)

        for cve_id, rec in list(self.cves.items()):
            if cve_id in referenced:
                continue
            if rec.alerted or rec.kev or rec.exploited:
                continue
            if age_days(rec.last_updated) > cve_retain_days:
                del self.cves[cve_id]
                stats["cves_pruned"] += 1

        return stats

    def heartbeat(self, run_summary: dict[str, Any]) -> None:
        """Written every successful run.

        A stale heartbeat is how you notice GitHub silently disabled the schedule
        after 60 days of repo inactivity, or that cron has been quietly failing.
        Alert on this externally.
        """
        self.meta["last_successful_run"] = utcnow()
        self.meta["last_run_summary"] = run_summary
        self.meta["schema_version"] = SCHEMA_VERSION
