"""Interval gating, read from state rather than inferred from the cron schedule.

Cron cannot express a true 10-hour cycle: "0 */10 * * *" fires at 00:00, 10:00 and
20:00, then the field resets at midnight, so the last gap of the day is 4 hours, not
10. The workflow therefore runs more often than needed and this gate decides whether
a run actually produces an update.

Reading the last-update time from state (rather than trusting the schedule) also
means manual runs, re-runs and GitHub's own cron delays cannot bypass the interval.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


def due(last_at: str | None, interval_hours: float, *, now: datetime | None = None) -> tuple[bool, str]:
    """Return (should_run, reason)."""
    if not last_at:
        return True, "no previous update recorded"

    now = now or datetime.now(timezone.utc)
    try:
        last = datetime.fromisoformat(last_at)
    except (ValueError, TypeError):
        # Fail open. A corrupt timestamp must never silently suppress patch alerting.
        return True, "unparseable last-update timestamp, proceeding"

    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)

    elapsed = now - last
    window = timedelta(hours=interval_hours)
    if elapsed < window:
        mins_left = int((window - elapsed).total_seconds() // 60)
        return False, (f"last update {int(elapsed.total_seconds() // 60)}m ago; "
                       f"{mins_left}m until the next is due")

    hours = elapsed.total_seconds() / 3600
    return True, f"last update {hours:.1f}h ago"
