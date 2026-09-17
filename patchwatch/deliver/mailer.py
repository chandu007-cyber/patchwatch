"""Email delivery: one digest per run, never repeating a release.

Named mailer.py rather than email.py on purpose - a module called email.py inside
this package would shadow the stdlib email package for anything using a relative
import, and that failure is confusing to debug.

Three guarantees, each enforced in a different place:

  1. ONE EMAIL PER RUN, not one per release. Ten new releases produce one digest.
  2. AT MOST ONE EMAIL EVERY 4 HOURS. Guarded by meta.last_email_at in state, so
     it holds across manual runs and re-runs, not just the cron schedule.
  3. NO REPEATS. A release is included only if its state record has no
     email_sent_at. That is written ONLY after the SMTP send succeeds, so a failed
     send means the release is retried next run rather than lost.

Works with any SMTP server: Gmail with an app password, Office 365, SES, SendGrid,
or an internal relay.
"""

from __future__ import annotations

import os
import smtplib
import ssl
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from ..models import Release
from ..severity import explain

MIN_INTERVAL_HOURS = int(os.environ.get("EMAIL_MIN_INTERVAL_HOURS", "4"))

# CVEs listed per release in the digest. Enough to act on, few enough that a
# 172-CVE Patch Tuesday does not produce an unreadable wall of text.
MAX_CVES_LISTED = 15

SEVERITY_COLOR = {
    "CRITICAL": "#8b0000",
    "HIGH": "#c2410c",
    "MEDIUM": "#a16207",
    "LOW": "#4d7c0f",
    "UNKNOWN": "#525252",
}


class MailConfig:
    def __init__(self) -> None:
        self.host = os.environ.get("SMTP_HOST", "")
        self.port = int(os.environ.get("SMTP_PORT", "587"))
        self.user = os.environ.get("SMTP_USER", "")
        self.password = os.environ.get("SMTP_PASSWORD", "")
        self.sender = os.environ.get("EMAIL_FROM", "") or self.user
        # Comma-separated list.
        self.recipients = [
            a.strip() for a in os.environ.get("EMAIL_TO", "").split(",") if a.strip()
        ]
        self.use_ssl = os.environ.get("SMTP_SSL", "").lower() in ("1", "true", "yes")
        self.subject_prefix = os.environ.get("EMAIL_SUBJECT_PREFIX", "[patchwatch]")

    @property
    def configured(self) -> bool:
        return bool(self.host and self.sender and self.recipients)

    def describe(self) -> str:
        missing = [n for n, v in [
            ("SMTP_HOST", self.host), ("EMAIL_FROM", self.sender),
            ("EMAIL_TO", self.recipients),
        ] if not v]
        return f"missing {', '.join(missing)}" if missing else "configured"


def throttled(last_email_at: str | None, *, now: datetime | None = None) -> tuple[bool, str]:
    """Return (should_skip, reason). Independent of the cron schedule so that
    manual runs and re-runs cannot bypass the interval."""
    if not last_email_at:
        return False, "no previous email"
    now = now or datetime.now(timezone.utc)
    try:
        last = datetime.fromisoformat(last_email_at)
    except (ValueError, TypeError):
        return False, "unparseable last_email_at, sending"
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)

    elapsed = now - last
    window = timedelta(hours=MIN_INTERVAL_HOURS)
    if elapsed < window:
        remaining = window - elapsed
        mins = int(remaining.total_seconds() // 60)
        return True, f"last email {int(elapsed.total_seconds() // 60)}m ago; {mins}m until next"
    return False, f"last email {elapsed.days}d {int(elapsed.seconds // 3600)}h ago"


ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"]


def _worst(release: Release) -> str:
    return min((v.severity for v in release.vulns), key=ORDER.index, default="UNKNOWN")


def _ranked(release: Release):
    """Most severe first, exploited ahead of everything at the same level."""
    return sorted(
        release.vulns,
        key=lambda v: (not (v.exploited or v.kev), ORDER.index(v.severity), v.cve_id),
    )


def build_subject(releases: list[Release], prefix: str) -> str:
    exploited = sum(1 for r in releases for v in r.vulns if v.exploited)
    worst = min((_worst(r) for r in releases),
                key=["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"].index,
                default="UNKNOWN")
    n = len(releases)
    bits = [prefix]
    if exploited:
        bits.append(f"EXPLOITED x{exploited} -")
    bits.append(f"{worst}:")
    bits.append(f"{n} new release{'s' if n != 1 else ''}")
    platforms = sorted({r.platform for r in releases})
    bits.append(f"({', '.join(platforms)})")
    return " ".join(bits)


def _plain_body(releases: list[Release], analyses: dict[str, dict]) -> str:
    lines = [
        "patchwatch - new OS security releases",
        f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "Only releases not previously emailed are listed below.",
        "",
    ]

    urgent = [(r, v) for r in releases for v in r.vulns if v.exploited or v.kev]
    if urgent:
        lines += ["=" * 60, "ACTIVELY EXPLOITED / KEV - PATCH FIRST", "=" * 60]
        for r, v in urgent:
            due = f"  KEV due {v.kev_due_date}" if v.kev_due_date else ""
            lines.append(f"  {v.cve_id}  {r.title}{due}")
            lines.append(f"      {explain(v)}")
        lines.append("")

    for r in releases:
        worst = _worst(r)
        counts: dict[str, int] = {}
        for v in r.vulns:
            counts[v.severity] = counts.get(v.severity, 0) + 1
        breakdown = ", ".join(f"{n} {s}" for s, n in sorted(counts.items())) or "no CVE detail"

        lines += ["-" * 60, f"{r.title}   [{worst}]",
                  f"  Platform : {r.platform}",
                  f"  Released : {r.release_date}",
                  f"  CVEs     : {len(r.vulns)} ({breakdown})",
                  f"  Advisory : {r.advisory_url}"]

        if r.details_unavailable:
            lines.append("  NOTE     : vendor published no CVE detail - the list is "
                         "empty because it was NOT PUBLISHED, not because nothing was fixed")

        ranked = _ranked(r)
        if ranked:
            lines.append("")
            for v in ranked[:MAX_CVES_LISTED]:
                flag = " [EXPLOITED]" if v.exploited else (" [KEV]" if v.kev else "")
                comp = f" ({v.component})" if v.component else ""
                lines.append(f"    {v.severity:<9} {v.cve_id}{flag}{comp}")
            if len(ranked) > MAX_CVES_LISTED:
                lines.append(f"    ... and {len(ranked) - MAX_CVES_LISTED} more - "
                             "see the advisory for the full list")

        analysis = analyses.get(r.release_key, {})
        if analysis.get("summary"):
            lines += ["", "  " + analysis["summary"].replace("\n", "\n  ")]
        for rec in analysis.get("intune_recommendations", []):
            lines += ["", f"  INTUNE: {rec.get('setting_key')} = {rec.get('value')}",
                      f"          {rec.get('policy_path')}"]
        lines.append("")

    lines += ["", "--", "Sent by patchwatch. Severity is determined by deterministic "
              "rules, not by a language model.",
              "Releases already emailed are never repeated."]
    return "\n".join(lines)


def _html_body(releases: list[Release], analyses: dict[str, dict]) -> str:
    def esc(s: str) -> str:
        return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))

    parts = [
        '<html><body style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;'
        'font-size:14px;color:#111;max-width:760px">',
        '<h2 style="margin:0 0 4px">New OS security releases</h2>',
        f'<div style="color:#666;font-size:12px">'
        f'{datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")} &middot; '
        f'only releases not previously emailed</div>',
    ]

    urgent = [(r, v) for r in releases for v in r.vulns if v.exploited or v.kev]
    if urgent:
        parts.append(
            '<div style="margin:16px 0;padding:12px;border-left:4px solid #8b0000;'
            'background:#fff5f5"><b style="color:#8b0000">'
            'ACTIVELY EXPLOITED / KEV &mdash; patch first</b><ul style="margin:8px 0 0">'
        )
        for r, v in urgent:
            due = f' &middot; KEV due {esc(v.kev_due_date)}' if v.kev_due_date else ""
            parts.append(
                f'<li><code>{esc(v.cve_id)}</code> in {esc(r.title)}{due}'
                f'<br><span style="color:#666;font-size:12px">{esc(explain(v))}</span></li>'
            )
        parts.append("</ul></div>")

    for r in releases:
        worst = _worst(r)
        colour = SEVERITY_COLOR.get(worst, "#525252")
        counts: dict[str, int] = {}
        for v in r.vulns:
            counts[v.severity] = counts.get(v.severity, 0) + 1
        chips = "".join(
            f'<span style="display:inline-block;padding:1px 7px;margin-right:4px;'
            f'border-radius:9px;font-size:11px;color:#fff;'
            f'background:{SEVERITY_COLOR.get(s, "#525252")}">{n} {s}</span>'
            for s, n in sorted(counts.items())
        ) or '<span style="color:#666;font-size:12px">no CVE detail published</span>'

        parts.append(
            f'<div style="margin:18px 0;padding:14px;border:1px solid #e5e5e5;border-radius:6px">'
            f'<div style="font-size:16px;font-weight:600">{esc(r.title)} '
            f'<span style="color:{colour}">[{worst}]</span></div>'
            f'<div style="color:#666;font-size:12px;margin:2px 0 8px">'
            f'{esc(r.platform)} &middot; released {esc(r.release_date)} &middot; '
            f'{len(r.vulns)} CVEs</div><div style="margin-bottom:8px">{chips}</div>'
        )

        if r.details_unavailable:
            parts.append(
                '<div style="padding:8px;background:#fffbe6;border-left:3px solid #a16207;'
                'font-size:12px;margin-bottom:8px">The vendor published no vulnerability '
                'detail for this release. The CVE list is empty <b>because it was not '
                'published</b>, not because nothing was fixed.</div>'
            )

        ranked = _ranked(r)
        if ranked:
            rows = "".join(
                f'<tr><td style="padding:2px 10px 2px 0;white-space:nowrap">'
                f'<span style="color:{SEVERITY_COLOR.get(v.severity, "#525252")};'
                f'font-weight:600;font-size:12px">{v.severity}</span></td>'
                f'<td style="padding:2px 10px 2px 0"><code>{esc(v.cve_id)}</code>'
                + ('<b style="color:#8b0000;font-size:11px"> EXPLOITED</b>' if v.exploited
                   else ('<b style="color:#8b0000;font-size:11px"> KEV</b>' if v.kev else ''))
                + f'</td><td style="padding:2px 0;color:#666;font-size:12px">'
                f'{esc(v.component or "")}</td></tr>'
                for v in ranked[:MAX_CVES_LISTED]
            )
            more = (f'<div style="color:#666;font-size:12px;margin-top:4px">'
                    f'and {len(ranked) - MAX_CVES_LISTED} more &mdash; see the advisory</div>'
                    if len(ranked) > MAX_CVES_LISTED else "")
            parts.append(f'<table style="border-collapse:collapse;margin:8px 0">{rows}</table>{more}')

        analysis = analyses.get(r.release_key, {})
        if analysis.get("summary"):
            parts.append(f'<div style="margin:8px 0">{esc(analysis["summary"])}</div>')
        for rec in analysis.get("intune_recommendations", []):
            parts.append(
                f'<div style="margin:6px 0;padding:8px;background:#f6f8fa;font-size:12px">'
                f'<b>Intune:</b> <code>{esc(rec.get("setting_key"))}</code> = '
                f'<code>{esc(rec.get("value"))}</code><br>'
                f'<span style="color:#666">{esc(rec.get("policy_path"))}</span></div>'
            )

        parts.append(
            f'<div style="margin-top:8px"><a href="{esc(r.advisory_url)}">Vendor advisory</a></div></div>'
        )

    parts.append(
        '<div style="color:#888;font-size:11px;margin-top:20px;border-top:1px solid #eee;'
        'padding-top:8px">Sent by patchwatch. Severity is determined by deterministic '
        'rules, not by a language model. Releases already emailed are never repeated.</div>'
        '</body></html>'
    )
    return "".join(parts)


def send_digest(releases: list[Release], analyses: dict[str, dict]) -> tuple[bool, str]:
    """Send one digest. Returns (sent, detail). Never raises."""
    cfg = MailConfig()
    if not cfg.configured:
        return False, f"email not configured ({cfg.describe()})"
    if not releases:
        return False, "nothing new to report"

    msg = EmailMessage()
    msg["Subject"] = build_subject(releases, cfg.subject_prefix)
    msg["From"] = cfg.sender
    msg["To"] = ", ".join(cfg.recipients)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="patchwatch.local")
    msg.set_content(_plain_body(releases, analyses))
    msg.add_alternative(_html_body(releases, analyses), subtype="html")

    try:
        context = ssl.create_default_context()
        if cfg.use_ssl:
            with smtplib.SMTP_SSL(cfg.host, cfg.port, context=context, timeout=45) as smtp:
                if cfg.user:
                    smtp.login(cfg.user, cfg.password)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(cfg.host, cfg.port, timeout=45) as smtp:
                smtp.ehlo()
                smtp.starttls(context=context)
                smtp.ehlo()
                if cfg.user:
                    smtp.login(cfg.user, cfg.password)
                smtp.send_message(msg)
    except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
        # Caller must NOT mark these releases as emailed - they retry next run.
        return False, f"SMTP send failed: {type(exc).__name__}: {exc}"

    return True, f"sent to {len(cfg.recipients)} recipient(s)"
