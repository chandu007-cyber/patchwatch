"""Email digest: throttle, dedupe, and failure handling."""
import sys, tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import unittest
from unittest import mock

from patchwatch.deliver import mailer
from patchwatch.models import Release, Vuln
from patchwatch.state import State


def rel(key="26.6.1", platform="ios", exploited=False):
    return Release(platform=platform, product="iOS and iPadOS", version=key,
                   release_date="2026-08-20", advisory_url="https://x",
                   vulns=[Vuln(cve_id="CVE-2026-1001", platform=platform,
                               severity="CRITICAL", exploited=exploited, kev=exploited)])


def ago(hours):
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="seconds")


class TestThrottle(unittest.TestCase):
    def test_first_email_always_allowed(self):
        skip, _ = mailer.throttled(None)
        self.assertFalse(skip)

    def test_blocked_within_four_hours(self):
        for h in [0, 1, 3.9]:
            skip, why = mailer.throttled(ago(h))
            self.assertTrue(skip, f"{h}h should be throttled: {why}")

    def test_allowed_after_four_hours(self):
        skip, _ = mailer.throttled(ago(4.1))
        self.assertFalse(skip)

    def test_unparseable_timestamp_sends_rather_than_blocks(self):
        """Fail open: a corrupt timestamp must not silently suppress alerting."""
        skip, _ = mailer.throttled("not-a-date")
        self.assertFalse(skip)

    def test_naive_timestamp_handled(self):
        naive = (datetime.now() - timedelta(hours=1)).isoformat(timespec="seconds")
        skip, _ = mailer.throttled(naive)
        self.assertTrue(skip)


class TestNoRepeats(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.s = State(Path(self.tmp.name) / "state.json")

    def tearDown(self):
        self.tmp.cleanup()

    def test_new_release_is_pending(self):
        self.s.upsert_release(rel(), "new")
        self.assertEqual(len(self.s.pending_email()), 1)

    def test_marked_release_not_resent(self):
        r = rel()
        self.s.upsert_release(r, "new")
        self.s.mark_emailed([r.release_key])
        self.assertEqual(self.s.pending_email(), [])

    def test_mark_emailed_sets_global_timestamp(self):
        r = rel()
        self.s.upsert_release(r, "new")
        self.s.mark_emailed([r.release_key])
        self.assertIsNotNone(self.s.last_email_at)

    def test_revised_advisory_is_re_emailed(self):
        """Apple adds CVEs to published advisories. That must reopen the email."""
        r1 = rel()
        self.s.upsert_release(r1, "new")
        self.s.mark_emailed([r1.release_key])

        r2 = rel()
        r2.vulns.append(Vuln(cve_id="CVE-2026-1002", platform="ios", severity="HIGH"))
        self.assertEqual(self.s.classify(r2), "changed")
        self.s.upsert_release(r2, "changed")
        self.assertEqual(self.s.pending_email(), [r2.release_key])

    def test_survives_reload(self):
        r = rel()
        self.s.upsert_release(r, "new")
        self.s.mark_emailed([r.release_key])
        self.s.save()
        reloaded = State(self.s.path)
        self.assertEqual(reloaded.pending_email(), [])
        self.assertIsNotNone(reloaded.last_email_at)


class TestSend(unittest.TestCase):
    ENV = {"SMTP_HOST": "smtp.example.com", "SMTP_PORT": "587",
           "SMTP_USER": "u", "SMTP_PASSWORD": "p",
           "EMAIL_FROM": "patchwatch@example.com",
           "EMAIL_TO": "sec@example.com, ops@example.com"}

    def test_unconfigured_reports_what_is_missing(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            sent, detail = mailer.send_digest([rel()], {})
        self.assertFalse(sent)
        self.assertIn("SMTP_HOST", detail)

    def test_empty_release_list_sends_nothing(self):
        with mock.patch.dict("os.environ", self.ENV, clear=True):
            sent, detail = mailer.send_digest([], {})
        self.assertFalse(sent)
        self.assertIn("nothing new", detail)

    def test_successful_send(self):
        with mock.patch.dict("os.environ", self.ENV, clear=True), \
             mock.patch("smtplib.SMTP") as smtp:
            sent, detail = mailer.send_digest([rel()], {})
        self.assertTrue(sent, detail)
        self.assertTrue(smtp.return_value.__enter__.return_value.send_message.called)

    def test_smtp_failure_returns_false_so_caller_retries(self):
        """Must not raise, and must not report success - otherwise the release is
        marked emailed and silently never sent."""
        import smtplib as s
        with mock.patch.dict("os.environ", self.ENV, clear=True), \
             mock.patch("smtplib.SMTP", side_effect=s.SMTPAuthenticationError(535, b"bad")):
            sent, detail = mailer.send_digest([rel()], {})
        self.assertFalse(sent)
        self.assertIn("SMTP send failed", detail)

    def test_subject_flags_exploited(self):
        subject = mailer.build_subject([rel(exploited=True)], "[patchwatch]")
        self.assertIn("EXPLOITED", subject)
        self.assertIn("CRITICAL", subject)

    def test_body_contains_advisory_and_cve(self):
        body = mailer._plain_body([rel()], {})
        self.assertIn("CVE-2026-1001", body)
        self.assertIn("https://x", body)

    def test_detail_unavailable_stated_in_body(self):
        r = Release(platform="android", product="Android Security Bulletin",
                    version="2026-08-01", release_date="2026-08-01",
                    advisory_url="https://x", vulns=[], details_unavailable=True)
        self.assertIn("NOT PUBLISHED", mailer._plain_body([r], {}))

    def test_cve_list_is_capped(self):
        r = rel()
        r.vulns = [Vuln(cve_id=f"CVE-2026-{2000+i}", platform="ios", severity="HIGH")
                   for i in range(40)]
        body = mailer._plain_body([r], {})
        self.assertIn("and 25 more", body)

    def test_exploited_sorted_first(self):
        r = rel()
        r.vulns = [Vuln(cve_id="CVE-2026-9999", platform="ios", severity="CRITICAL"),
                   Vuln(cve_id="CVE-2026-1111", platform="ios", severity="CRITICAL",
                        exploited=True)]
        body = mailer._plain_body([r], {})
        self.assertLess(body.index("CVE-2026-1111"), body.index("CVE-2026-9999"))
