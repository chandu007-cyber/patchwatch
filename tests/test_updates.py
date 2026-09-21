"""Interval gating, per-update documents, and no-repeat guarantees."""
import sys, tempfile, zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import unittest

from patchwatch import throttle
from patchwatch.deliver import timeline
from patchwatch.models import Release, Vuln
from patchwatch.state import State


def ago(h):
    return (datetime.now(timezone.utc) - timedelta(hours=h)).isoformat(timespec="seconds")


def rel(v="18.7.10", platform="ios", n=2):
    return Release(platform=platform, product="iOS and iPadOS", version=v,
                   release_date="2026-08-20", advisory_url="https://x",
                   vulns=[Vuln(cve_id=f"CVE-2026-{1000+i}", platform=platform,
                               severity="CRITICAL" if i == 0 else "HIGH")
                          for i in range(n)])


class TestTenHourGate(unittest.TestCase):
    def test_first_run_always_due(self):
        self.assertTrue(throttle.due(None, 10)[0])

    def test_held_inside_window(self):
        for h in [0, 3, 9.9]:
            self.assertFalse(throttle.due(ago(h), 10)[0], f"{h}h should be held")

    def test_due_after_ten_hours(self):
        self.assertTrue(throttle.due(ago(10.1), 10)[0])

    def test_corrupt_timestamp_fails_open(self):
        """Never let a bad timestamp silently suppress patch reporting."""
        self.assertTrue(throttle.due("garbage", 10)[0])

    def test_naive_timestamp_handled(self):
        naive = (datetime.now() - timedelta(hours=2)).isoformat(timespec="seconds")
        self.assertFalse(throttle.due(naive, 10)[0])


class TestNoRepeats(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.s = State(Path(self.tmp.name) / "state.json")

    def tearDown(self):
        self.tmp.cleanup()

    def test_new_release_pending(self):
        self.s.upsert_release(rel(), "new")
        self.assertEqual(len(self.s.pending_report()), 1)

    def test_reported_release_not_repeated(self):
        r = rel()
        self.s.upsert_release(r, "new")
        self.s.mark_reported([r.release_key])
        self.assertEqual(self.s.pending_report(), [])

    def test_survives_reload(self):
        r = rel()
        self.s.upsert_release(r, "new")
        self.s.mark_reported([r.release_key])
        self.s.save()
        self.assertEqual(State(self.s.path).pending_report(), [])

    def test_revised_advisory_reported_again(self):
        r1 = rel(n=2)
        self.s.upsert_release(r1, "new")
        self.s.mark_reported([r1.release_key])
        r2 = rel(n=3)
        self.s.upsert_release(r2, "changed")
        self.assertEqual(self.s.pending_report(), [r2.release_key])


class TestSchemaTolerance(unittest.TestCase):
    def test_old_state_with_email_field_loads(self):
        """A state file written by the email version must not crash the pipeline."""
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "state.json"
            p.write_text('''{
              "meta": {"schema_version": 1, "last_email_at": "2026-09-01T00:00:00+00:00"},
              "releases": {"ios-18-7-10": {"release_key":"ios-18-7-10","platform":"ios",
                "title":"iOS 18.7.10","advisory_url":"x","release_date":"2026-08-20",
                "content_hash":"abc","first_seen":"2026-09-01T00:00:00+00:00",
                "last_seen":"2026-09-01T00:00:00+00:00","cve_ids":["CVE-2026-1000"],
                "email_sent_at":"2026-09-01T00:00:00+00:00","revision":1,"notes":[]}},
              "cves": {}
            }''')
            s = State(p)
            self.assertIn("ios-18-7-10", s.releases)
            self.assertIsNone(s.releases["ios-18-7-10"].reported_at)
            self.assertEqual(s.pending_report(), ["ios-18-7-10"])


class TestUpdateDocument(unittest.TestCase):
    def test_contains_only_given_entries(self):
        e = [timeline.entry_from_release(rel(), "new", {})]
        with tempfile.TemporaryDirectory() as d:
            out = timeline.render_update(e, Path(d) / "u.docx", run_number="7")
            with zipfile.ZipFile(out) as z:
                xml = z.read("word/document.xml").decode()
            self.assertIn("CVE-2026-1000", xml)
            self.assertIn("Patch Update", xml)
            self.assertIn("run 7", xml)

    def test_empty_update_still_valid(self):
        with tempfile.TemporaryDirectory() as d:
            out = timeline.render_update([], Path(d) / "u.docx")
            with zipfile.ZipFile(out) as z:
                z.read("word/document.xml")
            self.assertTrue(out.exists())

    def test_exploited_banner_present(self):
        r = rel()
        r.vulns[0].exploited = True
        r.vulns[0].kev = True
        e = [timeline.entry_from_release(r, "new", {})]
        with tempfile.TemporaryDirectory() as d:
            out = timeline.render_update(e, Path(d) / "u.docx")
            with zipfile.ZipFile(out) as z:
                self.assertIn("active exploitation", z.read("word/document.xml").decode())
