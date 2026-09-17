"""Timeline: append-only semantics, dedupe, and valid docx output."""
import sys, tempfile, zipfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import unittest
from xml.etree import ElementTree

from patchwatch.deliver import timeline
from patchwatch.models import Release, Vuln


def rel(version="18.7.10", platform="ios", n=2, **kw):
    return Release(platform=platform, product="iOS and iPadOS", version=version,
                   release_date="2026-08-20", advisory_url="https://x",
                   vulns=[Vuln(cve_id=f"CVE-2026-{1000+i}", platform=platform,
                               severity="CRITICAL" if i == 0 else "HIGH")
                          for i in range(n)], **kw)


class TestAppend(unittest.TestCase):
    def test_entries_are_added(self):
        h, added = timeline.append_entries([], [timeline.entry_from_release(rel(), "new", {})])
        self.assertEqual((added, len(h)), (1, 1))

    def test_same_release_not_appended_twice(self):
        e = timeline.entry_from_release(rel(), "new", {})
        h, _ = timeline.append_entries([], [e])
        h, again = timeline.append_entries(h, [timeline.entry_from_release(rel(), "new", {})])
        self.assertEqual(again, 0)
        self.assertEqual(len(h), 1)

    def test_revised_advisory_is_a_new_entry(self):
        """A revision that gained CVEs is a real event, not a repeat."""
        h, _ = timeline.append_entries([], [timeline.entry_from_release(rel(n=2), "new", {})])
        h, added = timeline.append_entries(
            h, [timeline.entry_from_release(rel(n=3), "changed", {})])
        self.assertEqual(added, 1)
        self.assertEqual(len(h), 2)

    def test_history_survives_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "history.json"
            h, _ = timeline.append_entries([], [timeline.entry_from_release(rel(), "new", {})])
            timeline.save_history(p, h)
            self.assertEqual(len(timeline.load_history(p)), 1)

    def test_missing_history_file_is_empty_not_an_error(self):
        self.assertEqual(timeline.load_history("/nonexistent/history.json"), [])

    def test_corrupt_history_does_not_crash(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "h.json"
            p.write_text("{ not json")
            self.assertEqual(timeline.load_history(p), [])


class TestRender(unittest.TestCase):
    def _render(self, history):
        d = tempfile.mkdtemp()
        return timeline.render(history, Path(d) / "T.docx")

    def test_produces_valid_docx_zip(self):
        h, _ = timeline.append_entries([], [timeline.entry_from_release(rel(), "new", {})])
        out = self._render(h)
        with zipfile.ZipFile(out) as z:
            names = z.namelist()
            for required in ["[Content_Types].xml", "_rels/.rels",
                             "word/document.xml", "word/styles.xml"]:
                self.assertIn(required, names)
            # Must be well-formed XML or Word refuses to open it.
            ElementTree.fromstring(z.read("word/document.xml"))
            ElementTree.fromstring(z.read("word/styles.xml"))

    def test_empty_history_still_renders(self):
        out = self._render([])
        self.assertTrue(out.exists() and out.stat().st_size > 0)

    def test_cve_ids_present_in_document(self):
        h, _ = timeline.append_entries([], [timeline.entry_from_release(rel(), "new", {})])
        with zipfile.ZipFile(self._render(h)) as z:
            self.assertIn("CVE-2026-1000", z.read("word/document.xml").decode())

    def test_xml_special_characters_escaped(self):
        """An advisory title containing & or < must not corrupt the document."""
        r = rel()
        r.product = 'Fix for <script> & "quotes"'
        h, _ = timeline.append_entries([], [timeline.entry_from_release(r, "new", {})])
        with zipfile.ZipFile(self._render(h)) as z:
            ElementTree.fromstring(z.read("word/document.xml"))

    def test_rows_cannot_split_across_pages(self):
        h, _ = timeline.append_entries([], [timeline.entry_from_release(rel(), "new", {})])
        with zipfile.ZipFile(self._render(h)) as z:
            self.assertIn("<w:cantSplit/>", z.read("word/document.xml").decode())

    def test_detail_unavailable_stated(self):
        r = Release(platform="android", product="Android Security Bulletin",
                    version="2026-08-01", release_date="2026-08-01",
                    advisory_url="https://x", vulns=[], details_unavailable=True)
        h, _ = timeline.append_entries([], [timeline.entry_from_release(r, "new", {})])
        with zipfile.ZipFile(self._render(h)) as z:
            self.assertIn("NOT PUBLISHED", z.read("word/document.xml").decode())
