from __future__ import annotations

import asyncio
import gzip
import hashlib
import tempfile
import unittest
from unittest.mock import AsyncMock, patch
from io import StringIO
from pathlib import Path

import update


class ParserSemanticsTests(unittest.TestCase):
    def test_plain_domain_scope_is_source_declared(self):
        self.assertEqual(
            update.parse_source_line("ads.example.test", update.SCOPE_EXACT),
            [("ads.example.test", update.SCOPE_EXACT)],
        )
        self.assertEqual(
            update.parse_source_line("ads.example.test", update.SCOPE_TREE),
            [("ads.example.test", update.SCOPE_TREE)],
        )

    def test_oisd_wildcard_entry_is_tree_scope(self):
        self.assertEqual(
            update.parse_source_line("*.example.test", update.SCOPE_EXACT),
            [("example.test", update.SCOPE_TREE)],
        )

    def test_hosts_mapping_is_always_exact(self):
        self.assertEqual(
            update.parse_source_line("0.0.0.0 a.example.test b.example.test", update.SCOPE_TREE),
            [("a.example.test", update.SCOPE_EXACT), ("b.example.test", update.SCOPE_EXACT)],
        )

    def test_abp_tree_rule_preserved_and_modifiers_not_widened(self):
        self.assertEqual(
            update.parse_source_line("||ads.example.test^", update.SCOPE_EXACT),
            [("ads.example.test", update.SCOPE_TREE)],
        )
        self.assertEqual(update.parse_source_line("||ads.example.test^$third-party"), [])
        self.assertEqual(update.parse_source_line("@@||ads.example.test^"), [])

    def test_unicode_domain_normalized(self):
        self.assertEqual(
            update.parse_source_line("пример.рф"),
            [("xn--e1afmkfd.xn--p1ai", update.SCOPE_EXACT)],
        )

    def test_invalid_and_single_label_rejected(self):
        self.assertEqual(update.parse_source_line("localhost"), [])
        self.assertEqual(update.parse_source_line("not a domain"), [])
        self.assertEqual(update.parse_source_line("127.0.0.1"), [])

    def test_google_and_ai_studio_are_protected(self):
        for value in (
            "google.com", "googleapis.com", "aistudio.google.com",
            "generativelanguage.googleapis.com", "accounts.google.com",
        ):
            with self.subTest(value=value):
                self.assertEqual(update.parse_source_line(value, update.SCOPE_TREE), [])
        self.assertEqual(
            update.parse_source_line("google.com", update.SCOPE_TREE, force_roots={"google.com"}),
            [],
        )
        self.assertEqual(
            update.parse_source_line("aistudio.google.com", update.SCOPE_TREE, force_roots={"aistudio.google.com"}),
            [],
        )

    def test_narrow_ad_endpoint_can_override_generic_google_allow(self):
        self.assertEqual(
            update.parse_source_line("adservice.google.com", update.SCOPE_TREE),
            [("adservice.google.com", update.SCOPE_TREE)],
        )


    def test_production_sources_have_public_redistribution_metadata(self):
        sources = {source.id: source for source in update.FAT_SOURCES + update.SLIM_SOURCES}
        self.assertEqual(sources["oisd-big"].default_scope, update.SCOPE_TREE)
        self.assertEqual(sources["oisd-small"].default_scope, update.SCOPE_TREE)
        self.assertEqual(sources["adaway"].license_id, "CC-BY-3.0")
        self.assertIn("Kicelo and Dominik Schuermann", sources["adaway"].attribution)
        self.assertEqual(sources["nocoin"].license_id, "MIT")
        self.assertEqual(sources["r-a-y-adguard-dns"].license_id, "GPL-3.0")
        self.assertNotIn("schakal-full-hosts", sources)
        self.assertNotIn("goodbyeads", sources)
        self.assertNotIn("stevenblack-unified", sources)
        self.assertNotIn("phishing-army", sources)
        for source in sources.values():
            with self.subTest(source=source.id):
                self.assertIn(source.redistribution_status, update.PUBLIC_REDISTRIBUTION_STATUSES)
                self.assertTrue(source.license_id)
                self.assertTrue(source.license_url)
                self.assertTrue(source.attribution)

    def test_public_source_policy_fails_closed(self):
        bad = update.Source(
            "unlicensed", "Unlicensed feed", "https://example.test/list",
            redistribution_status="permission_required",
        )
        with self.assertRaisesRegex(RuntimeError, "Public build blocked"):
            update.validate_public_sources([bad])

    def test_public_source_policy_accepts_configured_sources(self):
        update.validate_public_sources(update.FAT_SOURCES)
        update.validate_public_sources(update.SLIM_SOURCES)

    def test_manual_legitimate_samples_are_allowed(self):
        hosts = (
            "www.baihe.com", "jobs.sciencecareers.org", "cardlytics.com",
            "s.youtube.com", "piwik.opendesktop.org",
            "hl-img.peco.uodoo.com", "browser.cloud.ucweb.com",
            "mini50.opera-mini.net", "yt3.ggpht.com", "suggestqueries.google.com",
            "redirector.googlevideo.com", "gstaticadssl.l.google.com",
            "audio-ak-spotify-com.akamaized.net", "stat.online.sberbank.ru",
            "s3.amazonaws.com",
        )
        for host in hosts:
            with self.subTest(host=host):
                self.assertEqual(update.parse_source_line(host), [])
        self.assertEqual(update.parse_source_line("youtube.com", update.SCOPE_TREE), [])
        self.assertEqual(update.parse_source_line("opendesktop.org", update.SCOPE_TREE), [])
        self.assertEqual(update.parse_source_line("opera-mini.net", update.SCOPE_TREE), [])
        self.assertEqual(
            update.parse_source_line("tracking.cardlytics.com", update.SCOPE_TREE),
            [("tracking.cardlytics.com", update.SCOPE_TREE)],
        )
        self.assertEqual(
            update.parse_source_line("ads.baihe.com", update.SCOPE_TREE),
            [("ads.baihe.com", update.SCOPE_TREE)],
        )

class OutputSemanticsTests(unittest.TestCase):
    def setUp(self):
        self.store = update.DomainStore()
        self.tmp = tempfile.TemporaryDirectory()
        self.input_path = Path(self.tmp.name) / "rules.tsv"
        self.input_path.write_text(
            "tree\tads.example.test\n"
            "exact\tapi.legacy.example.test\n"
            "exact\tchild.ads.example.test\n"
            "exact\troot.example.test\n",
            encoding="utf-8",
        )
        self.store.add_source_file("unit", self.input_path)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_adguard_does_not_widen_exact_rules(self):
        out = StringIO()
        update.write_adguard(self.store, out, "TEST")
        result = out.getvalue()
        self.assertIn("||ads.example.test^", result)
        self.assertIn("api.legacy.example.test\n", result)
        self.assertIn("root.example.test\n", result)
        self.assertNotIn("||api.legacy.example.test^", result)
        self.assertNotIn("child.ads.example.test\n", result)
        self.assertNotIn("@@||baihe.com^", result)
        self.assertNotIn("@@||sciencecareers.org^", result)
        self.assertNotIn("@@||cardlytics.com^", result)

    def test_hosts_includes_all_known_exact_hostnames(self):
        out = StringIO()
        update.write_hosts(self.store, out, "TEST")
        result = out.getvalue()
        self.assertIn("0.0.0.0 child.ads.example.test\n", result)
        self.assertIn("0.0.0.0 api.legacy.example.test\n", result)


    def test_atomic_generation_writes_report_source_map_and_valid_checksums(self):
        old_root = update.ROOT
        with tempfile.TemporaryDirectory() as temp_root:
            try:
                update.ROOT = Path(temp_root)
                profiles = []
                for profile, source_id, domain in (
                    ("FAT", "feed-fat", "ads.example.test"),
                    ("SLIM", "feed-slim", "tracker.example.test"),
                ):
                    store = update.DomainStore()
                    input_file = Path(temp_root) / f"{profile}.tsv"
                    input_file.write_text(f"tree\t{domain}\n", encoding="utf-8")
                    store.add_source_file(source_id, input_file, license_id="MIT", attribution="Test feed")
                    profiles.append({
                        "profile": profile, "store": store, "domain_count": store.count(),
                        "source_count": 1, "configured_source_count": 1,
                        "failed_source_count": 0, "overlap_domain_count": 0,
                        "rule_counts": store.rule_counts(),
                        "sources": [{"id": source_id, "name": source_id, "status": "fresh"}],
                        "duration_seconds": 0.01,
                    })
                report = update.publish_generation(profiles)
                for filename in ("hosts.txt", "abp.txt", "hosts-slim.txt", "abp-slim.txt", "build-report.json", "SHA256SUMS", "source-map.tsv.gz"):
                    self.assertTrue((Path(temp_root) / filename).is_file(), filename)
                source_map_info = report["outputs"]["source-map.tsv.gz"]
                self.assertGreater(source_map_info["rows"], 0)
                with gzip.open(Path(temp_root) / "source-map.tsv.gz", "rt", encoding="utf-8") as stream:
                    source_map = stream.read()
                self.assertIn("FAT\tfeed-fat\tads.example.test\ttree\tMIT\tTest feed", source_map)
                self.assertIn("SLIM\tfeed-slim\ttracker.example.test\ttree\tMIT\tTest feed", source_map)
                checksum_text = (Path(temp_root) / "SHA256SUMS").read_text(encoding="utf-8")
                self.assertNotIn("source-map.tsv.gz", checksum_text)
                for line in checksum_text.splitlines():
                    expected, filename = line.split("  ", 1)
                    actual = hashlib.sha256((Path(temp_root) / filename).read_bytes()).hexdigest()
                    self.assertEqual(actual, expected, filename)
                self.assertEqual(report["outputs"]["source-map.tsv.gz"]["sha256"], hashlib.sha256((Path(temp_root) / "source-map.tsv.gz").read_bytes()).hexdigest())
            finally:
                for item in profiles:
                    item["store"].close()
                update.ROOT = old_root

    def test_tree_parent_covers_child_but_exact_parent_does_not(self):
        self.assertTrue(update.rule_covered_by_tree("child.example.test", {"example.test"}))
        self.assertFalse(update.rule_covered_by_tree("example.test", {"child.example.test"}))


if __name__ == "__main__":
    unittest.main()
