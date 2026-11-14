from __future__ import annotations

import gzip
import hashlib
import json
import tempfile
import unittest
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


    def test_public_source_set_matches_approved_registry(self):
        policies = update.validate_public_source_policy()
        sources = {source.id: source for source in update.FAT_SOURCES + update.SLIM_SOURCES}
        self.assertEqual(set(sources), set(policies))
        self.assertNotIn("schakal-full-hosts", sources)
        self.assertNotIn("goodbyeads", sources)
        self.assertNotIn("stevenblack-unified", sources)
        self.assertNotIn("phishing-army", sources)
        self.assertEqual(sources["oisd-big"].default_scope, update.SCOPE_TREE)
        self.assertEqual(sources["oisd-small"].default_scope, update.SCOPE_TREE)
        self.assertEqual(sources["adaway"].default_scope, update.SCOPE_EXACT)
        self.assertEqual(sources["peter-lowe"].default_scope, update.SCOPE_EXACT)
        self.assertEqual(sources["nocoin"].default_scope, update.SCOPE_EXACT)
        self.assertEqual(sources["hagezi-pro-plus-wildcard"].input_format, "domains-only")
        self.assertEqual(sources["oisd-big"].input_format, "domainswild")
        self.assertEqual(sources["adaway"].input_format, "hosts")
        self.assertIn("Kicelo and Dominik Schuermann", policies["adaway"]["attribution"])
        self.assertIn("pgl.yoyo.org/as/", policies["peter-lowe"]["license"]["url"])
        self.assertIn("/hosts/pro.plus.txt", sources["hagezi-pro-plus-hosts"].url)
        self.assertIn("/hosts/light.txt", sources["hagezi-light-hosts"].url)
        self.assertIn("tif.medium-onlydomains.txt", sources["hagezi-tif-medium"].url)
        self.assertIn("tif.mini-onlydomains.txt", sources["hagezi-tif-mini"].url)

    def test_source_registry_fails_closed_on_format_drift(self):
        registry = update.load_source_registry()
        registry["active_sources"][0]["format"] = "hosts"
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sources.json"
            path.write_text(json.dumps(registry), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "format mismatch"):
                update.validate_public_source_policy(path=path)

    def test_source_registry_fails_closed_without_redistribution_basis(self):
        registry = update.load_source_registry()
        registry["active_sources"][0]["redistribution"].pop("basis")
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sources.json"
            path.write_text(json.dumps(registry), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "no redistribution basis"):
                update.validate_public_source_policy(path=path)

    def test_source_registry_must_enable_fail_closed(self):
        registry = update.load_source_registry()
        registry["policy"]["fail_closed"] = False
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sources.json"
            path.write_text(json.dumps(registry), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "fail_closed"):
                update.validate_public_source_policy(path=path)

    def test_public_source_policy_fails_closed_on_unknown_feed(self):
        bad_profiles = {
            "TEST": [
                update.Source(
                    "unlicensed-test-feed", "Test Feed",
                    "https://example.invalid/list.txt", update.SCOPE_EXACT,
                )
            ]
        }
        with self.assertRaisesRegex(RuntimeError, "missing metadata"):
            update.validate_public_source_policy(profiles=bad_profiles)

    def test_user_reported_compatibility_exceptions_are_exact(self):
        for host in (
            "s.youtube.com", "piwik.opendesktop.org", "yt3.ggpht.com",
            "suggestqueries.google.com", "redirector.googlevideo.com",
            "hl-img.peco.uodoo.com", "browser.cloud.ucweb.com",
            "gstaticadssl.l.google.com", "audio-ak-spotify-com.akamaized.net",
            "stat.online.sberbank.ru", "s3.amazonaws.com",
        ):
            with self.subTest(host=host):
                self.assertEqual(update.parse_source_line(host, update.SCOPE_EXACT), [])
        self.assertEqual(update.parse_source_line("other.youtube.com"), [("other.youtube.com", update.SCOPE_EXACT)])
        self.assertEqual(update.parse_source_line("mini5abc.opera-mini.net"), [])
        self.assertEqual(update.parse_source_line("cdn.mini5abc.opera-mini.net"), [])
        self.assertEqual(update.parse_source_line("mini5abc.opera-mini.net", update.SCOPE_TREE), [("mini5abc.opera-mini.net", update.SCOPE_TREE)])
        self.assertEqual(update.parse_source_line("opera-mini.net", update.SCOPE_TREE), [("opera-mini.net", update.SCOPE_TREE)])
        self.assertEqual(update.parse_source_line("other.opera-mini.net"), [("other.opera-mini.net", update.SCOPE_EXACT)])
        self.assertEqual(update.parse_source_line("opera-mini.net", update.SCOPE_TREE), [("opera-mini.net", update.SCOPE_TREE)])

    def test_manual_legitimate_samples_are_allowed(self):
        self.assertEqual(update.parse_source_line("www.baihe.com"), [])
        self.assertEqual(update.parse_source_line("jobs.sciencecareers.org"), [])
        self.assertEqual(update.parse_source_line("cardlytics.com"), [])
        # Compatibility exceptions are narrow exact hosts, not blanket trees.
        self.assertEqual(
            update.parse_source_line("tracking.cardlytics.com", update.SCOPE_TREE),
            [("tracking.cardlytics.com", update.SCOPE_TREE)],
        )
        self.assertEqual(update.parse_source_line("cardlytics.com", update.SCOPE_TREE), [("cardlytics.com", update.SCOPE_TREE)])
        self.assertEqual(update.parse_source_line("sciencecareers.org", update.SCOPE_TREE), [("sciencecareers.org", update.SCOPE_TREE)])


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
        self.assertIn("@@||mini5*.opera-mini.net^", result)

    def test_hosts_includes_all_known_exact_hostnames(self):
        out = StringIO()
        update.write_hosts(self.store, out, "TEST")
        result = out.getvalue()
        self.assertIn("0.0.0.0 child.ads.example.test\n", result)
        self.assertIn("0.0.0.0 api.legacy.example.test\n", result)


    def test_adguard_emits_wildcard_exception_not_hosts_syntax(self):
        adguard = StringIO()
        hosts = StringIO()
        update.write_adguard(self.store, adguard, "TEST")
        update.write_hosts(self.store, hosts, "TEST")
        self.assertIn("@@||mini5*.opera-mini.net^\n", adguard.getvalue())
        self.assertNotIn("mini5*", hosts.getvalue())

    def test_manual_exceptions_survive_tree_rules_in_both_outputs(self):
        manual_path = Path(self.tmp.name) / "manual.tsv"
        manual_path.write_text(
            "tree\tcardlytics.com\n"
            "tree\ts3.amazonaws.com\n"
            "tree\tmini5abc.opera-mini.net\n",
            encoding="utf-8",
        )
        self.store.add_source_file("manual", manual_path)

        hosts = StringIO()
        adguard = StringIO()
        update.write_hosts(self.store, hosts, "TEST")
        update.write_adguard(self.store, adguard, "TEST")
        host_text = hosts.getvalue()
        adguard_text = adguard.getvalue()

        self.assertNotIn("0.0.0.0 cardlytics.com\n", host_text)
        self.assertNotIn("0.0.0.0 s3.amazonaws.com\n", host_text)
        self.assertNotIn("0.0.0.0 mini5abc.opera-mini.net\n", host_text)
        self.assertIn("||cardlytics.com^\n", adguard_text)
        self.assertIn("||s3.amazonaws.com^\n", adguard_text)
        self.assertIn("||mini5abc.opera-mini.net^\n", adguard_text)
        self.assertIn("@@cardlytics.com\n", adguard_text)
        self.assertIn("@@s3.amazonaws.com\n", adguard_text)
        self.assertIn("@@||mini5*.opera-mini.net^\n", adguard_text)

    def test_output_headers_include_only_contributing_source_notices(self):
        manual_path = Path(self.tmp.name) / "notices.tsv"
        manual_path.write_text("exact\tads.example.test\n", encoding="utf-8")
        self.store.add_source_file("adaway", manual_path)
        hosts = StringIO()
        update.write_hosts(self.store, hosts, "TEST")
        self.assertIn("Kicelo and Dominik Schuermann", hosts.getvalue())
        self.assertIn("CC BY 3.0", hosts.getvalue())
        self.assertNotIn("NoCoin", hosts.getvalue())

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
                    store.add_source_file(source_id, input_file)
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
                self.assertIn("FAT\tfeed-fat\tUNASSESSED\tads.example.test\ttree", source_map)
                self.assertIn("SLIM\tfeed-slim\tUNASSESSED\ttracker.example.test\ttree", source_map)
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
