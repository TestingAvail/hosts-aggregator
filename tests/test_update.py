import sys
import tempfile
import unittest
import json
from datetime import timedelta
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import update


class ParserTests(unittest.TestCase):
    def test_google_services_are_allowlisted(self):
        protected = [
            "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
            "aistudio.google.com", "generativelanguage.googleapis.com",
            "accounts.google.com", "oauth2.googleapis.com", "fonts.gstatic.com",
            "sub.aistudio.google.com", "sub.generativelanguage.googleapis.com",
        ]
        for domain in protected:
            with self.subTest(domain=domain):
                self.assertIsNone(update.parse_line(domain))

    def test_explicit_ad_domains_override_google_allowlist(self):
        for domain in [
            "doubleclick.net", "googlesyndication.com", "adservice.google.com",
            "googletagmanager.com", "googleadservices.com",
        ]:
            with self.subTest(domain=domain):
                self.assertEqual(update.parse_line(domain), domain)

    def test_hosts_mapping_keeps_all_valid_aliases(self):
        line = "0.0.0.0 ads.example.test aistudio.google.com ads2.example.test # local test"
        self.assertEqual(
            update.parse_domains_from_line(line),
            ["ads.example.test", "ads2.example.test"],
        )

    def test_ipv6_hosts_mapping(self):
        self.assertEqual(
            update.parse_domains_from_line("::1 tracker.example.test another.example.test"),
            ["tracker.example.test", "another.example.test"],
        )

    def test_only_exact_abp_domain_rules_are_converted(self):
        self.assertEqual(update.parse_line("||ads.example.test^"), "ads.example.test")
        self.assertIsNone(update.parse_line("@@||ads.example.test^"))
        self.assertIsNone(update.parse_line("||ads.example.test^$third-party"))
        self.assertIsNone(update.parse_line("||*.ads.example.test^"))
        self.assertIsNone(update.parse_line("|https://ads.example.test^"))

    def test_idna_is_normalized(self):
        self.assertEqual(update.parse_line("пример.рф"), "xn--e1afmkfd.xn--p1ai")

    def test_invalid_input_is_rejected(self):
        for value in ["", "localhost", "not a domain", "https://example.com", "-bad.example"]:
            with self.subTest(value=value):
                self.assertIsNone(update.parse_line(value))

    def test_whitelist_protects_parent_zone(self):
        # The parent zone needed for a protected service cannot be blocked.
        self.assertIsNone(update.parse_line("googleapis.com"))
        self.assertIsNone(update.parse_line("google.com"))


class StoreAndOutputTests(unittest.TestCase):
    def test_hosts_keeps_exact_subdomains_but_adguard_compacts_parent(self):
        store = update.DomainStore()
        try:
            store.add_manual_domains(["example.test", "sub.example.test", "other.test"])
            with tempfile.TemporaryDirectory() as tmp:
                hosts_path = Path(tmp) / "hosts.txt"
                adguard_path = Path(tmp) / "adguard.txt"
                with hosts_path.open("w", encoding="utf-8") as stream:
                    count = update.write_hosts(store, stream, "TEST")
                with adguard_path.open("w", encoding="utf-8") as stream:
                    rules = update.write_adguard(store, stream, "TEST")
                hosts = hosts_path.read_text(encoding="utf-8")
                adguard = adguard_path.read_text(encoding="utf-8")
                self.assertEqual(count, 3)
                self.assertIn("0.0.0.0 sub.example.test", hosts)
                self.assertEqual(rules, 2)
                self.assertIn("||example.test^", adguard)
                self.assertNotIn("||sub.example.test^", adguard)
        finally:
            store.close()

    def test_source_provenance_and_overlap_metrics(self):
        store = update.DomainStore()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                a = Path(tmp) / "a.txt"
                b = Path(tmp) / "b.txt"
                a.write_text("a.example\nshared.example\n", encoding="utf-8")
                b.write_text("b.example\nshared.example\n", encoding="utf-8")
                store.add_source_file("source-a", a)
                store.add_source_file("source-b", b)
            metrics = store.source_metrics()
            self.assertEqual(metrics["source-a"]["unique_domains"], 2)
            self.assertEqual(metrics["source-a"]["exclusive_domains"], 1)
            self.assertEqual(metrics["source-b"]["exclusive_domains"], 1)
            self.assertEqual(store.overlap_count(), 1)
            self.assertEqual(store.count(), 3)
        finally:
            store.close()


    def test_manual_rules_do_not_distort_source_metrics(self):
        store = update.DomainStore()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                source = Path(tmp) / "source.txt"
                source.write_text("shared.example\n", encoding="utf-8")
                store.add_source_file("source-a", source)
            store.add_manual_domains(["shared.example", "manual.example"])
            metrics = store.source_metrics()
            self.assertEqual(set(metrics), {"source-a"})
            self.assertEqual(metrics["source-a"]["unique_domains"], 1)
            self.assertEqual(metrics["source-a"]["exclusive_domains"], 1)
            self.assertEqual(store.overlap_count(), 0)
            self.assertEqual(store.count(), 2)
        finally:
            store.close()

    def test_generation_publishes_all_formats_and_report(self):
        store = update.DomainStore()
        original_root = update.ROOT
        try:
            store.add_manual_domains(["example.test", "sub.example.test", "ads.test"])
            with tempfile.TemporaryDirectory() as tmp:
                update.ROOT = Path(tmp)
                profile = {
                    "profile": "FAT", "store": store, "domain_count": store.count(),
                    "source_count": 0, "configured_source_count": 0,
                    "failed_source_count": 0, "overlap_domain_count": 0,
                    "duration_seconds": 0.01, "sources": [],
                }
                # A second profile is included to check that all four public
                # filenames are published in the same generation.
                slim_store = update.DomainStore()
                slim_store.add_manual_domains(["slim.test"])
                slim = {**profile, "profile": "SLIM", "store": slim_store, "domain_count": 1}
                try:
                    report = update.publish_generation([profile, slim])
                    for name in ("hosts.txt", "abp.txt", "hosts-slim.txt", "abp-slim.txt", "build-report.json", "SHA256SUMS"):
                        self.assertTrue((Path(tmp) / name).is_file(), name)
                    self.assertEqual(report["outputs"]["hosts.txt"]["domain_entries"], 3)
                    self.assertGreater(report["outputs"]["abp.txt"]["domain_rules"], 0)
                    self.assertIn("hosts.txt", (Path(tmp) / "SHA256SUMS").read_text(encoding="utf-8"))
                finally:
                    slim_store.close()
        finally:
            update.ROOT = original_root
            store.close()

    def test_protected_zone_audit_fails_closed(self):
        store = update.DomainStore()
        try:
            store.add_manual_domains(["googleapis.com"])
            with self.assertRaises(RuntimeError):
                update.audit_protected_domains(store, "TEST")
        finally:
            store.close()

    def test_source_cache_is_validated_and_expires(self):
        source = update.Source("test-source", "Test Source", "https://example.test/list")
        with tempfile.TemporaryDirectory() as tmp, patch.object(update, "CACHE_DIR", Path(tmp)):
            data_path, metadata_path = update._source_cache_paths(source)
            data_path.write_text("tracker.example.test\n", encoding="utf-8")
            metadata = {
                "url": source.url,
                "fetched_at": update.iso_utc(),
                "sha256": update.file_sha256(data_path),
            }
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            cached = update._read_cache(source, set())
            self.assertIsNotNone(cached)
            cached_path, details = cached
            try:
                self.assertEqual(cached_path.read_text(encoding="utf-8").strip(), "tracker.example.test")
                self.assertEqual(details["cache_age_days"], 0)
            finally:
                cached_path.unlink(missing_ok=True)

            metadata["fetched_at"] = update.iso_utc(update.utc_now() - timedelta(days=46))
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            self.assertIsNone(update._read_cache(source, set()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
