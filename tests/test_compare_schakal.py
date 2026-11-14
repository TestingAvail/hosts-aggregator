from __future__ import annotations

import unittest

from scripts.compare_schakal import is_adguard_blocked, parse_adguard, parse_hosts


class CompareSchakalTests(unittest.TestCase):
    def test_tree_coverage_and_exact_coverage_are_distinguished(self):
        exact, tree, allow_exact, allow_tree = parse_adguard(
            b"||ads.example.test^\napi.legacy.example.test\n"
        )
        self.assertTrue(is_adguard_blocked("x.ads.example.test", exact, tree, allow_exact, allow_tree))
        self.assertTrue(is_adguard_blocked("api.legacy.example.test", exact, tree, allow_exact, allow_tree))
        self.assertFalse(is_adguard_blocked("x.legacy.example.test", exact, tree, allow_exact, allow_tree))

    def test_allow_tree_overrides_block_tree(self):
        exact, tree, allow_exact, allow_tree = parse_adguard(
            b"||example.test^\n@@||safe.example.test^\n"
        )
        self.assertTrue(is_adguard_blocked("bad.example.test", exact, tree, allow_exact, allow_tree))
        self.assertFalse(is_adguard_blocked("safe.example.test", exact, tree, allow_exact, allow_tree))
        self.assertFalse(is_adguard_blocked("a.safe.example.test", exact, tree, allow_exact, allow_tree))

    def test_hosts_parser_reads_aliases(self):
        domains = parse_hosts(b"0.0.0.0 ads.example.test tracker.example.test\n")
        self.assertEqual(domains, {"ads.example.test", "tracker.example.test"})


if __name__ == "__main__":
    unittest.main()
