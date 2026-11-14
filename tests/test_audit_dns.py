import unittest

from audit_dns import classify_observations, extract_domains


class DNSAuditTests(unittest.TestCase):
    def test_extract_hosts_abp_and_oisd_wildcard(self):
        lines = [
            "# comment",
            "0.0.0.0 ads.example.test tracker.example.test",
            "||tree.example.test^",
            "*.wild.example.test",
            "@@||allowed.example.test^",
            "invalid token extra",
        ]
        self.assertEqual(
            extract_domains(lines),
            {"ads.example.test", "tracker.example.test", "tree.example.test", "wild.example.test"},
        )

    def test_any_address_answer_means_resolves(self):
        self.assertEqual(
            classify_observations({
                "1.1.1.1:A": "ANSWER", "1.1.1.1:AAAA": "NODATA",
                "8.8.8.8:A": "ANSWER", "8.8.8.8:AAAA": "NODATA",
            }),
            "RESOLVES",
        )

    def test_two_resolvers_nxdomain_is_confirmed(self):
        self.assertEqual(
            classify_observations({
                "1.1.1.1:A": "NXDOMAIN", "1.1.1.1:AAAA": "NXDOMAIN",
                "8.8.8.8:A": "NXDOMAIN", "8.8.8.8:AAAA": "NXDOMAIN",
            }),
            "CONFIRMED_NXDOMAIN",
        )

    def test_nodata_is_not_nxdomain(self):
        self.assertEqual(
            classify_observations({
                "1.1.1.1:A": "NODATA", "1.1.1.1:AAAA": "NODATA",
                "8.8.8.8:A": "NODATA", "8.8.8.8:AAAA": "NODATA",
            }),
            "NO_ADDRESS_RECORD",
        )

    def test_timeouts_are_indeterminate(self):
        self.assertEqual(
            classify_observations({
                "1.1.1.1:A": "TIMEOUT", "1.1.1.1:AAAA": "TIMEOUT",
                "8.8.8.8:A": "SERVFAIL", "8.8.8.8:AAAA": "NXDOMAIN",
            }),
            "INDETERMINATE",
        )


if __name__ == "__main__":
    unittest.main()
