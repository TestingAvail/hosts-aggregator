import asyncio
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import audit_dns


class DNSAuditInputTests(unittest.TestCase):
    def test_loads_hosts_and_adguard_formats_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.txt"
            path.write_text(
                "# comment\n"
                "0.0.0.0 ads.example.test tracker.example.test\n"
                "||ads.example.test^\n"
                "! comment\n"
                "||phishing.example.test^\n",
                encoding="utf-8",
            )
            self.assertEqual(
                audit_dns.load_domains([path]),
                ["ads.example.test", "phishing.example.test", "tracker.example.test"],
            )


class DNSAuditVerdictTests(unittest.TestCase):
    def test_nxdomain_requires_two_resolver_agreement(self):
        async def run_case(first, second):
            with patch.object(
                audit_dns, "doh_query", new=AsyncMock(side_effect=[first, second])
            ) as query:
                result = await audit_dns.audit_one(None, asyncio.Semaphore(1), "dead.example")
                self.assertEqual(query.await_count, 2)
                return result

        confirmed = asyncio.run(run_case(("NXDOMAIN", "no such name"), ("NXDOMAIN", "no such name")))
        disagreement = asyncio.run(run_case(("NXDOMAIN", "no such name"), ("RESOLVES", "answer")))
        self.assertEqual(confirmed["verdict"], "CONFIRMED_NXDOMAIN")
        self.assertEqual(disagreement["verdict"], "RESOLVES")

    def test_timeout_or_nodata_is_never_marked_dead(self):
        async def run_case(first):
            with patch.object(audit_dns, "doh_query", new=AsyncMock(return_value=first)):
                return await audit_dns.audit_one(None, asyncio.Semaphore(1), "maybe.example")

        timeout = asyncio.run(run_case(("TIMEOUT", "timed out")))
        nodata = asyncio.run(run_case(("NODATA", "no A record")))
        self.assertEqual(timeout["verdict"], "INCONCLUSIVE")
        self.assertEqual(nodata["verdict"], "NODATA")


if __name__ == "__main__":
    unittest.main(verbosity=2)
