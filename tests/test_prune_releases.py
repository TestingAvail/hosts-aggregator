import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import scripts.prune_releases as prune_releases


class ReleasePruningTests(unittest.TestCase):
    def test_selects_only_old_project_releases(self):
        releases = [
            {"tag_name": "hosts-new", "published_at": "2026-11-13T12:00:00Z"},
            {"tag_name": "manual-release", "published_at": "2026-11-13T11:00:00Z"},
            {"tag_name": "hosts-old", "published_at": "2026-11-12T12:00:00Z"},
            {"tag_name": "other-tool", "published_at": "2026-11-10T12:00:00Z"},
        ]
        stale = prune_releases.select_stale_releases(releases, keep=1)
        self.assertEqual([item["tag_name"] for item in stale], ["hosts-old"])

    def test_fetches_all_release_pages(self):
        first = [{"id": n} for n in range(100)]
        second = [{"id": 100}, {"id": 101}]
        with patch.object(prune_releases, "api_request", side_effect=[first, second]) as request:
            result = prune_releases.list_all_releases("https://api.example/repos/a/b", "token")
        self.assertEqual(len(result), 102)
        self.assertEqual(request.call_count, 2)
        self.assertIn("page=2", request.call_args_list[1].args[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
