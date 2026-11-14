import unittest

from scripts.prune_releases import select_releases_to_delete


class ReleasePruningTests(unittest.TestCase):
    def test_keeps_newest_n_owned_releases_by_publication_date(self):
        releases = [
            {"id": 1, "tag_name": "hosts-aggregator-old", "published_at": "2026-01-01T00:00:00Z"},
            {"id": 2, "tag_name": "hosts-aggregator-new", "published_at": "2026-03-01T00:00:00Z"},
            {"id": 3, "tag_name": "hosts-aggregator-mid", "published_at": "2026-02-01T00:00:00Z"},
        ]
        old = select_releases_to_delete(releases, keep=2)
        self.assertEqual([x["tag_name"] for x in old], ["hosts-aggregator-old"])

    def test_legacy_automated_release_tags_are_still_managed(self):
        releases = [
            {"id": 1, "tag_name": "hosts-1-1", "published_at": "2026-01-01T00:00:00Z"},
            {"id": 2, "tag_name": "hosts-3-1", "published_at": "2026-03-01T00:00:00Z"},
            {"id": 3, "tag_name": "hosts-aggregator-new", "published_at": "2026-04-01T00:00:00Z"},
            {"id": 4, "tag_name": "hosts-manual-not-a-build", "published_at": "2019-01-01T00:00:00Z"},
        ]
        old = select_releases_to_delete(releases, keep=2)
        self.assertEqual([x["tag_name"] for x in old], ["hosts-1-1"])

    def test_unrelated_and_manual_releases_are_never_pruned(self):
        releases = [
            {"id": 1, "tag_name": "hosts-aggregator-old", "published_at": "2020-01-01T00:00:00Z"},
            {"id": 2, "tag_name": "manual-release", "published_at": "2019-01-01T00:00:00Z"},
            {"id": 3, "tag_name": "blocklists-legacy", "published_at": "2018-01-01T00:00:00Z"},
        ]
        self.assertEqual([x["tag_name"] for x in select_releases_to_delete(releases, keep=0)], ["hosts-aggregator-old"])

    def test_keep_all_returns_no_deletions(self):
        self.assertEqual(select_releases_to_delete([{"tag_name": "hosts-aggregator-1", "created_at": "2026-01-01"}], keep=1), [])


if __name__ == "__main__":
    unittest.main()
