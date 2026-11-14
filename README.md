# Hosts Aggregator

A GitHub Actions-powered builder for router-ready **FAT** and **SLIM** DNS blocklists.

- `hosts.txt` / `hosts-slim.txt`: conventional hosts mappings. These block listed hostnames only; they cannot express arbitrary wildcard subdomains.
- `abp.txt` / `abp-slim.txt`: AdGuard DNS rules. `||example.org^` blocks a domain and its subdomains; a bare hostname is exact-only.

The builder downloads approved upstream feeds, preserves exact/tree scope, deduplicates entries, validates both profiles, produces source-level provenance and publishes only complete generations.

## Stable download URLs

| Profile | Hosts | AdGuard DNS |
|---|---|---|
| FAT | https://raw.githubusercontent.com/TestingAvail/hosts-aggregator/main/hosts.txt | https://raw.githubusercontent.com/TestingAvail/hosts-aggregator/main/abp.txt |
| SLIM | https://raw.githubusercontent.com/TestingAvail/hosts-aggregator/main/hosts-slim.txt | https://raw.githubusercontent.com/TestingAvail/hosts-aggregator/main/abp-slim.txt |

The latest Release contains the same four files, `build-report.json`, `SHA256SUMS`, and `source-map.tsv.gz`.

## Profiles and sources

### FAT

- HaGeZi Pro++ wildcard domains and legacy hosts expansion.
- HaGeZi TIF Medium.
- OISD Big.
- NoCoin hosts (MIT).
- AdGuard DNS from r-a-y/mobile-hosts (GPL-3.0; large composite feed).

### SLIM

- HaGeZi Light wildcard domains and legacy hosts expansion.
- HaGeZi TIF Mini.
- OISD Small.
- NoCoin hosts.

OISD Big and Small are alternatives, not layers. HaGeZi's legacy hosts expansion enumerates known subdomains only; use the AdGuard output where wildcard support is available.

## Data licensing and attribution

The root `LICENSE` applies to the original builder code and documentation only. It does **not** relicense third-party feed data or generated blocklists.

Each active source has a recorded license identifier, license URL, attribution and redistribution status in [SOURCES.md](SOURCES.md). Imported entries are parsed, normalized, filtered to DNS-compatible records and deduplicated into a modified aggregate; they are not verbatim mirrors. Public builds fail closed unless every configured source has an explicitly approved public-redistribution status. The build report records these fields per source, and the compressed source map records the license and attribution for every source-derived domain.

The generated outputs are **multi-source data collections**, not blanket MIT-licensed datasets. Preserve the individual source terms and attribution. Do not assume that a publicly reachable URL grants redistribution rights.

The source list from the Schakal 4PDA post was reviewed as a candidate inventory, not copied as a feed. AdAway has clear CC BY 3.0 terms but is kept as a separate candidate rather than mixed into the GPL-based aggregate until the licensing of the transformed combined dataset is reviewed. Sources with no clear public redistribution grant (including user-maintained 4PDA lists) are documented in [SOURCE-CANDIDATES.md](SOURCE-CANDIDATES.md) and are not ingested into public builds.

## Rule semantics and compatibility

The builder keeps two scopes:

- **exact**: one fully qualified hostname;
- **tree**: the listed domain plus all subdomains.

Hosts mappings are always parsed as exact hostnames. ABP `||domain^` and OISD wildcard entries are parsed as tree rules. ABP exceptions and unsupported modifiers are not widened into block rules.

A conventional hosts file cannot cover unknown future subdomains. The AdGuard output preserves supported tree rules.

A manually reviewed compatibility allowlist includes the functionality exceptions listed in the original 4PDA post: YouTube history, KDE theme downloads, Opera Mini, UC Browser, Google suggestions/connectivity, Spotify device switching, Sberbank, and S3 downloads. Exact exceptions are kept narrow; the Opera Mini pattern is represented separately instead of allowlisting its entire parent zone. Existing Google/Gemini, DNS and connectivity protections remain in place.

## Reliability and publication

- Every configured source is required; a fresh download or a checksum-verified cache snapshot no older than 14 days is accepted.
- A suspicious source shrink greater than 50% is rejected unless a reviewed manual override is enabled.
- No silent partial build: both profiles must complete before publication.
- Generated files are staged and replaced atomically with rollback on filesystem errors.
- `build-report.json` records per-source counts, status, licenses, overlap, output sizes and SHA-256 hashes.
- `source-map.tsv.gz` maps each output rule to its source, scope, license and attribution.
- DNS auditing is diagnostic only. A failed lookup, timeout, SERVFAIL or NODATA never automatically removes a domain.

## GitHub Actions

`.github/workflows/build.yml` runs tests, builds both profiles, verifies checksums, commits generated outputs on `main`, publishes a Release and keeps the newest 30 releases. The daily schedule is 12:17 UTC.

`.github/workflows/ci.yml` runs offline tests on pushes and pull requests. Dependabot checks GitHub Actions and pip dependencies weekly.

## Local use

Python 3.13 is recommended:

1. Create a virtual environment and install `requirements.txt`.
2. Run `python update.py --self-test`.
3. Run `python -m unittest discover -s tests -v`.
4. Run `python update.py --list-sources` to inspect active feeds and their licenses.
5. Run `python update.py` to build both profiles.

## Attribution and notices

See [SOURCES.md](SOURCES.md), [SOURCE-CANDIDATES.md](SOURCE-CANDIDATES.md), and [licenses/](licenses/). A green build proves that parsing and publication safeguards passed; it does not prove that every site works for every household or that every malicious domain is covered. Test FAT on a small set of devices first and keep a rollback URL.
