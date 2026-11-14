# Hosts Aggregator

A GitHub Actions-powered aggregator that builds router-ready **FAT** and **SLIM** DNS blocklists in two output formats:

- `hosts.txt` / `hosts-slim.txt` — traditional hosts mappings (`0.0.0.0 hostname`). These block only the listed hostnames; a hosts file cannot express a wildcard for unknown subdomains.
- `abp.txt` / `abp-slim.txt` — AdGuard DNS filtering syntax. Domain-tree rules use `||example.org^`; exact-host rules are emitted as bare `example.org`. The builder preserves the source rule's scope instead of widening every host entry into a subtree rule.

The project is designed to do expensive download, parsing, de-duplication, validation and report generation on GitHub-hosted runners. Routers only download finished text files.

## Stable router URLs

These URLs and file names are intentionally preserved:

| Profile | Hosts | AdGuard DNS |
|---|---|---|
| FAT | <https://raw.githubusercontent.com/TestingAvail/hosts-aggregator/main/hosts.txt> | <https://raw.githubusercontent.com/TestingAvail/hosts-aggregator/main/abp.txt> |
| SLIM | <https://raw.githubusercontent.com/TestingAvail/hosts-aggregator/main/hosts-slim.txt> | <https://raw.githubusercontent.com/TestingAvail/hosts-aggregator/main/abp-slim.txt> |

Release assets (latest successful release):

- <https://github.com/TestingAvail/hosts-aggregator/releases/latest/download/hosts.txt>
- <https://github.com/TestingAvail/hosts-aggregator/releases/latest/download/abp.txt>
- <https://github.com/TestingAvail/hosts-aggregator/releases/latest/download/hosts-slim.txt>
- <https://github.com/TestingAvail/hosts-aggregator/releases/latest/download/abp-slim.txt>

The release additionally includes `build-report.json`, `SHA256SUMS`, and `source-map.tsv.gz` (source-level provenance for audits). `SHA256SUMS` covers the four router files and `build-report.json`; the compressed source map has its own SHA-256 recorded in the report. The build report and source map are not router blocklists.

## Profiles

### FAT

A high-coverage profile for routers with sufficient memory/CPU:

- HaGeZi Multi Pro++ wildcard-domain feed.
- HaGeZi Pro++ legacy hosts expansion, to enumerate known subdomains for the hosts output.
- HaGeZi TIF Medium (larger threat companion for the high-capacity FAT profile).
- OISD Big in its `domainswild` format.
- GoodbyeAds.
- StevenBlack Unified.
- Phishing Army canonical Adblock feed (tenant-host scoped, with subdomain coverage).
- Schakal full global hosts feed, imported as exact hostnames only.

FAT is intentionally aggressive and memory-heavier: TIF Medium is substantially larger than TIF Mini. Use it only on higher-capacity routers; for AdGuard Home, HaGeZi notes that TIF Medium needs at least 1 GB RAM. It can still block legitimate/dual-use services. Review the source list and maintain local exceptions where necessary.

Schakal is included in FAT by default as an exact-host supplemental feed, so it contributes to the published aggregate instead of needing to be layered on separately. Its entries are never widened to parent-domain tree rules. The list is publicly available, but the reviewed forum post did not identify an explicit open redistribution license; source URL and attribution are recorded in `SOURCES.md`, and the repository owner should verify or obtain redistribution permission. A manual workflow run can disable it with `include_schakal=false`.

### SLIM

A smaller compatibility-oriented profile:

- HaGeZi Light wildcard-domain feed.
- HaGeZi Light legacy hosts expansion.
- HaGeZi TIF Mini (compact threat-intelligence companion for constrained hardware).
- OISD Small in `domainswild` format.

OISD Big and Small are not combined in one profile: Big is the larger alternative, not an extra layer over Small. SLIM now includes TIF Mini so its smaller footprint does not mean dropping threat-intelligence coverage entirely; check the actual memory use on the weakest router before switching it on everywhere.

## Important rule semantics

The builder stores two rule scopes:

- **exact** — only this fully qualified hostname;
- **tree** — the hostname and all subdomains.

Source formats are interpreted explicitly:

- `0.0.0.0 ads.example.org` → exact.
- plain hosts/domain entries → the source's declared default scope.
- Phishing Army Adblock entries → tree rules for the listed hostname and descendants; the shared hosting parent is not promoted.
- `*.example.org` in OISD `domainswild` → tree.
- `||example.org^` → tree.
- ABP rules with resource-type or other modifiers are discarded rather than broadened.
- ABP exceptions are not imported as block entries.

The AdGuard output keeps exact and tree scopes distinct. An exact entry under an existing tree rule is omitted as redundant. Hosts output contains all known hostnames as exact mappings, including hostnames explicitly enumerated by legacy hosts sources. **No hosts-format list can block arbitrary future/dynamic subdomains. HaGeZi explicitly warns that its legacy hosts/subdomain outputs are only partial for generic, dynamic or previously unknown subdomains; we use them only as best-effort expansion, not as equivalent wildcard protection.** For full wildcard coverage, use `abp.txt` with an AdGuard-compatible DNS blocker, or another router DNS engine that supports wildcard domain rules.

## Google / AI Studio compatibility

The builder has protected zones for Google infrastructure and AI Studio/Gemini/auth/connectivity endpoints. A protected service cannot be swallowed by an imported broad tree rule. A small set of explicitly selected advertising endpoints under Google can still be blocked. Add new exceptions only after checking the exact hostname and the effect on the parent zone.

HaGeZi's standard tiers already include its Native Tracker categories at the tier's chosen strength; we do not add those same device lists again as separate sources. The builder preserves three narrowly scoped exact-host compatibility exceptions observed in the Schakal comparison sample: `www.baihe.com`, `jobs.sciencecareers.org`, and `cardlytics.com`. It does **not** allowlist their entire parent trees; unrelated sibling subdomains remain eligible for blocking. A tree rule on a parent that would swallow one of these exact exceptions is rejected.

## Reliability and publication

- All configured sources must either download successfully or have a checksum-verified cached snapshot no older than 14 days. Otherwise the build stops and existing public files/releases remain untouched.
- A suspicious source shrink greater than 50% is rejected and the previous good snapshot is used when available. A manual workflow option can accept a reviewed upstream shrink.
- There is no silent partial build.
- FAT and SLIM are both built before publication; if either profile fails, neither output generation is published.
- Files are staged and published with rollback on filesystem errors.
- `build-report.json` records source status, per-source counts, exact/tree counts, overlaps, output sizes and SHA-256 values.
- `source-map.tsv.gz` records `profile`, `source_id`, `domain`, and `scope` for every source-derived entry.
- `audit_dns.py` is diagnostic only. It compares A/AAAA responses via two independent resolvers and reports `RESOLVES`, `CONFIRMED_NXDOMAIN`, `NO_ADDRESS_RECORD`, or `INDETERMINATE`. It never removes a domain. A domain with no A/AAAA record is not necessarily dead (it may be a non-resolving parent with working subdomains).
- A failed DNS lookup, one timeout, SERVFAIL, or NODATA must never trigger automatic deletion.

## GitHub Actions

`.github/workflows/build.yml`:

- runs on pushes to builder/config/docs paths;
- runs daily at **12:17 UTC**, after HaGeZi's published daily update window (scheduled jobs can still be delayed by GitHub);
- includes the exact-host Schakal supplement in FAT by default; a manual workflow run can disable it;
- supports `workflow_dispatch`, including an explicit confirmation switch for a reviewed source shrink;
- runs tests before source downloads/build;
- caches last successful source snapshots;
- commits the four stable output files plus `build-report.json` and `SHA256SUMS` to `main`;
- publishes a GitHub Release with the same four stable filenames and audit metadata;
- keeps the newest 30 releases.

`.github/workflows/ci.yml` runs offline tests on builder changes and pull requests. Keep your separate `pages-build-deployment` workflow; this package does not replace or remove it. Dependabot is configured for GitHub Actions and pip updates.

For the `GITHUB_TOKEN` release/push steps, repository Actions permissions must allow read and write access to contents. Public-repository GitHub-hosted runners are used; GitHub still has per-job execution limits and scheduled-run delays.

## Local use

Python 3.13 is recommended.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python update.py --self-test
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python update.py --list-sources
.venv/bin/python update.py
```

Optional DNS diagnostic sample (never edits lists):

```bash
python3 audit_dns.py --files hosts.txt hosts-slim.txt --limit 10000 --concurrency 100 --output dns-audit.csv
```

Use `--limit 0` only when intentionally auditing every hostname; this can take significant time and generate many DNS queries.

## Before relying on a new release

A green build proves that source parsing, safeguards and publication steps succeeded; it does not prove that every website will work for every household or that every new malicious hostname is covered. Test FAT first on a small subset of devices and keep a rollback URL. SLIM is the safer default for low-memory routers. Prefer the AdGuard format wherever the router's DNS software supports it.

## Attribution and licenses

See [SOURCES.md](SOURCES.md) and [licenses/](licenses/). The generated lists contain data maintained by upstream projects; this repository does not claim ownership of those entries. HaGeZi and OISD publish their lists under GPL-3.0 and their license texts are included here. GoodbyeAds' repository is MIT-licensed, but its source catalog lists upstream feeds with differing terms. The Schakal forum post links to the public list but no explicit redistribution license was identified in the reviewed post; verify applicable terms or obtain permission before distributing derived data publicly. Do not assume that the code license automatically licenses every upstream data source.
