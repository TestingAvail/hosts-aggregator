# Hosts Aggregator

**A fast, automatically built DNS/hosts blocklist for home routers.**

Hosts Aggregator combines curated public domain feeds, normalizes them, removes duplicates, preserves protected services, and publishes two profiles in two router-friendly formats. Heavy work happens in GitHub Actions; routers only download the finished files.

## Downloads

Use the raw files from `main`:

| Profile | Hosts format | AdGuard Home / DNS format |
|---|---|---|
| **FAT** — maximum coverage | [`hosts.txt`](https://raw.githubusercontent.com/TestingAvail/hosts-aggregator/main/hosts.txt) | [`abp.txt`](https://raw.githubusercontent.com/TestingAvail/hosts-aggregator/main/abp.txt) |
| **SLIM** — smaller source set | [`hosts-slim.txt`](https://raw.githubusercontent.com/TestingAvail/hosts-aggregator/main/hosts-slim.txt) | [`abp-slim.txt`](https://raw.githubusercontent.com/TestingAvail/hosts-aggregator/main/abp-slim.txt) |

The latest build also publishes `build-report.json` and `SHA256SUMS`. The report shows source health, accepted counts, per-source unique and exclusive contributions, overlap, generation time, output sizes, and hashes.

## Profiles and sources

### FAT

| Source | Purpose | Why it is included |
|---|---|---|
| [HaGeZi Pro++](https://github.com/hagezi/dns-blocklists) | Ads, trackers, telemetry and unwanted domains | Main high-coverage DNS feed |
| [HaGeZi TIF Mini](https://github.com/hagezi/dns-blocklists) | Threat intelligence | Separate phishing/malware-oriented companion feed |
| [OISD Big](https://oisd.nl/) | Broad ads, trackers and unwanted domains | Independent curated DNS list |
| [GoodbyeAds](https://github.com/jerryn70/GoodbyeAds) | Mobile and general advertising | Additional mobile-oriented coverage |
| [StevenBlack Unified](https://github.com/StevenBlack/hosts) | Adware and malware | A separate hosts aggregator with its own curated inputs |
| [Phishing Army Extended](https://phishing.army/) | Phishing domains | Dedicated phishing feed |

### SLIM

| Source | Purpose |
|---|---|
| [HaGeZi Light](https://github.com/hagezi/dns-blocklists) | Compatibility-oriented DNS filtering |
| [OISD Small](https://oisd.nl/) | Smaller general-purpose ad/tracker list |

HaGeZi's main protection tiers are alternatives, not layers to stack. FAT uses one main tier (Pro++) plus the separate TIF feed. SLIM uses Light. StevenBlack Unified already combines several established hosts sources; its component feeds are not added again just to inflate the source count. The build report shows whether a source actually contributes exclusive domains.

The source selection is intentionally curated rather than an indiscriminate download of every available list. More sources do not automatically mean better blocking: they can add duplicates, false positives, stale domains, or incompatible syntax.

## Output formats

- **Hosts** (`hosts*.txt`): `0.0.0.0 example.com`. This format blocks only hostnames explicitly present in the file. Subdomains are blocked only when they are separately listed.
- **AdGuard DNS rules** (`abp*.txt`): `||example.com^`. This is an AdGuard Home-compatible domain rule that covers the domain and its subdomains. Covered child rules are compacted away.

These formats are not semantically identical. The hosts file keeps every exact imported hostname; the AdGuard file removes child entries already covered by a parent rule. Do not assume that a hosts consumer expands parent domains automatically.

This project operates at the DNS/hosts level. It cannot remove every ad served from the same hostname as the content (for example, some in-stream or first-party ads). Browser cosmetic filters are a different technology and are not converted into unsafe DNS-wide rules.

## Compatibility and allowlist policy

Google service namespaces (`google.com`, `googleapis.com`, `gstatic.com`, and `googleusercontent.com`) are protected so that Google AI Studio, Gemini, authentication, and related APIs are not accidentally blocked by imported feeds. A deliberately narrow set of well-known Google ad-serving domains is explicitly force-blocked. Explicit manual ad rules take precedence over the broad Google allowlist.

Other compatibility exceptions are maintained in `update.py`. These exceptions are part of the product's policy: review changes carefully before adding broad parent domains.

## Reliability and build pipeline

The GitHub Actions workflow:

1. Runs daily and can also be started manually.
2. Restores the last successful source snapshots from the Actions cache.
3. Downloads feeds concurrently and retries transient network/HTTP failures.
4. Uses a source's last successful snapshot for up to 45 days during a temporary outage.
5. Requires at least 75% of FAT feeds or 50% of SLIM feeds, plus the profile's primary feed, to be available (fresh or cached).
6. Refuses to publish an empty result or a catastrophic drop of more than 45% versus the previous hosts file.
7. Runs parser and compatibility regression tests before building.
8. Stages all four output files, the JSON report and checksums, then publishes the generation with rollback on a file-replacement failure.
9. Commits generated lists and publishes a GitHub Release; old releases are pruned to the newest 30.

The source cache is stored in GitHub Actions cache, not committed to the repository. If a cache is missing and a source is unavailable, the workflow fails closed rather than silently publishing an incomplete generation.

## DNS liveness audit (optional)

`audit_dns.py` is a separate, opt-in check. It queries Google Public DNS and only asks Cloudflare DNS for a second opinion when Google returns NXDOMAIN. A hostname is marked `CONFIRMED_NXDOMAIN` only when both resolvers agree.

The audit is **non-destructive**: it writes `dns-audit.csv` and `dns-audit-summary.json` but never removes a domain from the lists. DNS timeouts, SERVFAIL, NODATA, and disagreement are not treated as dead domains. A hostname with no current A record can still be useful, can have AAAA/MX-only service, or can be reused later; automatic pruning based on one failed lookup is unsafe.

To run locally:

```bash
python -m pip install -r requirements.txt
python audit_dns.py --input hosts.txt hosts-slim.txt
```

For a quick sample:

```bash
python audit_dns.py --input hosts.txt --limit 10000
```

The manual GitHub Actions dispatch has an optional `run_dns_audit` switch. Leave it off for the normal fast build.

## Run locally

Python 3.11 or newer is recommended.

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python update.py
```

The builder writes exactly these public filenames:

- `hosts.txt`
- `abp.txt`
- `hosts-slim.txt`
- `abp-slim.txt`

It also writes:

- `build-report.json`
- `SHA256SUMS`

## Repository layout

```text
.
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── false-positive.yml
│   │   └── source-request.yml
│   ├── workflows/
│   │   ├── build.yml
│   │   └── ci.yml
│   └── dependabot.yml
├── scripts/
│   └── prune_releases.py
├── tests/
│   ├── test_update.py
│   ├── test_audit_dns.py
│   └── test_prune_releases.py
├── audit_dns.py
├── update.py
├── requirements.txt
├── README.md
├── SOURCES.md
├── CONTRIBUTING.md
├── CHANGELOG.md
├── COPY-TO-REPO.md
├── .editorconfig
├── .gitattributes
└── .gitignore
```

## Sources, false positives and support

Each upstream source owns its inclusion policy and data quality. Use `build-report.json` to identify which source contributed a hostname; report a false positive to the source that supplied it. The aggregate is not a guarantee that every listed domain is malicious or that every ad will be blocked.

For a router, choose the format supported by its DNS/blocking software and test the list on your device before enabling it for every client. Keep a way to disable the list locally if a critical service is unexpectedly affected.
