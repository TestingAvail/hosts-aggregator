# Source inventory and redistribution policy

This document describes the feeds currently used by the public FAT and SLIM profiles. The machine-readable source of truth is [sources.json](sources.json). Public builds fail closed if the code configuration and this registry differ or if an active source does not have an approved redistribution basis.

## Active public feeds

| Source | Profile | Format / scope | Rights basis | Attribution |
|---|---|---|---|---|
| HaGeZi Pro++ wildcard | FAT | domains-only / tree | GPL-3.0 | HaGeZi |
| HaGeZi Pro++ legacy hosts | FAT | hosts / exact | GPL-3.0 | HaGeZi |
| HaGeZi TIF Medium | FAT | domains-only / tree | GPL-3.0 | HaGeZi |
| OISD Big | FAT | domainswild / tree | GPL-3.0 | OISD |
| HaGeZi Light wildcard | SLIM | domains-only / tree | GPL-3.0 | HaGeZi |
| HaGeZi Light legacy hosts | SLIM | hosts / exact | GPL-3.0 | HaGeZi |
| HaGeZi TIF Mini | SLIM | domains-only / tree | GPL-3.0 | HaGeZi |
| OISD Small | SLIM | domainswild / tree | GPL-3.0 | OISD |
| AdAway hosts | FAT, SLIM | hosts / exact | CC BY 3.0 | Kicelo, Dominik Schuermann and subsequent contributors |
| Peter Lowe Ad and Tracking Server List | FAT, SLIM | hosts / exact | Explicit publisher permission to combine and republish | Peter Lowe |
| NoCoin hosts | FAT | hosts / exact | MIT | Hosh |

## Why these direct feeds

- **AdAway:** its upstream hosts file declares CC Attribution 3.0 and names Kicelo and Dominik Schuermann. Its hosts.txt content last changed on 2023-04-29; the build preserves author/source/license attribution and identifies normalization and inclusion in an aggregate. Its actual incremental value is visible in the per-source build report, so it can be removed if the feed becomes stale without adding useful coverage.
- **Peter Lowe:** the publisher explicitly permits combining the list with other lists and publishing the result on the web (see the current [publisher page](https://pgl.yoyo.org/as/), under “submit a hostname for the list”). The build retains the publisher credit and policy link.
- **NoCoin:** the upstream repository contains an MIT license and a hosts-specific output. The file header reports last modified 2025-03-05, while its file history shows a 2026-09-12 change removing `fastspot.go`; it remains FAT-only as a small specialized supplement. Hosh's copyright and permission notice are included in `licenses/MIT-Hosh.txt`.
- **HaGeZi:** the primary and legacy repositories each include GPL-3.0.
- **OISD:** the official FAQ states that OISD lists are distributed under GNU GPL version 3.

## Excluded, retired and pending feeds

The complete machine-readable inventory is in `sources.json` under `excluded_or_pending`.

- **Schakal full hosts:** excluded until its maintainer provides an explicit redistribution grant or an applicable license is identified. A public download URL alone is not a redistribution license.
- **GoodbyeAds:** excluded because its upstream catalogue includes components with differing terms, including non-commercial, no-license and all-rights-reserved entries.
- **StevenBlack Unified:** excluded as a downstream aggregate while its component data and the relevant redistribution rights are not fully mapped. We prefer individually licensed direct feeds.
- **Phishing Army:** excluded pending an upstream rights audit; its publisher warns that independent upstream intelligence-provider rights are not automatically sublicensed.
- **r-a-y AdGuard DNS conversion:** candidate only. The repository is GPL-3.0, but the converted feed incorporates AdGuard, EasyList/EasyPrivacy and other upstream lists; all upstream notices and license compatibility must be mapped first.
- **Dan Pollock, Malware Domain List and hpHosts:** treated as unavailable, stale or retired based on the supplied source inventory.
- **Energized Spark:** excluded for previously observed excessive false positives.

The 4PDA user-contributed lists (VLADIK2000, Exodus/MimiKatze, Xiaomi/MimiKatze, nasgern hosts, nasgern Pi-hole, raletag, RussianRice, Flyme/Anton29000, and Schakal's own findings) are recorded as pending permission. A forum post or downloadable file is not, by itself, permission to republish. Before enabling one, obtain a stable source, identify the maintainer, understand the upstream provenance, and record an explicit license or redistribution grant.

## Scope semantics

- `exact` means only that fully qualified hostname.
- `tree` means that hostname and all subdomains.
- Hosts mappings are always interpreted as `exact`.
- `*.example.org` in OISD `domainswild` and `||example.org^` are interpreted as `tree`.
- Browser-only URL rules, unsupported modifiers and exceptions are not widened into DNS blocks.
- A conventional hosts file cannot represent arbitrary wildcard subdomains. Use the AdGuard output for domain-tree matching.

## Provenance

`build-report.json` records license/permission references, attribution, redistribution status, per-source counts and hashes. `source-map.tsv.gz` records `profile`, `source_id`, `license_id`, `domain` and `scope` for every source-derived row.

This inventory is informational, not legal advice. Re-check publisher terms when changing sources or distribution.
