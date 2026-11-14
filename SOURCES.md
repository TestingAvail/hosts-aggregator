# Source inventory and scope policy

This file describes the exact feeds used by the builder. Feed semantics are part of the configuration: do not change a source from `exact` to `tree` unless its upstream format explicitly means the domain and all subdomains should be blocked.

## FAT

| Source ID | Feed | Scope | Purpose / notes |
|---|---|---|---|
| `hagezi-pro-plus-wildcard` | <https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.plus-onlydomains.txt> | tree | Primary aggressive HaGeZi tier. |
| `hagezi-pro-plus-hosts` | <https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists-legacy@latest/hosts/pro.plus.txt> | exact | Legacy hosts expansion to list known subdomains; does not cover unknown future subdomains. |
| `hagezi-tif-medium` | <https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.medium-onlydomains.txt> | tree | Companion threat-intelligence tier; it is not the full TIF. |
| `oisd-big` | <https://big.oisd.nl/domainswild> | tree | OISD wildcard-domain format; input syntax `*.example.org` is parsed as tree scope. |
| `goodbyeads` | <https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt> | exact | Hosts feed; audit source catalog and upstream component terms before redistribution. |
| `stevenblack-unified` | <https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts> | exact | Curated unified hosts feed; do not add all of its components individually. |
| `phishing-army` | <https://phishing.army/download/phishing-army-adblock.txt> | tree per listed hostname | Canonical reviewed Adblock feed. A listed tenant hostname and its descendants are blocked without promoting it to the shared provider's parent domain. |
| `schakal-full-hosts` | <https://schakal.ru/hosts/hosts.txt> | exact | Full global Schakal hosts list, included in FAT as exact hostnames only; never broadened to parent trees. Attribution is retained here. Verify redistribution terms. |

## SLIM

| Source ID | Feed | Scope | Purpose / notes |
|---|---|---|---|
| `hagezi-light-wildcard` | <https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/light-onlydomains.txt> | tree | Compatibility-oriented main tier. |
| `hagezi-light-hosts` | <https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists-legacy@latest/hosts/light.txt> | exact | Enumerated known hostnames for hosts consumers. |
| `hagezi-tif-mini` | <https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt> | tree | Compact threat-intelligence companion for lower-capacity profile. |
| `oisd-small` | <https://small.oisd.nl/domainswild> | tree | Smaller OISD option. OISD Big is not added on top of Small. |

## Why the legacy HaGeZi hosts feeds are present

The modern wildcard-domain feeds are the authoritative source for AdGuard output. Their wildcard semantics cannot be represented in a conventional hosts file. The separate HaGeZi legacy hosts files enumerate known hostnames, improving hosts-format coverage for currently known subdomains. HaGeZi explicitly warns that legacy hosts/subdomain formats cannot reliably cover generic, dynamic, or previously unknown subdomains. The two feeds are not redundant for hosts consumers; for AdGuard output, exact entries already covered by a tree rule are compacted away.

## Source selection principles

- Use one HaGeZi main tier per profile; do not stack Light, Pro, Pro++, and Ultimate together.
- TIF is a separate threat-intelligence complement. FAT uses TIF Medium for higher coverage; current HaGeZi documentation lists roughly 363k entries for Medium and warns that AdGuard Home needs at least 1 GB RAM. SLIM uses TIF Mini as the compact alternative (roughly 186k entries). Neither is the full TIF.
- Use OISD Big OR OISD Small in a profile, not both. Big includes the broader coverage.
- HaGeZi's Native Tracker categories are already integrated into the standard tier levels. Do not add all Native Tracker device feeds on top of Pro++ or Light without checking the official inclusion matrix; that would mostly duplicate data and can increase breakage.
- Do not blindly re-add the component sources already curated by an aggregator. OISD's catalog already incorporates many well-known lists and has its own deduplication/quality process.
- The HaGeZi Most Abused TLDs feed is deliberately not included in normal FAT: it can block entire TLDs and the project warns about legitimate collateral. NRD/DGA feeds are also excluded from normal FAT because the upstream warns they are very large, potentially false-positive-prone, and not guaranteed to be refreshed daily. These are candidates for a separate opt-in high-security profile, not silent additions to the router defaults.
- Schakal is included as an exact-host supplemental FAT source to add hostnames not present in the other selected feeds. Its entries are never widened to parent trees. The reviewed forum post exposes a public feed URL but no explicit open redistribution license was identified; verify terms or obtain permission before public redistribution. A manual workflow run can disable the source.
- HaGeZi's legacy hosts/subdomain project explicitly warns that these formats are incomplete for dynamic or previously unknown subdomains. The legacy hosts feeds are only a best-effort expansion for the hosts output; use the AdGuard output for wildcard coverage whenever supported.
- HaGeZi integrates Native Tracker categories into its standard tiers at tier-specific blocking strengths. Pro++ is already aggressive here; do not layer the same device feeds on top without checking its inclusion matrix.
- HaGeZi's Most Abused TLDs feed blocks entire top-level domains and carries explicit collateral-risk warnings; it is not included in normal FAT. NRD/DGA feeds can contain millions of newly registered names and false positives and are not included in the normal router profiles.

## Compatibility exceptions

Only these exact hostnames are currently kept out of the blocklists based on the false-positive review of additional Schakal candidates: `www.baihe.com`, `jobs.sciencecareers.org`, and `cardlytics.com`. This is deliberately not a parent-domain allowlist. A parent tree rule that would cover one of these exact names is rejected, while other sibling subdomains remain eligible for inclusion.

## License and attribution notes

- **HaGeZi:** official list repository states GPL-3.0; this project includes the GPL-3.0 text in `licenses/GPL-3.0.txt`. Preserve upstream attribution and comply with GPL-3.0 when redistributing derived list data.
- **OISD:** upstream repository identifies GPL-3.0; same license text is included. Follow the upstream terms for redistribution.
- **GoodbyeAds:** upstream repository code license is MIT, but the source catalog includes component feeds with differing terms (including non-commercial, no-license, or all-rights-reserved entries). The repository's MIT license should not be treated as blanket permission for every upstream feed's data.
- **StevenBlack:** check the current repository license and attribution requirements when redistributing its derived data.
- **Phishing Army:** the project says its generated feeds are freely accessible, but that does not grant or sublicense rights from its independent upstream intelligence providers. The project places responsibility for checking upstream terms on organizations and services using the feed. Its current documentation distinguishes exact hostnames from DNS/Adblock matching, which covers the listed hostname and its descendants. See its [usage and licensing policy](https://phishing.army/license/).
- **Schakal:** the full exact-host feed is fetched from `https://schakal.ru/hosts/hosts.txt`, with `https://schakal.hopto.org/hosts.txt` as a fallback host documented in the community forum. The reviewed 4PDA post provides a public URL but no explicit open redistribution license was identified. The source is included by the repository owner's choice as an exact-host supplement, with attribution here; verify the maintainer's terms or obtain permission for public redistribution. This note is not a legal opinion.

Upstream licenses and source contents can change. Re-check upstream terms before changing the source set or distributing a new product/service.
