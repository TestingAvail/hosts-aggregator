# Source inventory, licenses and publication policy

This is the authoritative register for feeds actually used by public builds. Each enabled source must have a documented license, license URL, attribution, and explicit public-redistribution status. The builder enforces this before downloading any source.

## Active FAT sources

| Source ID | Feed | Format / scope | License | Attribution | Status |
|---|---|---|---|---|---|
| `hagezi-pro-plus-wildcard` | [HaGeZi Pro++ wildcard](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.plus-onlydomains.txt) | domain-only / tree | GPL-3.0 | HaGeZi contributors | approved with attribution |
| `hagezi-pro-plus-hosts` | [HaGeZi Pro++ legacy hosts](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists-legacy@latest/hosts/pro.plus.txt) | hosts / exact | GPL-3.0 | HaGeZi contributors | approved with attribution |
| `hagezi-tif-medium` | [HaGeZi TIF Medium](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.medium-onlydomains.txt) | domain-only / tree | GPL-3.0 | HaGeZi contributors | approved with attribution |
| `oisd-big` | [OISD Big](https://big.oisd.nl/domainswild) | `domainswild` / tree | GPL-3.0 | OISD contributors | approved with attribution |
| `adaway` | [AdAway hosts](https://adaway.org/hosts.txt) | hosts / exact | CC BY 3.0 | AdAway contributors | approved with attribution |
| `nocoin` | [NoCoin hosts](https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt) | hosts / exact | MIT | Hosh (hoshsadiq) | approved with attribution |
| `r-a-y-adguard-dns` | [AdGuard DNS (r-a-y/mobile-hosts)](https://raw.githubusercontent.com/r-a-y/mobile-hosts/master/AdguardDNS.txt) | mixed DNS filter syntax | GPL-3.0 | r-a-y/mobile-hosts and documented upstream authors | approved with attribution |

## Active SLIM sources

| Source ID | Feed | Format / scope | License | Attribution | Status |
|---|---|---|---|---|---|
| `hagezi-light-wildcard` | [HaGeZi Light wildcard](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/light-onlydomains.txt) | domain-only / tree | GPL-3.0 | HaGeZi contributors | approved with attribution |
| `hagezi-light-hosts` | [HaGeZi Light legacy hosts](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists-legacy@latest/hosts/light.txt) | hosts / exact | GPL-3.0 | HaGeZi contributors | approved with attribution |
| `hagezi-tif-mini` | [HaGeZi TIF Mini](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt) | domain-only / tree | GPL-3.0 | HaGeZi contributors | approved with attribution |
| `oisd-small` | [OISD Small](https://small.oisd.nl/domainswild) | `domainswild` / tree | GPL-3.0 | OISD contributors | approved with attribution |
| `adaway` | [AdAway hosts](https://adaway.org/hosts.txt) | hosts / exact | CC BY 3.0 | AdAway contributors | approved with attribution |
| `nocoin` | [NoCoin hosts](https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt) | hosts / exact | MIT | Hosh (hoshsadiq) | approved with attribution |

## License references and caveats

- **HaGeZi:** [upstream license](https://github.com/hagezi/dns-blocklists/blob/main/LICENSE). The published lists are GPL-3.0. Some underlying third-party inputs may have separate terms; this project consumes the published HaGeZi feeds.
- **OISD:** [upstream repository](https://github.com/sjhgvr/oisd). OISD identifies its published data under GPL-3.0. Re-check current upstream terms before changing versions or use.
- **AdAway:** the hosts file itself declares [CC Attribution 3.0](https://creativecommons.org/licenses/by/3.0/). Its hosts.txt content history shows the latest content change on 2023-04-29. It is included because its terms are explicit, but its freshness and unique contribution must be monitored.
- **NoCoin:** the hosts feed points to MIT, and the upstream repository contains an MIT license. Its hosts.txt file was updated on 2026-09-12.
- **r-a-y/mobile-hosts:** the repository declares GPL-3.0. Its README describes AdGuard DNS as a DNS-oriented composite built from AdGuard, EasyList, EasyPrivacy, ABPindo and hostsVN inputs. This project attributes the aggregator and its documented upstream authors.
- **Generated outputs:** each output combines data under different source licenses. This repository does not publish a single blanket license for the combined data. The original builder code remains MIT under root LICENSE; data rights remain source-specific.

## Scope policy

- `exact` means only the listed fully qualified hostname.
- `tree` means the listed domain and its subdomains.
- Hosts mappings (for example, `0.0.0.0 ads.example.org`) are exact-only.
- ABP `||example.org^` and OISD `*.example.org` are tree rules.
- Unsupported ABP modifiers and exceptions are discarded rather than widened.
- Hosts output enumerates known names only. It cannot block arbitrary future subdomains.

## Compatibility exceptions

The following hosts were supplied as functionality exceptions in the referenced Schakal 4PDA post. Previously configured exceptions are retained where still relevant. Exceptions are exact-host unless noted; the Opera Mini pattern is handled separately.

| Exception | Reason supplied |
|---|---|
| `s.youtube.com` | YouTube viewing history |
| `piwik.opendesktop.org` | KDE theme downloads |
| `yt3.ggpht.com` | YouTube channel icons |
| `mini5*.opera-mini.net` | Opera Mini functionality |
| `suggestqueries.google.com` | Google search suggestions (also covered by Google protected zone) |
| `redirector.googlevideo.com` | Third-party YouTube video downloads |
| `hl-img.peco.uodoo.com` | UC Browser functionality |
| `browser.cloud.ucweb.com` | UC Browser functionality |
| `gstaticadssl.l.google.com` | Google fonts (also covered by protected zone) |
| `audio-ak-spotify-com.akamaized.net` | Spotify device switching |
| `stat.online.sberbank.ru` | Sberbank application functionality |
| `s3.amazonaws.com` | File downloads, including GitHub-related assets |

These are user-provided functional exceptions, not a claim that every subdomain of the parent service is safe. Exact exceptions prevent parent tree rules from shadowing them. The Opera Mini glob does not allowlist the whole `opera-mini.net` zone.

## Public build gate

Only `approved` and `approved_with_attribution` sources may be enabled in `FAT_SOURCES` or `SLIM_SOURCES`. `permission_required`, `non_commercial_only`, `unknown`, or `blocked` sources must remain outside public profiles until the source owner grants the required rights or terms are verified. The build fails closed if a configured source lacks a license identifier, license URL, attribution, or approved status.

Upstream terms and content can change. Review license metadata and feed freshness periodically, and before adding or replacing any source.
