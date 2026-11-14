# Data licensing and public redistribution

The root [MIT LICENSE](LICENSE) applies to the project's original builder code. It does not relicense third-party feeds, source data or generated lists.

## Public-build requirements

A feed may enter a public profile only when all of the following are recorded in `sources.json`:

1. Stable HTTPS source URL and input format.
2. License or explicit publisher permission, with a reference.
3. Redistribution status of `approved` or `approved_with_attribution`.
4. Required attribution.
5. The exact profile, URL and rule scope used by the builder.

The builder validates these requirements before downloading sources. Missing rights metadata, an unknown status, URL/scope/profile drift, or a non-HTTPS source stops the build before publication.

## Active feed notices

- **HaGeZi:** GPL-3.0. See the [main repository](https://github.com/hagezi/dns-blocklists) and [legacy repository](https://github.com/hagezi/dns-blocklists-legacy).
- **OISD:** GPL-3.0, as stated in the publisher's [FAQ](https://oisd.nl/faq).
- **AdAway:** CC BY 3.0. Attribute AdAway contributors, link to the source and license, and say the source was normalized and incorporated into an aggregate.
- **Peter Lowe:** the publisher explicitly permits combining and republishing the list. Preserve the source credit and policy reference.
- **NoCoin:** MIT. See [Hosh's license](https://github.com/hoshsadiq/adblock-nocoin-list/blob/master/LICENSE); a copy of the notice is included at [licenses/MIT-Hosh.txt](licenses/MIT-Hosh.txt).

## Provenance and limits

The source map identifies the feed through which a domain entered the build. Generated hosts and AdGuard files also include attribution comments for the feeds that contributed to that profile. It does not claim to identify the author of every domain, nor does it automatically grant rights in an upstream aggregate's underlying components.

A third-party aggregator's MIT/GPL license is not treated as a blanket license for all upstream data. Such feeds remain excluded until their component terms are understood and public redistribution is authorized.

## Manual compatibility exceptions

The user's supplied compatibility list is represented as narrow exceptions:

- Exact: `s.youtube.com`, `piwik.opendesktop.org`, `yt3.ggpht.com`, `suggestqueries.google.com`, `redirector.googlevideo.com`, `hl-img.peco.uodoo.com`, `browser.cloud.ucweb.com`, `gstaticadssl.l.google.com`, `audio-ak-spotify-com.akamaized.net`, `stat.online.sberbank.ru`, and `s3.amazonaws.com`.
- The existing reviewed exact exceptions `www.baihe.com`, `jobs.sciencecareers.org` and `cardlytics.com` remain narrow exact-host exceptions; they do not allowlist whole parent zones.
- AdGuard output contains exact-host exceptions such as `@@s.youtube.com`, plus the wildcard exception `@@||mini5*.opera-mini.net^`.

A normal hosts file cannot express a wildcard exception. It omits known matching hostnames enumerated in the source feeds, but cannot anticipate future names. The AdGuard output emits the wildcard exception directly, so it can override a matching parent tree rule for those Opera Mini hostnames. Exact-host exceptions are emitted as bare-domain `@@hostname` rules and do not automatically allow subdomains.

These exceptions are compatibility observations, not guarantees that every listed service always needs the exception.

This document is informational, not legal advice.
