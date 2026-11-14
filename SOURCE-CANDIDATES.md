# Candidate inventory from the Schakal 4PDA post

This is a review queue, not a feed configuration. A URL being public or linked from a forum post does not grant permission to republish its contents. Only candidates with sufficiently clear redistribution terms are enabled in public profiles; see [SOURCES.md](SOURCES.md).

| Candidate from the post | Decision | Reason / next step |
|---|---|---|
| AdAway | Included | The feed itself states CC BY 3.0 and provides attribution. Its hosts-file content last changed 2023-04-29, so contribution and freshness are monitored. |
| Dan Pollock / someonewhocares | Excluded | Marked inactive in the supplied post. StevenBlack's source inventory describes its terms as non-commercial with attribution. Do not mirror without confirming current permission. |
| Peter Lowe | Excluded pending permission | uBlock's license overview identifies McRae GPL, non-commercial. A public free feed is not sufficient evidence of redistribution permission for this aggregate. |
| Malware Domain List | Excluded | The supplied post marks the domain/feed as expired. No current maintained canonical feed was confirmed. |
| StevenBlack Unified | Excluded as a composite | Its own source inventory lists components with non-commercial terms (including MVPS and Dan Pollock) alongside other licenses. Do not consume the aggregate until the complete recipe and rights are audited. |
| hpHosts | Excluded | The supplied post says maintenance ended on 2020-03-30. |
| NoCoin | Included | Hosts feed declares MIT; upstream hosts.txt had a commit on 2026-09-12. |
| Energized Spark | Excluded | The supplied post reports too many false positives. |
| VLADIK2000 YouTube list | Excluded pending permission | Personal forum contribution; no explicit open redistribution license was supplied. |
| Exodus (MimiKatze) | Excluded pending permission | The forum list is a separate user-maintained list. Do not infer that it inherits the official Exodus Privacy database license. |
| Xiaomi (MimiKatze) | Excluded pending permission | Personal forum contribution; no explicit open redistribution license was supplied. HaGeZi tiers already include Native Tracker categories, so a separate feed needs a measured unique contribution. |
| nasgern host list | Excluded pending permission | Personal forum contribution; no explicit open redistribution license was supplied. |
| nasgern Pi-hole list | Excluded pending permission | Personal forum contribution; no explicit open redistribution license was supplied. |
| raletag list | Excluded pending permission | Personal forum contribution; no explicit open redistribution license was supplied. |
| RussianRice list | Excluded pending permission | Personal forum contribution; its purpose relates to visitor IP tracking; rights and exact feed format need confirmation. |
| Flyme (Anton29000) | Excluded pending permission | Personal forum contribution; no explicit open redistribution license was supplied. |
| AdGuard DNS (r-a-y/mobile-hosts) | Included | Upstream repository declares GPL-3.0 and documents source families; included in FAT only due to size and broad scope. |
| Schakal's own findings | Excluded pending permission | The source owner has not published a clear redistribution grant in the material reviewed. |

## Additional source notes

- The official Exodus Privacy platform says its database and API results are under ODbL 1.0, with individual database contents under the Database Contents License. That does not automatically license a third-party list posted by MimiKatze on 4PDA. See [Exodus Privacy's repository and license notice](https://github.com/Exodus-Privacy/exodus).
- StevenBlack's current README lists input licenses. Among them are AdAway (CC BY 3.0), several MIT feeds, KADhosts (CC BY-SA 4.0), MVPS (CC BY-NC-SA 4.0), Dan Pollock (non-commercial with attribution), and Peter Lowe (separate terms). This is why the unified output is not treated as a cleanly MIT-only source. See [StevenBlack source inventory](https://github.com/StevenBlack/hosts#sources-of-hosts-data-unified-in-this-variant).
- The uBlock filter-list overview lists EasyList and EasyPrivacy as GPL-3.0 / CC BY-SA 3.0 dual-licensed, Peter Lowe under McRae GPL non-commercial, and Dan Pollock under an informal attribution/non-commercial license. See [uBlock filter-list licenses](https://github.com/gorhill/uBlock/wiki/Filter-list-licenses).

A personal or forum-maintained source can be reconsidered when the author publishes an explicit license covering redistribution, or grants permission in writing. Keep the author's name, source URL, license and any required notice.
