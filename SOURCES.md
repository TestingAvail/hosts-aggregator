# Source notes

This file documents why each upstream is used. Counts and actual contribution are generated per build in `build-report.json`.

| Profile | Source | Feed | Notes |
|---|---|---|---|
| FAT | HaGeZi Pro++ | `wildcard/pro.plus-onlydomains.txt` | One main HaGeZi tier; do not also stack Pro, Pro++, or Ultimate tiers. |
| FAT | HaGeZi TIF Mini | `wildcard/tif.mini-onlydomains.txt` | Separate threat-intelligence companion. |
| FAT | OISD Big | `https://big.oisd.nl/` | Independent broad DNS list. |
| FAT | GoodbyeAds | `Hosts/GoodbyeAds.txt` | Mobile/general ad domains. |
| FAT | StevenBlack Unified | `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts` | A curated hosts aggregator; its component sources are not separately re-added by default. |
| FAT | Phishing Army Extended | `https://phishing.army/download/phishing_army_blocklist_extended.txt` | Dedicated phishing source; legacy extended endpoint is documented by the project as compatible with its canonical domains feed. |
| SLIM | HaGeZi Light | `wildcard/light-onlydomains.txt` | Lower-impact main tier. |
| SLIM | OISD Small | `https://small.oisd.nl/` | Smaller general-purpose list. |

Do not judge source value by raw list size. The `exclusive_domains` field in the build report counts domains present in only one input source; `unique_domains` counts unique domains within a source after normalization. These metrics make overlap visible, but a domain present in multiple sources may still represent valuable consensus.
