# Changelog

## 4.2.2

- Add the community-documented `schakal.hopto.org/hosts.txt` mirror as a fallback when the primary Schakal host is unreachable from GitHub Actions.
- Report fallback URLs in source provenance and bind cached snapshots to the configured fallback list.

## 4.2.1

- Keep Schakal out of scheduled/public releases by default because the reviewed source did not provide an explicit redistribution license; add a deliberate workflow-dispatch opt-in for owners who have confirmed permission.
- Remove trailing whitespace so `git diff --check` succeeds.
- Make the downloader User-Agent report the actual builder version.

## 4.2.0

- Narrow the reviewed Schakal-sample compatibility exceptions to three exact hostnames instead of allowing entire registrable-domain trees. This prevents broad allowlisting from hiding unrelated ad/tracker subdomains.
- Add publication checks that refuse to emit a tree rule covering any exact compatibility exception.
- Keep the full Schakal feed exact-only; its records are supplemental hostnames, never promoted to parent-domain wildcards.
- Clarify source licensing and feed usage restrictions, including Phishing Army's third-party upstream terms.
- Improve one-command Linux deployment by creating and using a project-local Python virtual environment.

## 4.1.0

- Preserve exact-host and domain-tree rule scope separately from ingestion through AdGuard output.
- Parse OISD `domainswild` entries (`*.example.org`) as tree rules; previously these lines could be rejected by a domain-only parser.
- Add official HaGeZi legacy hosts feeds to enumerate known subdomains for conventional hosts consumers.
- Add full global Schakal hosts as exact-only FAT supplemental source; no parent-domain broadening.
- Add a compressed source provenance map to release assets.
- Add non-destructive multi-resolver DNS diagnostic and release-retention helper.
- Protect AI Studio/Gemini/auth/connectivity zones even from manual force-block roots.
- Stop force-blocking whole attribution/deep-link vendor roots to reduce app breakage.
- Move daily build to 12:17 UTC, after HaGeZi's published daily update window.
- Add offline unit tests and document source licensing/attribution caveats.

- Switched Phishing Army to its canonical Adblock feed and preserved per-listed-host tree semantics without widening to the shared parent.
- Added TIF Mini to SLIM so the low-resource profile retains a compact threat-intelligence companion.
- Shortened last-good-source cache lifetime to 14 days and added a manual, review-only override for legitimate upstream shrink events.
- Added source-attribution pointers to generated hosts and AdGuard files.
