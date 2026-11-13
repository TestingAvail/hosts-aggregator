# Contributing

Thanks for helping improve Hosts Aggregator. The goal is reliable router-level protection, not the largest possible number of lines.

## Suggesting a source

A source proposal should include:

- A direct HTTPS URL to a machine-readable list.
- A clearly described category and inclusion policy.
- Evidence that the list is actively maintained.
- A license or explicit reuse terms.
- A reason it adds coverage beyond the existing sources.
- A format that can be safely represented as exact DNS hostnames.

Do not submit another vendor tier that is already included, a browser-only cosmetic filter, an unmaintained dump, or a list that requires broadening URL patterns into entire DNS zones. The project intentionally avoids separately importing components already aggregated by StevenBlack unless a measured unique contribution justifies it.

## Reporting false positives

Use the false-positive issue template. Include the exact hostname, affected profile and output format, the broken service, and reproducible evidence. Check `build-report.json` to identify which source supplied the hostname. When possible, report the false positive to the upstream maintainer as well.

## Code changes

Before opening a pull request, run:

```bash
python -m pip install -r requirements.txt
python -m py_compile update.py audit_dns.py
python -m unittest discover -s tests -v
python update.py --self-test
```

Keep the four published filenames and formats stable unless a breaking change is explicitly discussed. Changes to Google / AI Studio allowlists or manual block rules require dedicated regression tests.
