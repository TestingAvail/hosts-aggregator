# Copy this package into the repository

Copy the contents of this folder into the **root** of `TestingAvail/hosts-aggregator`, preserving the directory structure.

## Replace existing files

- `update.py`
- `requirements.txt`
- `README.md`
- `.github/workflows/build.yml`
- `.gitignore` (merge any personal entries you already have)

If your repository has another scheduled build workflow in `.github/workflows/`, disable or remove it. Keep only one daily publisher to avoid concurrent commits and duplicate releases.

## Add new files

- `audit_dns.py`
- `SOURCES.md`
- `CONTRIBUTING.md`
- `CHANGELOG.md`
- `tests/test_update.py`
- `tests/test_audit_dns.py`
- `tests/test_prune_releases.py`
- `scripts/prune_releases.py`
- `.github/workflows/ci.yml`
- `.github/dependabot.yml`
- `.github/ISSUE_TEMPLATE/false-positive.yml`
- `.github/ISSUE_TEMPLATE/source-request.yml`
- `.editorconfig`
- `.gitattributes`

Do not replace the four generated list files with samples. The next successful Actions build will regenerate them.

## GitHub setting

In **Settings → Actions → General → Workflow permissions**, allow read and write permissions for `GITHUB_TOKEN`. The workflow itself requests only `contents: write`, which it needs to commit generated files, create releases and prune its own old releases.

## First run

1. Commit and push the copied files to `main`.
2. Open **Actions → Build and publish blocklists → Run workflow**.
3. Leave the optional DNS audit disabled for the first build.
4. Check the run summary and `build-report.json`. Confirm both profiles report their primary source as `fresh` (or `cached`) and that the four expected output files were published.
5. If you later want a DNS health report, manually run the workflow with `run_dns_audit` enabled. It is intentionally non-destructive.

The project has been syntax-checked and its offline tests pass in the prepared package. This environment could not perform a real download of all external feeds, so the first GitHub Actions run remains the live integration check.
