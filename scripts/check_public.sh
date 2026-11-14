#!/usr/bin/env bash
set -Eeuo pipefail
OWNER_REPO="${1:-TestingAvail/hosts-aggregator}"
BASE="https://raw.githubusercontent.com/${OWNER_REPO}/main"
RELEASE="https://github.com/${OWNER_REPO}/releases/latest/download"
FILES=(hosts.txt abp.txt hosts-slim.txt abp-slim.txt)
FAILED=0

check_url() {
  local label="$1" url="$2" code
  code="$(curl -L -sS --max-time 30 -o /dev/null -w '%{http_code}' "$url" || true)"
  printf '%-32s %s\n' "$label" "$code"
  [[ "$code" == "200" ]] || FAILED=1
}

printf '%s\n' "=== RAW / main ==="
for file in "${FILES[@]}"; do
  check_url "$file" "$BASE/$file"
done

printf '\n%s\n' "=== Latest GitHub Release ==="
for file in "${FILES[@]}"; do
  check_url "$file" "$RELEASE/$file"
done

if (( FAILED )); then
  echo "One or more endpoints are not ready. Check the latest Actions run and release assets." >&2
  exit 1
fi

echo "All eight stable router endpoints respond with HTTP 200."
