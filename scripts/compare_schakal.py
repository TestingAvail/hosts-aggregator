#!/usr/bin/env python3
"""Compare the published FAT hosts/AdGuard files with Schakal's full hosts list.

This distinguishes exact hosts coverage from AdGuard tree coverage. It is a
measurement tool only: it does not modify the builder or any published list.
"""
from __future__ import annotations

import collections
import csv
import ipaddress
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO = "TestingAvail/hosts-aggregator"
BASE = f"https://github.com/{REPO}/releases/latest/download"
URLS = {
    "ours_hosts": f"{BASE}/hosts.txt",
    "ours_adguard": f"{BASE}/abp.txt",
    "schakal": "https://schakal.ru/hosts/hosts.txt",
    "report": f"{BASE}/build-report.json",
}
OUT = Path("hosts-compare-output")
LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)
ABP_TREE = re.compile(r"^\|\|([a-z0-9.-]+)\^(?:\$important)?$", re.I)
ABP_EXCEPTION_TREE = re.compile(r"^@@\|\|([a-z0-9.-]+)\^(?:\$important)?$", re.I)


def fetch(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "hosts-aggregator-compare/2.0", "Accept": "text/plain, */*"},
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            if response.status != 200:
                raise RuntimeError(f"HTTP {response.status}: {url}")
            return response.read()
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"Не удалось скачать {url}: {exc}") from exc


def valid_domain(raw: str) -> str | None:
    name = raw.strip().lower().rstrip(".")
    if not name:
        return None
    if not name.isascii():
        try:
            name = name.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    if len(name) > 253 or "." not in name:
        return None
    labels = name.split(".")
    if any(not label or len(label) > 63 or not LABEL.fullmatch(label) for label in labels):
        return None
    try:
        ipaddress.ip_address(name)
        return None
    except ValueError:
        return name


def parse_hosts(payload: bytes) -> set[str]:
    text = payload.decode("utf-8-sig", errors="replace")
    domains: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "!", "[")):
            continue
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        try:
            ipaddress.ip_address(parts[0])
            candidates = parts[1:]
        except ValueError:
            candidates = parts if len(parts) == 1 else []
        for candidate in candidates:
            domain = valid_domain(candidate)
            if domain:
                domains.add(domain)
    return domains


def parse_adguard(payload: bytes) -> tuple[set[str], set[str], set[str], set[str]]:
    """Return (block_exact, block_tree, allow_exact, allow_tree)."""
    exact: set[str] = set()
    tree: set[str] = set()
    allow_exact: set[str] = set()
    allow_tree: set[str] = set()
    text = payload.decode("utf-8-sig", errors="replace")
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("!", "#")):
            continue
        match = ABP_EXCEPTION_TREE.fullmatch(line)
        if match:
            domain = valid_domain(match.group(1))
            if domain:
                allow_tree.add(domain)
            continue
        match = ABP_TREE.fullmatch(line)
        if match:
            domain = valid_domain(match.group(1))
            if domain:
                tree.add(domain)
            continue
        if line.startswith("@@"):
            continue
        domain = valid_domain(line)
        if domain:
            exact.add(domain)
    return exact, tree, allow_exact, allow_tree


def covered_by_tree(domain: str, trees: set[str]) -> bool:
    labels = domain.split(".")
    return any(".".join(labels[i:]) in trees for i in range(len(labels)))


def is_adguard_blocked(
    domain: str,
    exact: set[str],
    tree: set[str],
    allow_exact: set[str],
    allow_tree: set[str],
) -> bool:
    if domain in allow_exact or covered_by_tree(domain, allow_tree):
        return False
    return domain in exact or covered_by_tree(domain, tree)


def save_domains(path: Path, domains: set[str]) -> None:
    path.write_text("\n".join(sorted(domains)) + ("\n" if domains else ""), encoding="utf-8")


def main() -> int:
    print("Скачиваю актуальный FAT hosts из последнего GitHub Release...")
    ours_hosts = parse_hosts(fetch(URLS["ours_hosts"]))
    print("Скачиваю актуальный FAT AdGuard...")
    adguard_exact, adguard_tree, allow_exact, allow_tree = parse_adguard(fetch(URLS["ours_adguard"]))
    print("Скачиваю полный глобальный hosts Schakal (не ru_com)...")
    schakal = parse_hosts(fetch(URLS["schakal"]))

    common_exact = ours_hosts & schakal
    schakal_only_hosts = schakal - ours_hosts
    schakal_adguard_covered = {
        domain for domain in schakal
        if is_adguard_blocked(domain, adguard_exact, adguard_tree, allow_exact, allow_tree)
    }
    schakal_adguard_gaps = schakal - schakal_adguard_covered

    OUT.mkdir(exist_ok=True)
    save_domains(OUT / "intersection-hosts-exact.txt", common_exact)
    save_domains(OUT / "schakal-only-hosts.txt", schakal_only_hosts)
    save_domains(OUT / "schakal-only-adguard-covered.txt", schakal_adguard_covered)
    save_domains(OUT / "schakal-only-adguard-gaps.txt", schakal_adguard_gaps)

    def pct(value: int, total: int) -> float:
        return 100.0 * value / total if total else 0.0

    print("\n=== ТОЧНОЕ ПОКРЫТИЕ HOSTS ===")
    print(f"Наш FAT hosts:              {len(ours_hosts):,}")
    print(f"Schakal:                    {len(schakal):,}")
    print(f"Точные совпадения:          {len(common_exact):,}")
    print(f"Отсутствуют в нашем hosts:  {len(schakal_only_hosts):,} ({pct(len(schakal_only_hosts), len(schakal)):.1f}% Schakal)")

    print("\n=== ПОКРЫТИЕ НАШИМ ADGUARD ===")
    print(f"AdGuard exact rules:        {len(adguard_exact):,}")
    print(f"AdGuard tree rules:         {len(adguard_tree):,}")
    print(f"AdGuard allow-tree rules:   {len(allow_tree):,}")
    print(f"Домены Schakal уже заблокированы: {len(schakal_adguard_covered):,} ({pct(len(schakal_adguard_covered), len(schakal)):.1f}%)")
    print(f"Реальные пробелы AdGuard:         {len(schakal_adguard_gaps):,} ({pct(len(schakal_adguard_gaps), len(schakal)):.1f}%)")

    print("\n=== TOP TLD В ПРОБЕЛАХ ADGUARD ===")
    for tld, count in collections.Counter(d.rsplit(".", 1)[-1] for d in schakal_adguard_gaps).most_common(20):
        print(f".{tld:<12} {count:>9,}")

    print("\n=== ПРИМЕРЫ ПРОБЕЛОВ ADGUARD ===")
    for domain in sorted(schakal_adguard_gaps)[:60]:
        print(domain)

    try:
        report = json.loads(fetch(URLS["report"]))
        report_path = OUT / "source-contribution.csv"
        with report_path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow([
                "profile", "source_id", "source_name", "status", "accepted_rules_in_feed",
                "unique_domains", "exclusive_domains", "exact_domains", "tree_domains",
            ])
            for profile in report.get("profiles", []):
                for source in profile.get("sources", []):
                    writer.writerow([
                        profile.get("name"), source.get("id"), source.get("name"), source.get("status"),
                        source.get("accepted_rules_in_feed", 0), source.get("unique_domains", 0),
                        source.get("exclusive_domains", 0), source.get("exact_domains", 0),
                        source.get("tree_domains", 0),
                    ])
        print(f"\nОтчёт по источникам: {report_path.resolve()}")
    except Exception as exc:
        print(f"\nНе удалось прочитать build-report.json: {exc}", file=sys.stderr)

    print(f"\nРезультаты: {OUT.resolve()}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ОШИБКА: {exc}", file=sys.stderr)
        raise SystemExit(1)
