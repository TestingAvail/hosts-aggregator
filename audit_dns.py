#!/usr/bin/env python3
"""Non-destructive DNS audit for a generated hosts file.

Only a name returning NXDOMAIN from both Google Public DNS and Cloudflare DNS
is marked CONFIRMED_NXDOMAIN. No entries are deleted or rewritten.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import ipaddress
import json
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import aiohttp

GOOGLE_DOH = "https://dns.google/resolve"
CLOUDFLARE_DOH = "https://cloudflare-dns.com/dns-query"


def load_domains(paths: list[Path]) -> list[str]:
    domains: set[str] = set()
    for path in paths:
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for raw in stream:
                line = raw.strip()
                if not line or line.startswith(("#", "!", "[")):
                    continue
                if line.startswith("||") and line.endswith("^"):
                    candidates = [line[2:-1]]
                else:
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            ipaddress.ip_address(parts[0])
                            candidates = []
                            for token in parts[1:]:
                                if token.startswith(("#", "!")):
                                    break
                                candidates.append(token)
                        except ValueError:
                            candidates = [parts[0]] if len(parts) == 1 else []
                    elif len(parts) == 1:
                        candidates = [parts[0]]
                    else:
                        candidates = []
                for candidate in candidates:
                    domain = candidate.rstrip(".").lower()
                    if "." in domain and len(domain) <= 253:
                        domains.add(domain)
    return sorted(domains)


async def doh_query(session: aiohttp.ClientSession, endpoint: str, domain: str) -> tuple[str, str]:
    headers = {"Accept": "application/dns-json"}
    params = {"name": domain, "type": "A"}
    try:
        async with session.get(endpoint, params=params, headers=headers) as response:
            if response.status != 200:
                return "HTTP_ERROR", f"HTTP {response.status}"
            payload = await response.json(content_type=None)
        status = payload.get("Status")
        answers = payload.get("Answer") or []
        if status == 3:
            return "NXDOMAIN", "DNS status 3"
        if status == 0 and answers:
            return "RESOLVES", f"{len(answers)} answer(s)"
        if status == 0:
            return "NODATA", "NOERROR without A answer"
        if status == 2:
            return "SERVFAIL", "DNS status 2"
        return "DNS_ERROR", f"DNS status {status!r}"
    except asyncio.TimeoutError:
        return "TIMEOUT", "request timed out"
    except (aiohttp.ClientError, ValueError, json.JSONDecodeError) as error:
        return "ERROR", str(error)[:200]


async def audit_one(session, semaphore, domain):
    async with semaphore:
        google_status, google_detail = await doh_query(session, GOOGLE_DOH, domain)
        cloudflare_status = "NOT_QUERIED"
        cloudflare_detail = ""
        # Only spend the second query on a possible NXDOMAIN. A single
        # resolver's NXDOMAIN is never enough to flag a domain as dead.
        if google_status == "NXDOMAIN":
            cloudflare_status, cloudflare_detail = await doh_query(
                session, CLOUDFLARE_DOH, domain
            )
        if google_status == "RESOLVES":
            verdict = "RESOLVES"
        elif google_status == "NXDOMAIN" and cloudflare_status == "NXDOMAIN":
            verdict = "CONFIRMED_NXDOMAIN"
        elif google_status == "NODATA":
            verdict = "NODATA"
        elif cloudflare_status == "RESOLVES":
            verdict = "RESOLVES"
        else:
            verdict = "INCONCLUSIVE"
        return {
            "domain": domain,
            "verdict": verdict,
            "google_dns": google_status,
            "cloudflare_dns": cloudflare_status,
            "google_detail": google_detail,
            "cloudflare_detail": cloudflare_detail,
        }


async def main_async(args):
    domains = load_domains([Path(item) for item in args.input])
    if args.limit:
        domains = domains[: args.limit]
    timeout = aiohttp.ClientTimeout(total=args.timeout, connect=min(15, args.timeout))
    connector = aiohttp.TCPConnector(limit=args.concurrency, ttl_dns_cache=300)
    semaphore = asyncio.Semaphore(args.concurrency)
    started = time.monotonic()
    counts = Counter()
    confirmed_nxdomain = []
    audited = 0
    csv_path = Path(args.output)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["domain", "verdict", "google_dns", "cloudflare_dns", "google_detail", "cloudflare_detail"]
    async with aiohttp.ClientSession(
        connector=connector,
        timeout=timeout,
        headers={"User-Agent": "HostsAggregator-DNS-Audit/1.0"},
    ) as session, csv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        # Process bounded batches: do not create hundreds of thousands of
        # asyncio tasks at once for a large router list.
        batch_size = max(args.concurrency * 8, 256)
        for start in range(0, len(domains), batch_size):
            batch = domains[start : start + batch_size]
            batch_results = await asyncio.gather(
                *(audit_one(session, semaphore, domain) for domain in batch)
            )
            writer.writerows(batch_results)
            for item in batch_results:
                counts[item["verdict"]] += 1
                if item["verdict"] == "CONFIRMED_NXDOMAIN":
                    confirmed_nxdomain.append(item["domain"])
            audited += len(batch_results)
            print(f"DNS audit: {audited:,}/{len(domains):,}")

    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    summary = {
        "generated_at_utc": generated_at,
        "input_files": args.input,
        "audited_domains": audited,
        "duration_seconds": round(time.monotonic() - started, 2),
        "counts": dict(sorted(counts.items())),
        "confirmed_nxdomain_domains": confirmed_nxdomain,
        "policy": "Non-destructive audit only. No domains are removed automatically.",
        "warning": "CONFIRMED_NXDOMAIN is a review candidate, not proof that a blocklist entry should be deleted. A domain may be reused or intentionally have no A record.",
    }
    summary_path = csv_path.with_name("dns-audit-summary.json")
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\nDNS audit complete: {audited:,} domains")
    for verdict, count in sorted(counts.items()):
        print(f"  {verdict}: {count:,}")
    print(f"CSV: {csv_path}")
    print(f"Summary: {summary_path}")
    print("No blocklist entries were deleted.")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", nargs="+", default=["hosts.txt"], help="hosts/AdGuard list file(s)")
    parser.add_argument("--output", default="dns-audit.csv", help="CSV output path")
    parser.add_argument("--limit", type=int, default=0, help="audit only the first N domains (0 = all)")
    parser.add_argument("--concurrency", type=int, default=48, help="parallel DNS-over-HTTPS requests")
    parser.add_argument("--timeout", type=float, default=8.0, help="per-request timeout in seconds")
    args = parser.parse_args()
    if args.concurrency < 1 or args.timeout <= 0 or args.limit < 0:
        parser.error("concurrency/timeout must be positive and limit must be >= 0")
    return args


if __name__ == "__main__":
    asyncio.run(main_async(parse_args()))
