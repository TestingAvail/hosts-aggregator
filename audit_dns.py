#!/usr/bin/env python3
"""Non-destructive DNS diagnostics for generated blocklists.

This tool NEVER edits, removes, or rewrites any blocklist entry. NXDOMAIN,
NODATA, SERVFAIL and timeout are reported separately because DNS absence alone
is not proof that a blocklist entry is stale or useless.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import ipaddress
import random
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable

try:
    import dns.asyncresolver
    import dns.exception
    import dns.resolver
except ImportError as exc:  # pragma: no cover - exercised by environment
    raise SystemExit("Install requirements first: python3 -m pip install -r requirements.txt") from exc

LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_domain(value: str) -> str | None:
    value = value.strip().lower().rstrip(".")
    if not value:
        return None
    if not value.isascii():
        try:
            value = value.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass
    if len(value) > 253:
        return None
    labels = value.split(".")
    if len(labels) < 2 or any(not x or len(x) > 63 or not LABEL.fullmatch(x) for x in labels):
        return None
    return value


def extract_domains(lines: Iterable[str]) -> set[str]:
    """Extract domain names from hosts, ABP and wildcard-domain text formats."""
    found: set[str] = set()
    for raw in lines:
        line = raw.strip().lstrip("\ufeff")
        if not line or line.startswith(("#", "!", "[", "@@")):
            continue
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        if " !" in line:
            line = line.split(" !", 1)[0].strip()
        if line.startswith("||"):
            match = re.fullmatch(r"\|\|([a-z0-9.-]+)\^(?:\$important)?", line, re.I)
            if match:
                domain = normalize_domain(match.group(1))
                if domain:
                    found.add(domain)
            continue
        if line.startswith("*."):
            domain = normalize_domain(line[2:])
            if domain:
                found.add(domain)
            continue
        parts = line.split()
        if len(parts) >= 2:
            try:
                ipaddress.ip_address(parts[0])
                for token in parts[1:]:
                    if token.startswith(("#", "!")):
                        break
                    domain = normalize_domain(token)
                    if domain:
                        found.add(domain)
                continue
            except ValueError:
                pass
        if len(parts) == 1:
            domain = normalize_domain(parts[0])
            if domain:
                found.add(domain)
    return found


def classify_observations(observations: dict[str, str]) -> str:
    """Classify per-resolver A/AAAA outcomes without making deletion decisions."""
    values = [str(v).upper() for v in observations.values()]
    if any(v == "ANSWER" for v in values):
        return "RESOLVES"
    # Only two independent resolvers reporting NXDOMAIN for both A and AAAA
    # makes this a confirmed NXDOMAIN observation.
    resolver_names = sorted({key.split(":", 1)[0] for key in observations})
    if len(resolver_names) >= 2 and all(
        observations.get(f"{resolver}:A") == "NXDOMAIN"
        and observations.get(f"{resolver}:AAAA") == "NXDOMAIN"
        for resolver in resolver_names
    ):
        return "CONFIRMED_NXDOMAIN"
    if values and all(v in {"NODATA", "NXDOMAIN"} for v in values):
        return "NO_ADDRESS_RECORD"
    return "INDETERMINATE"


async def query_one(
    domain: str,
    nameserver: str,
    record_type: str,
    timeout: float,
) -> str:
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = [nameserver]
    resolver.timeout = timeout
    try:
        await resolver.resolve(domain, record_type, lifetime=timeout, search=False)
        return "ANSWER"
    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return "NODATA"
    except dns.resolver.NoNameservers:
        return "SERVFAIL"
    except dns.exception.Timeout:
        return "TIMEOUT"
    except Exception as exc:  # Keep unexpected network errors visible in CSV.
        return f"ERROR:{type(exc).__name__}"


async def audit_domain(
    domain: str,
    resolvers: list[str],
    timeout: float,
    semaphore: asyncio.Semaphore,
) -> dict[str, str]:
    async with semaphore:
        tasks = {
            f"{resolver}:{rtype}": query_one(domain, resolver, rtype, timeout)
            for resolver in resolvers for rtype in ("A", "AAAA")
        }
        results = await asyncio.gather(*tasks.values())
        observations = dict(zip(tasks.keys(), results))
        return {"domain": domain, **observations, "classification": classify_observations(observations)}


async def main_async(args: argparse.Namespace) -> int:
    domains: set[str] = set()
    for file_path in args.files:
        path = Path(file_path)
        if not path.is_file():
            raise SystemExit(f"Input file not found: {path}")
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            domains.update(extract_domains(stream))
    ordered = sorted(domains)
    if args.limit and len(ordered) > args.limit:
        ordered = sorted(random.Random(args.seed).sample(ordered, args.limit))

    resolvers = [x.strip() for x in args.resolvers.split(",") if x.strip()]
    if len(resolvers) < 2:
        raise SystemExit("Use at least two independent resolvers, comma-separated.")
    semaphore = asyncio.Semaphore(args.concurrency)
    print(f"DNS audit: {len(ordered):,} hostnames; resolvers={','.join(resolvers)}; timeout={args.timeout}s")
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    fields = ["domain"] + [f"{resolver}:{rtype}" for resolver in resolvers for rtype in ("A", "AAAA")] + ["classification"]
    counts = Counter()
    batch_size = max(args.concurrency * 8, 256)
    audited = 0
    with output.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for start in range(0, len(ordered), batch_size):
            batch = ordered[start:start + batch_size]
            rows = await asyncio.gather(*(
                audit_domain(domain, resolvers, args.timeout, semaphore) for domain in batch
            ))
            writer.writerows(rows)
            counts.update(row["classification"] for row in rows)
            audited += len(rows)
            print(f"DNS audit: {audited:,}/{len(ordered):,}")
    print("\nClassification summary (diagnostic only; nothing is removed):")
    for label in ("RESOLVES", "CONFIRMED_NXDOMAIN", "NO_ADDRESS_RECORD", "INDETERMINATE"):
        print(f"  {label:<22} {counts.get(label, 0):>9,}")
    print(f"Report: {output}")
    print("IMPORTANT: Do not automatically delete entries based on this audit.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", nargs="+", default=["hosts.txt", "hosts-slim.txt"], help="input hosts/ABP files")
    parser.add_argument("--output", default="dns-audit.csv")
    parser.add_argument("--limit", type=int, default=10000, help="deterministic sample cap; use 0 for all")
    parser.add_argument("--seed", type=int, default=41014)
    parser.add_argument("--concurrency", type=int, default=100)
    parser.add_argument("--timeout", type=float, default=1.5)
    parser.add_argument("--resolvers", default="1.1.1.1,8.8.8.8")
    args = parser.parse_args()
    if args.limit < 0 or args.concurrency < 1 or args.timeout <= 0:
        parser.error("limit must be >=0, concurrency >=1 and timeout >0")
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
