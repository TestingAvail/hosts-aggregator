#!/usr/bin/env python3
"""Build FAT/SLIM router blocklists with loss-aware hosts and AdGuard outputs.

Input semantics are preserved:
- hosts mappings and plain domain entries are exact-host rules;
- explicit ABP ``||domain^`` and feeds declared as wildcard-domain feeds are
  domain-tree rules (the domain plus all subdomains);
- hosts output enumerates exact hostnames; AdGuard output keeps exact and tree
  rules distinct, avoiding accidental widening of exact hosts entries.

All configured production sources are required. A fresh download or a
checksum-verified cache snapshot (default max 14 days) is accepted. Missing sources,
suspicious source shrinkage, or failed compatibility checks abort publication
and leave the previously published files untouched.
"""
from __future__ import annotations

import argparse
import asyncio
import codecs
import hashlib
import gzip
import ipaddress
import json
import os
import re
import shutil
import sqlite3
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, TextIO

import aiohttp

VERSION = "4.2.1"
ROOT = Path(__file__).resolve().parent
CACHE_DIR = Path(os.environ.get("SOURCE_CACHE_DIR", ROOT / ".source-cache"))
CACHE_MAX_AGE_DAYS = int(os.environ.get("SOURCE_CACHE_MAX_AGE_DAYS", "14"))
ALLOW_SOURCE_SHRINK = os.environ.get("ALLOW_SOURCE_SHRINK", "false").strip().lower() in {"1", "true", "yes", "on"}
# Schakal is publicly available and included as an exact-host supplement.
# Its reviewed forum post does not identify an open redistribution license;
# attribution is retained and the owner must verify applicable terms.
ENABLE_SCHAKAL_SOURCE = os.environ.get("ENABLE_SCHAKAL_SOURCE", "true").strip().lower() in {"1", "true", "yes", "on"}
MAX_CONCURRENT_DOWNLOADS = 10
DOWNLOAD_ATTEMPTS = 3
MAX_LINE_LENGTH = 65536
INSERT_BATCH_SIZE = 5000
MIN_SOURCE_COUNT_FOR_SHRINK_GUARD = 1000
MAX_ACCEPTED_SHRINK_RATIO = 0.50  # reject a >50% unexplained drop vs cached snapshot
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=240, connect=25, sock_read=90)
SCOPE_EXACT = "exact"
SCOPE_TREE = "tree"


@dataclass(frozen=True)
class Source:
    id: str
    name: str
    url: str
    default_scope: str = SCOPE_EXACT
    primary: bool = False
    purpose: str = "general"
    notes: str = ""


HAGEZI_MAIN = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest"
HAGEZI_LEGACY = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists-legacy@latest"

# FAT: one primary tier + its threat add-on, independent curation approaches,
# plus exact-host feeds that improve legacy hosts coverage.
FAT_SOURCES = [
    Source(
        "hagezi-pro-plus-wildcard", "HaGeZi Pro++ (wildcard domains)",
        f"{HAGEZI_MAIN}/wildcard/pro.plus-onlydomains.txt",
        SCOPE_TREE, True, "ads-trackers-telemetry", "Primary aggressive DNS tier; wildcard semantics retained for AdGuard.",
    ),
    Source(
        "hagezi-pro-plus-hosts", "HaGeZi Pro++ (legacy hosts expansion)",
        f"{HAGEZI_LEGACY}/hosts/pro.plus.txt",
        SCOPE_EXACT, False, "hosts-expansion", "Enumerated known hostnames for hosts consumers; cannot represent unknown dynamic subdomains.",
    ),
    Source(
        "hagezi-tif-medium", "HaGeZi TIF Medium",
        f"{HAGEZI_MAIN}/wildcard/tif.medium-onlydomains.txt",
        SCOPE_TREE, False, "threat-intelligence", "Larger threat feed companion for the FAT/high-capacity profile; not a replacement for the main tier.",
    ),
    Source(
        "oisd-big", "OISD Big (domainswild)", "https://big.oisd.nl/domainswild",
        SCOPE_TREE, False, "ads-trackers-malware", "Official wildcard-domain form; covers unknown subdomains in AdGuard output.",
    ),
    Source(
        "goodbyeads", "GoodbyeAds",
        "https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt",
        SCOPE_EXACT, False, "mobile-ads-trackers", "Hosts feed. See SOURCES.md for attribution and upstream source-license caveat.",
    ),
    Source(
        "stevenblack-unified", "StevenBlack Unified",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        SCOPE_EXACT, False, "adware-malware", "Curated hosts aggregator; component feeds are not re-added separately.",
    ),
    Source(
        "phishing-army", "Phishing Army (canonical Adblock feed)",
        "https://phishing.army/download/phishing-army-adblock.txt",
        SCOPE_TREE, False, "phishing", "Canonical reviewed phishing-host feed. A listed tenant hostname covers that hostname and its descendants, but never its unrelated parent/shared-hosting provider.",
    ),
 ]

SCHAKAL_SOURCE = Source(
    "schakal-full-hosts", "Schakal full hosts", "https://schakal.ru/hosts/hosts.txt",
    SCOPE_EXACT, False, "community-hosts", "Default FAT exact-host supplement; disable only for a manual run.",
)
if ENABLE_SCHAKAL_SOURCE:
    FAT_SOURCES.append(SCHAKAL_SOURCE)

SLIM_SOURCES = [
    Source(
        "hagezi-light-wildcard", "HaGeZi Light (wildcard domains)",
        f"{HAGEZI_MAIN}/wildcard/light-onlydomains.txt",
        SCOPE_TREE, True, "ads-trackers", "Compatibility-oriented primary tier.",
    ),
    Source(
        "hagezi-light-hosts", "HaGeZi Light (legacy hosts expansion)",
        f"{HAGEZI_LEGACY}/hosts/light.txt",
        SCOPE_EXACT, False, "hosts-expansion", "Enumerated known hostnames for hosts consumers.",
    ),
    Source(
        "hagezi-tif-mini", "HaGeZi TIF Mini",
        f"{HAGEZI_MAIN}/wildcard/tif.mini-onlydomains.txt",
        SCOPE_TREE, False, "threat-intelligence", "Smaller threat-intelligence companion for resource-constrained routers.",
    ),
    Source(
        "oisd-small", "OISD Small (domainswild)", "https://small.oisd.nl/domainswild",
        SCOPE_TREE, False, "ads", "Small wildcard-domain list; Big and Small are alternatives, not layers.",
    ),
]

OUTPUTS = {
    "FAT": ("hosts.txt", "abp.txt"),
    "SLIM": ("hosts-slim.txt", "abp-slim.txt"),
}
PROFILE_SOURCES = {"FAT": FAT_SOURCES, "SLIM": SLIM_SOURCES}

GOOGLE_PROTECTED_ZONES = {
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
}
AI_STUDIO_PROTECTED_ZONES = {
    "aistudio.google.com", "makersuite.google.com", "ai.google.dev",
    "generativelanguage.googleapis.com", "accounts.google.com",
    "oauth2.googleapis.com", "apis.google.com", "www.googleapis.com",
    "fonts.googleapis.com", "fonts.gstatic.com",
}
# These service zones are never overridden by manual force-block rules.
# Broad generic Google protection still permits deliberately selected ad endpoints
# such as adservice.google.com, but AI Studio/Gemini/auth/API hosts stay protected.
HARD_PROTECTED_ZONES = set(AI_STUDIO_PROTECTED_ZONES) | {
    "clients1.google.com", "clients3.google.com", "play.googleapis.com",
    "android.clients.google.com", "connectivitycheck.gstatic.com",
    "connectivitycheck.android.com", "time.google.com", "time.android.com",
}

# These are deliberately narrow, manually reviewed tracking/ad endpoints.
# Tree scope is intentional: a vendor endpoint may use changing subdomains.
FORCE_BLOCK_TREE = {
    "alimama.alicdn.com", "aecpm.alicdn.com", "afp.alicdn.com", "afpmm.alicdn.com",
    "log.aliyuncs.com", "arms.aliyuncs.com", "beacon-api.aliyuncs.com", "click.aliyun.com",
    "tanx.com", "alimama.com", "aplus.qwen.ai", "ss.qwen.ai", "ut.qwen.ai",
    "ads.vk.ru", "ad.vk.ru", "trk.vk.ru", "mtrk.vk.ru", "tracer.vk.ru",
    "ads.mail.ru", "ad.mail.ru", "trk.mail.ru", "yabs.yandex.ru",
    "redirect.appmetrica.yandex.com", "s.click.aliexpress.com", "aemetrics.aliexpress.ru",
    "fourier.aliexpress.com", "acjs.aliyun.com", "mmstat.com", "ru.mmstat.com",
    "fourier.taobao.com", "piwik.opendesktop.org", "app-measurement.com",
    "firebase-settings.crashlytics.com", "googletagmanager.com", "doubleclick.net",
    "doubleclick.com", "googleads.g.doubleclick.net", "googlesyndication.com",
    "googleadservices.com", "googletagservices.com", "googleads.com", "2mdn.net",
    "adservice.google.com",
}
# Broad attribution/deep-link vendors are intentionally NOT force-blocked at
# their registrable root: doing so can break app redirects, sign-in and campaigns.
# Their specifically classified endpoints can still enter from curated feeds.
FAT_EXTRA_FORCE_BLOCK_TREE: set[str] = set()

# Protected trees include user-requested services and connectivity/DNS endpoints.
WHITELIST_TREE = {
    *GOOGLE_PROTECTED_ZONES, *AI_STUDIO_PROTECTED_ZONES,
    "localhost", "local", "broadcasthost", "ip6-localhost",
    "vk.ru", "vk.com", "userapi.com", "vk-cdn.net",
    "cloud.mail.ru", "mail.ru", "imgsmail.ru",
    "yt3.ggpht.com", "redirector.googlevideo.com", "gstaticadssl.l.google.com",
    "audio-ak-spotify-com.akamaized.net", "stat.online.sberbank.ru", "s3.amazonaws.com",
    "dns.quad9.net", "dns10.quad9.net", "cloudflare-dns.com", "security.cloudflare-dns.com",
    "family.cloudflare-dns.com", "one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com",
    "dns.google", "common.dot.dns.yandex.net", "safe.dot.dns.yandex.net", "family.dot.dns.yandex.net",
    "dns.comss.one", "xbox-dns.ru", "dns.dns-ai.ru", "dns.bezmezhau.com", "geohide.ru",
    "eu.geohide.ru", "us.geohide.ru", "dns.malw.link", "dns.zapret.moed.webshiftvpn.ru",
    "dns.dagami.ru", "freedns.controld.com", "unfiltered.joindns4.eu", "protective.joindns4.eu",
    "child.joindns4.eu", "web.telegram.org",
    "pclead.co.uk", "offshor.co.uk", "cakeisalie.co.uk", "noskomnadzor.co.uk",
    "lovetrue.co.uk", "sorokdva.co.uk", "pyatdesyatdva.co.uk", "kartoshka.co.uk",
    "sorokodin.co.uk", "pyatdesyatodin.co.uk", "notelega.co.uk", "ebally.co.uk",
    "nebally.co.uk", "havegreatday.co.uk", "pomogite.co.uk", "fixtelega.co.uk",
    "sadnews.co.uk", "onedaychamp.co.uk", "stopblocking.co.uk", "nothingthere.co.uk",
    "qwen.ai", "api.qwen.ai", "qwenlm.ai", "qwen.com", "auth.qwen.ai",
    "sg-entitlement.qwen.com", "sg-member.qwen.com",
    "img.alicdn.com", "at.alicdn.com", "p.alicdn.com", "o.alicdn.com",
    "g.alicdn.com", "assets.alicdn.com", "aliyunga0019.com",
    "api.aliyuncs.com", "dashscope.aliyuncs.com", "dashscope-intl.aliyuncs.com",
    "rutracker.org", "rutracker.cc", "static.rutracker.cc", "gamecontent.io", "ws6.gamecontent.io",
    "challenges.cloudflare.com", "connectivitycheck.gstatic.com", "connectivitycheck.android.com",
    "clients1.google.com", "clients3.google.com", "play.googleapis.com", "android.clients.google.com",
    "time.android.com", "time.google.com", "pool.ntp.org", "ntp.org", "connect.rom.miui.com",
    "connectivitycheck.platform.hicloud.com", "connectivitycheck.cbg-app.huawei.com",
    "www.qualcomm.cn", "captive.apple.com", "time.apple.com", "www.msftconnecttest.com",
    "www.msftncsi.com", "time.windows.com", "detectportal.firefox.com", "nmcheck.gnome.org",
    "connectivity-check.ubuntu.com",
}

# Known legitimate/dual-use domains observed in the Schakal-only sample. These
# exceptions are conservative: keep service functionality rather than blanket
# block a whole legitimate provider. Review before extending this set.
# Exact compatibility exceptions from examples reviewed in the Schakal-only
# sample. Keep these narrow: a broad allow tree would hide unrelated tracking
# subdomains and create avoidable underblocking.
MANUAL_ALLOW_EXACT = {
    "www.baihe.com",             # legitimate dating/community service hostname
    "jobs.sciencecareers.org",   # legitimate science jobs/career hostname
    "cardlytics.com",            # bank/card-linked offers and cashback apex
}

DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
ABP_TREE_RULE = re.compile(r"^\|\|([a-z0-9.-]+)\^(?:\$(important))?$", re.IGNORECASE)
OISD_WILDCARD_DOMAIN = re.compile(r"^\*\.([a-z0-9.-]+)$", re.IGNORECASE)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(value: datetime | None = None) -> str:
    return (value or utc_now()).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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
    if len(labels) < 2 or any(
        not label or len(label) > 63 or not DOMAIN_LABEL.fullmatch(label)
        for label in labels
    ):
        return None
    try:
        for label in labels:
            if label.startswith("xn--"):
                label.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return None
    return value


def is_same_or_subdomain(domain: str, zone: str) -> bool:
    return domain == zone or domain.endswith("." + zone)


def is_parent_of(domain: str, child: str) -> bool:
    return child.endswith("." + domain)


def suffixes(domain: str) -> Iterable[str]:
    labels = domain.split(".")
    for index in range(len(labels)):
        yield ".".join(labels[index:])


def is_protected_rule(domain: str, scope: str, force: bool = False) -> bool:
    """Return True when the rule must be excluded to protect functionality.

    Narrow, explicit ad endpoints may override broad vendor allowlists, but no
    forced rule may block an AI Studio/Gemini/auth/connectivity service or any
    parent tree that would shadow one of those hard-protected hosts.
    """
    if force:
        for zone in HARD_PROTECTED_ZONES:
            if is_same_or_subdomain(domain, zone):
                return True
            if scope == SCOPE_TREE and is_parent_of(domain, zone):
                return True
        return False
    for zone in WHITELIST_TREE:
        if is_same_or_subdomain(domain, zone):
            return True
        # A tree rule on a parent would swallow an allowlisted protected tree.
        if scope == SCOPE_TREE and is_parent_of(domain, zone):
            return True
    if domain in MANUAL_ALLOW_EXACT:
        return True
    # Do not let a tree rule on a parent swallow a narrowly allowlisted FQDN.
    if scope == SCOPE_TREE and any(is_parent_of(domain, exact) for exact in MANUAL_ALLOW_EXACT):
        return True
    return False


def is_force_blocked(domain: str, force_roots: set[str]) -> bool:
    return any(is_same_or_subdomain(domain, root) for root in force_roots)


def parse_source_line(
    line: str,
    default_scope: str = SCOPE_EXACT,
    force_roots: set[str] | None = None,
) -> list[tuple[str, str]]:
    """Parse one source line into (hostname, scope) pairs.

    `tree` means domain + every subdomain. `exact` means only that FQDN.
    Hosts mappings are ALWAYS exact, even when a source's default is tree.
    Plain domains inherit the declared source format semantics.
    """
    if default_scope not in {SCOPE_EXACT, SCOPE_TREE}:
        raise ValueError(f"Unknown scope: {default_scope}")
    if not isinstance(line, str):
        return []
    raw_line = line.strip().lstrip("\ufeff")
    if not raw_line or raw_line.startswith(("#", "!", "[")):
        return []
    raw_line = re.split(r"\s+[#!]", raw_line, maxsplit=1)[0].strip()
    if not raw_line:
        return []
    if raw_line.startswith("@@"):
        return []

    force_roots = FORCE_BLOCK_TREE if force_roots is None else force_roots

    # OISD domainswild entries use the explicit form *.example.com. The
    # asterisk means the apex and every subdomain, not a literal hostname.
    wildcard_match = OISD_WILDCARD_DOMAIN.fullmatch(raw_line)
    if wildcard_match:
        domain = normalize_domain(wildcard_match.group(1))
        if not domain:
            return []
        forced = is_force_blocked(domain, force_roots)
        if is_protected_rule(domain, SCOPE_TREE, force=forced):
            return []
        return [(domain, SCOPE_TREE)]

    # Canonical domain-wide ABP rule. Only the harmless $important modifier is
    # ignored; resource-type/scope modifiers are discarded rather than widened.
    match = ABP_TREE_RULE.fullmatch(raw_line)
    if match:
        domain = normalize_domain(match.group(1))
        if not domain:
            return []
        forced = is_force_blocked(domain, force_roots)
        if is_protected_rule(domain, SCOPE_TREE, force=forced):
            return []
        return [(domain, SCOPE_TREE)]

    # Other ABP/browser syntax is not safely representable as a DNS rule.
    if any(marker in raw_line for marker in ("|", "^", "$", "*", "#")):
        return []

    parts = raw_line.split()
    if not parts:
        return []
    try:
        ipaddress.ip_address(parts[0])
        is_hosts_mapping = len(parts) > 1
    except ValueError:
        is_hosts_mapping = False

    if is_hosts_mapping:
        names = []
        for token in parts[1:]:
            if token.startswith(("#", "!")):
                break
            names.append((token, SCOPE_EXACT))
    else:
        if len(parts) != 1:
            return []
        names = [(parts[0], default_scope)]

    accepted: list[tuple[str, str]] = []
    for token, scope in names:
        domain = normalize_domain(token)
        if not domain:
            continue
        forced = is_force_blocked(domain, force_roots)
        if is_protected_rule(domain, scope, force=forced):
            continue
        # Explicit manual block roots remain tree-scoped even when a source
        # mentions the root using a hosts/exact line.
        if domain in force_roots:
            scope = SCOPE_TREE
        accepted.append((domain, scope))
    return accepted


def parse_line(line: str, force_block: set[str] | None = None) -> str | None:
    """Backward-compatible single-domain parser used by small external tests."""
    parsed = parse_source_line(line, SCOPE_EXACT, force_roots=force_block)
    return parsed[0][0] if parsed else None


class DomainStore:
    """Disk-backed exact-domain store with scope and per-source provenance."""
    def __init__(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="hosts-aggregator-")
        self.db = sqlite3.connect(Path(self.tempdir.name) / "domains.sqlite3")
        self.db.execute("PRAGMA journal_mode=OFF")
        self.db.execute("PRAGMA synchronous=OFF")
        self.db.execute("PRAGMA temp_store=FILE")
        self.db.execute("PRAGMA cache_size=-16384")
        self.db.execute("PRAGMA locking_mode=EXCLUSIVE")
        self.db.execute("CREATE TABLE domains (domain TEXT PRIMARY KEY) WITHOUT ROWID")
        self.db.execute("CREATE TABLE rules (domain TEXT PRIMARY KEY, scope TEXT NOT NULL CHECK(scope IN ('exact','tree'))) WITHOUT ROWID")
        self.db.execute(
            "CREATE TABLE source_domains (source_id TEXT NOT NULL, domain TEXT NOT NULL, "
            "scope TEXT NOT NULL CHECK(scope IN ('exact','tree')), PRIMARY KEY(source_id,domain)) WITHOUT ROWID"
        )

    def add_source_file(self, source_id: str, path: Path) -> int:
        before = self.db.total_changes
        batch: list[tuple[str, str, str]] = []
        with self.db:
            with path.open("r", encoding="utf-8") as stream:
                for line in stream:
                    line = line.rstrip("\r\n")
                    if not line:
                        continue
                    try:
                        scope, domain = line.split("\t", 1)
                    except ValueError:
                        continue
                    if scope not in {SCOPE_EXACT, SCOPE_TREE} or not normalize_domain(domain):
                        continue
                    batch.append((source_id, domain, scope))
                    if len(batch) >= INSERT_BATCH_SIZE:
                        self._insert_batch(batch)
                        batch.clear()
            if batch:
                self._insert_batch(batch)
        return self.db.total_changes - before

    def _insert_batch(self, batch: list[tuple[str, str, str]]) -> None:
        self.db.executemany(
            "INSERT INTO source_domains(source_id,domain,scope) VALUES(?,?,?) "
            "ON CONFLICT(source_id,domain) DO UPDATE SET scope=CASE "
            "WHEN excluded.scope='tree' THEN 'tree' ELSE source_domains.scope END",
            batch,
        )
        self.db.executemany("INSERT OR IGNORE INTO domains(domain) VALUES(?)", ((d,) for _, d, _ in batch))
        self.db.executemany(
            "INSERT INTO rules(domain,scope) VALUES(?,?) ON CONFLICT(domain) DO UPDATE SET "
            "scope=CASE WHEN excluded.scope='tree' THEN 'tree' ELSE rules.scope END",
            ((d, scope) for _, d, scope in batch),
        )

    def add_manual_tree_rules(self, domains: Iterable[str]) -> None:
        clean = sorted({d for d in domains if normalize_domain(d)})
        with self.db:
            self.db.executemany("INSERT OR IGNORE INTO domains(domain) VALUES(?)", ((d,) for d in clean))
            self.db.executemany(
                "INSERT INTO rules(domain,scope) VALUES(?,?) ON CONFLICT(domain) DO UPDATE SET scope='tree'",
                ((d, SCOPE_TREE) for d in clean),
            )

    def count(self) -> int:
        return int(self.db.execute("SELECT COUNT(*) FROM domains").fetchone()[0])

    def contains_rule(self, domain: str, scope: str | None = None) -> bool:
        if scope:
            return self.db.execute("SELECT 1 FROM rules WHERE domain=? AND scope=?", (domain, scope)).fetchone() is not None
        return self.db.execute("SELECT 1 FROM rules WHERE domain=?", (domain,)).fetchone() is not None

    def rule_counts(self) -> dict[str, int]:
        rows = self.db.execute("SELECT scope,COUNT(*) FROM rules GROUP BY scope").fetchall()
        result = {SCOPE_EXACT: 0, SCOPE_TREE: 0}
        result.update({scope: int(count) for scope, count in rows})
        return result

    def source_metrics(self) -> dict[str, dict[str, int]]:
        rows = self.db.execute(
            "SELECT sd.source_id, COUNT(*) AS source_unique, "
            "SUM(CASE WHEN dc.source_count=1 THEN 1 ELSE 0 END) AS exclusive_count, "
            "SUM(CASE WHEN sd.scope='exact' THEN 1 ELSE 0 END) AS exact_count, "
            "SUM(CASE WHEN sd.scope='tree' THEN 1 ELSE 0 END) AS tree_count "
            "FROM source_domains sd JOIN (SELECT domain,COUNT(*) AS source_count FROM source_domains GROUP BY domain) dc "
            "ON dc.domain=sd.domain GROUP BY sd.source_id"
        ).fetchall()
        return {
            sid: {
                "unique_domains": int(unique),
                "exclusive_domains": int(exclusive or 0),
                "exact_domains": int(exact or 0),
                "tree_domains": int(tree or 0),
            }
            for sid, unique, exclusive, exact, tree in rows
        }

    def overlap_count(self) -> int:
        row = self.db.execute(
            "SELECT COUNT(*) FROM (SELECT domain FROM source_domains GROUP BY domain HAVING COUNT(*)>1)"
        ).fetchone()
        return int(row[0])

    def all_domains(self):
        return self.db.execute("SELECT domain FROM domains ORDER BY domain")

    def close(self) -> None:
        self.db.close()
        self.tempdir.cleanup()


def source_cache_paths(source: Source) -> tuple[Path, Path]:
    key = hashlib.sha256(f"{source.id}\n{source.url}\n{source.default_scope}".encode()).hexdigest()
    return CACHE_DIR / f"{key}.txt", CACHE_DIR / f"{key}.json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_copy(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".cache-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as output, source.open("rb") as input_stream:
            shutil.copyfileobj(input_stream, output, length=1024 * 1024)
        os.chmod(temp_name, 0o644)
        os.replace(temp_name, target)
    except Exception:
        Path(temp_name).unlink(missing_ok=True)
        raise


def atomic_json(data: dict, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".meta-", dir=target.parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.chmod(temp_name, 0o644)
        os.replace(temp_name, target)
    except Exception:
        Path(temp_name).unlink(missing_ok=True)
        raise


def read_cache(source: Source, force_roots: set[str]) -> tuple[Path, dict] | None:
    data_path, meta_path = source_cache_paths(source)
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        fetched_at = datetime.fromisoformat(meta["fetched_at"].replace("Z", "+00:00"))
        age = utc_now() - fetched_at
        if age.total_seconds() < 0 or age.total_seconds() > CACHE_MAX_AGE_DAYS * 86400:
            print(f"CACHE EXPIRED {source.name}: {age.days} days")
            return None
        if meta.get("url") != source.url or not data_path.is_file() or sha256_file(data_path) != meta.get("sha256"):
            print(f"CACHE INVALID {source.name}: metadata/checksum mismatch")
            return None
        fd, temp_name = tempfile.mkstemp(prefix="cache-normalized-", suffix=".txt")
        accepted = 0
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
                with data_path.open("r", encoding="utf-8") as cached:
                    for row in cached:
                        row = row.rstrip("\r\n")
                        if "\t" not in row:
                            continue
                        scope, domain = row.split("\t", 1)
                        if scope not in {SCOPE_EXACT, SCOPE_TREE}:
                            continue
                        domain = normalize_domain(domain)
                        if not domain or is_protected_rule(domain, scope, force=is_force_blocked(domain, force_roots)):
                            continue
                        output.write(f"{scope}\t{domain}\n")
                        accepted += 1
            if not accepted:
                Path(temp_name).unlink(missing_ok=True)
                return None
        except Exception:
            Path(temp_name).unlink(missing_ok=True)
            raise
        meta = dict(meta)
        meta["cache_age_days"] = age.days
        meta["cached_rule_count"] = accepted
        print(f"CACHE {source.name}: last good snapshot {meta['fetched_at']} ({age.days} days old)")
        return Path(temp_name), meta
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


async def download_source(
    session: aiohttp.ClientSession,
    source: Source,
    semaphore: asyncio.Semaphore,
    force_roots: set[str],
) -> tuple[Path, int]:
    headers = {
        "User-Agent": f"HostsAggregator/{VERSION} (+https://github.com/TestingAvail/hosts-aggregator)",
        "Accept": "text/plain, text/*;q=0.9, */*;q=0.5",
    }
    async with semaphore:
        last_error: Exception | None = None
        for attempt in range(DOWNLOAD_ATTEMPTS):
            spool_path: Path | None = None
            try:
                async with session.get(source.url, headers=headers, timeout=REQUEST_TIMEOUT) as response:
                    if response.status != 200:
                        raise aiohttp.ClientResponseError(
                            response.request_info, response.history,
                            status=response.status, message="HTTP error", headers=response.headers,
                        )
                    content_type = response.headers.get("Content-Type", "").lower()
                    if "text/html" in content_type:
                        raise ValueError("HTML returned instead of a blocklist")
                    fd, temp_name = tempfile.mkstemp(prefix="source-", suffix=".txt")
                    spool_path = Path(temp_name)
                    raw_lines = accepted = 0
                    decoder = codecs.getincrementaldecoder("utf-8-sig")("replace")
                    pending = ""
                    skipping_long = False
                    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
                        async for chunk in response.content.iter_chunked(65536):
                            pending += decoder.decode(chunk)
                            if skipping_long:
                                if "\n" not in pending:
                                    pending = ""
                                    continue
                                pending = pending.split("\n", 1)[1]
                                skipping_long = False
                            lines = pending.split("\n")
                            pending = lines.pop()
                            for line in lines:
                                raw_lines += 1
                                if len(line) > MAX_LINE_LENGTH:
                                    continue
                                for domain, scope in parse_source_line(line.rstrip("\r"), source.default_scope, force_roots):
                                    output.write(f"{scope}\t{domain}\n")
                                    accepted += 1
                            if len(pending) > MAX_LINE_LENGTH:
                                pending = ""
                                skipping_long = True
                        pending += decoder.decode(b"", final=True)
                        if pending and len(pending) <= MAX_LINE_LENGTH:
                            raw_lines += 1
                            for domain, scope in parse_source_line(pending.rstrip("\r"), source.default_scope, force_roots):
                                output.write(f"{scope}\t{domain}\n")
                                accepted += 1
                    if accepted == 0:
                        raise ValueError("source is empty or yielded no valid DNS rules")
                    print(f"OK {source.name}: {raw_lines:,} lines, {accepted:,} accepted rules")
                    return spool_path, accepted
            except Exception as error:
                last_error = error
                if spool_path:
                    spool_path.unlink(missing_ok=True)
                status = error.status if isinstance(error, aiohttp.ClientResponseError) else None
                retryable = status is None or status in {408, 425, 429} or (status is not None and status >= 500)
                print(f"Download failed {source.name} ({attempt + 1}/{DOWNLOAD_ATTEMPTS}): {error}")
                if not retryable:
                    break
                if attempt + 1 < DOWNLOAD_ATTEMPTS:
                    await asyncio.sleep(1.5 * (2 ** attempt) + 0.25)
        raise RuntimeError(f"{source.name}: {last_error}")


async def fetch_source(
    session: aiohttp.ClientSession,
    source: Source,
    semaphore: asyncio.Semaphore,
    force_roots: set[str],
) -> dict:
    downloaded: Path | None = None
    data_path, meta_path = source_cache_paths(source)
    try:
        downloaded, accepted = await download_source(session, source, semaphore, force_roots)
        # Reject suspicious shrinkage instead of silently replacing a known
        # working feed with a suddenly much smaller partial/error response.
        try:
            previous_meta = json.loads(meta_path.read_text(encoding="utf-8"))
            previous_count = int(previous_meta.get("rule_count", 0))
        except Exception:
            previous_count = 0
        if (not ALLOW_SOURCE_SHRINK and previous_count >= MIN_SOURCE_COUNT_FOR_SHRINK_GUARD
                and accepted < previous_count * MAX_ACCEPTED_SHRINK_RATIO):
            raise RuntimeError(
                f"suspicious source shrink: {accepted:,} vs last successful {previous_count:,}; "
                "using cache if available"
            )
        fetched_at = iso_utc()
        try:
            atomic_copy(downloaded, data_path)
            atomic_json({
                "source_id": source.id,
                "source_name": source.name,
                "url": source.url,
                "fetched_at": fetched_at,
                "rule_count": accepted,
                "sha256": sha256_file(data_path),
            }, meta_path)
        except OSError as error:
            print(f"WARNING: cache write failed for {source.name}: {error}")
        return {
            "source": source, "path": downloaded, "accepted_rules": accepted,
            "status": "fresh", "last_success": fetched_at, "cache_age_days": 0,
        }
    except Exception as error:
        if downloaded:
            downloaded.unlink(missing_ok=True)
        cached = read_cache(source, force_roots)
        if cached:
            path, meta = cached
            return {
                "source": source, "path": path,
                "accepted_rules": int(meta["cached_rule_count"]),
                "status": "cached", "last_success": meta["fetched_at"],
                "cache_age_days": int(meta["cache_age_days"]), "download_error": str(error),
            }
        return {"source": source, "status": "failed", "error": str(error)}


def load_previous_host_count(path: Path) -> int:
    if not path.is_file():
        return 0
    count = 0
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for line in stream:
            if line.startswith("0.0.0.0 "):
                count += 1
    return count


async def build_profile(profile: str) -> dict:
    started = time.monotonic()
    sources = PROFILE_SOURCES[profile]
    force_roots = set(FORCE_BLOCK_TREE)
    if profile == "FAT":
        force_roots.update(FAT_EXTRA_FORCE_BLOCK_TREE)

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_DOWNLOADS)
    connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT_DOWNLOADS, ttl_dns_cache=300)
    store = DomainStore()
    results: list[dict] = []
    try:
        async with aiohttp.ClientSession(connector=connector, raise_for_status=False) as session:
            results = await asyncio.gather(
                *(fetch_source(session, source, semaphore, force_roots) for source in sources)
            )
        failed = [item for item in results if item["status"] == "failed"]
        if failed:
            details = "; ".join(f"{item['source'].name}: {item['error']}" for item in failed)
            raise RuntimeError(
                f"{profile}: refusing partial publication; {len(failed)} required source(s) have no fresh/cache snapshot: {details}"
            )
        if not any(item["source"].primary for item in results if item["status"] in {"fresh", "cached"}):
            raise RuntimeError(f"{profile}: primary source unavailable; publication refused")

        for item in results:
            store.add_source_file(item["source"].id, item["path"])
            item["path"].unlink(missing_ok=True)

        manual = set(FORCE_BLOCK_TREE)
        if profile == "FAT":
            manual.update(FAT_EXTRA_FORCE_BLOCK_TREE)
        store.add_manual_tree_rules(manual)
        if store.count() == 0:
            raise RuntimeError(f"{profile}: empty result")

        previous_count = load_previous_host_count(ROOT / OUTPUTS[profile][0])
        if previous_count >= 1000 and store.count() < int(previous_count * 0.50):
            raise RuntimeError(
                f"{profile}: domain count dropped from {previous_count:,} to {store.count():,} (>50%); publication refused"
            )
        audit_protected_rules(store, profile)

        metrics = store.source_metrics()
        source_report = []
        for item in results:
            source = item["source"]
            source_metric = metrics.get(source.id, {
                "unique_domains": 0, "exclusive_domains": 0, "exact_domains": 0, "tree_domains": 0,
            })
            entry = {
                "id": source.id, "name": source.name, "url": source.url,
                "status": item["status"], "primary": source.primary,
                "purpose": source.purpose, "default_scope": source.default_scope,
                "accepted_rules_in_feed": int(item.get("accepted_rules", 0)),
                **source_metric,
                "notes": source.notes,
            }
            if "last_success" in item:
                entry["last_success_utc"] = item["last_success"]
                entry["cache_age_days"] = item["cache_age_days"]
            if "download_error" in item:
                entry["download_error"] = item["download_error"]
            source_report.append(entry)

        return {
            "profile": profile, "store": store, "domain_count": store.count(),
            "source_count": len(results), "configured_source_count": len(sources),
            "failed_source_count": 0, "overlap_domain_count": store.overlap_count(),
            "rule_counts": store.rule_counts(), "sources": source_report,
            "duration_seconds": round(time.monotonic() - started, 2),
        }
    except Exception:
        for item in results:
            path = item.get("path")
            if path:
                Path(path).unlink(missing_ok=True)
        store.close()
        raise


def audit_protected_rules(store: DomainStore, profile: str) -> None:
    """Reject exact blocks of protected hosts or tree rules shadowing services."""
    for protected in GOOGLE_PROTECTED_ZONES | AI_STUDIO_PROTECTED_ZONES | MANUAL_ALLOW_EXACT:
        # A tree rule at this name or any parent would match this protected host.
        for parent in suffixes(protected):
            if store.contains_rule(parent, SCOPE_TREE):
                raise RuntimeError(
                    f"{profile}: tree rule {parent} shadows protected service {protected}; publication aborted"
                )
        if store.contains_rule(protected, SCOPE_EXACT):
            raise RuntimeError(
                f"{profile}: exact rule blocks protected service {protected}; publication aborted"
            )
    print(f"{profile}: Google / AI Studio / Gemini / authentication protection: OK")


def run_self_tests() -> None:
    # Scope semantics: source format, not parser convenience, controls wildcarding.
    assert parse_source_line("ads.example.test", SCOPE_EXACT) == [("ads.example.test", SCOPE_EXACT)]
    assert parse_source_line("ads.example.test", SCOPE_TREE) == [("ads.example.test", SCOPE_TREE)]
    assert parse_source_line("0.0.0.0 ads.example.test", SCOPE_TREE) == [("ads.example.test", SCOPE_EXACT)]
    assert parse_source_line("127.0.0.1 one.example.test two.example.test", SCOPE_TREE) == [
        ("one.example.test", SCOPE_EXACT), ("two.example.test", SCOPE_EXACT)
    ]
    assert parse_source_line("||ads.example.test^", SCOPE_EXACT) == [("ads.example.test", SCOPE_TREE)]
    assert parse_source_line("*.ads.example.test", SCOPE_EXACT) == [("ads.example.test", SCOPE_TREE)]
    assert parse_source_line("*.ads.example.test", SCOPE_TREE) == [("ads.example.test", SCOPE_TREE)]
    assert parse_source_line("||ads.example.test^$third-party", SCOPE_EXACT) == []
    assert parse_source_line("@@||ads.example.test^", SCOPE_EXACT) == []
    assert parse_source_line("||*.example.test^", SCOPE_EXACT) == []
    assert parse_source_line("пример.рф", SCOPE_EXACT) == [("xn--e1afmkfd.xn--p1ai", SCOPE_EXACT)]
    assert parse_source_line("invalid token extra", SCOPE_EXACT) == []

    # Google protected zones cannot be covered by an imported broad parent.
    assert parse_source_line("google.com", SCOPE_TREE) == []
    assert parse_source_line("googleapis.com", SCOPE_TREE) == []
    assert parse_source_line("aistudio.google.com", SCOPE_TREE) == []
    assert parse_source_line("generativelanguage.googleapis.com", SCOPE_EXACT) == []
    assert parse_source_line("*.generativelanguage.googleapis.com", SCOPE_EXACT) == []
    assert parse_source_line("google.com", SCOPE_TREE, force_roots={"google.com"}) == []
    assert parse_source_line("aistudio.google.com", SCOPE_TREE, force_roots={"aistudio.google.com"}) == []
    # Narrow explicitly reviewed ad endpoints can override a broad allowlist.
    assert parse_source_line("adservice.google.com", SCOPE_TREE) == [("adservice.google.com", SCOPE_TREE)]
    assert parse_source_line("ads.mail.ru", SCOPE_TREE) == [("ads.mail.ru", SCOPE_TREE)]
    assert parse_source_line("tracker.mail.ru", SCOPE_TREE) == []

    # False-positive examples sampled from Schakal's unique set are excluded.
    assert parse_source_line("www.baihe.com", SCOPE_EXACT) == []
    assert parse_source_line("jobs.sciencecareers.org", SCOPE_EXACT) == []
    assert parse_source_line("cardlytics.com", SCOPE_EXACT) == []
    # Exceptions are exact, not blanket parent-tree allowlists.
    assert parse_source_line("tracking.cardlytics.com", SCOPE_TREE) == [("tracking.cardlytics.com", SCOPE_TREE)]
    assert parse_source_line("ads.baihe.com", SCOPE_TREE) == [("ads.baihe.com", SCOPE_TREE)]
    assert parse_source_line("cardlytics.com", SCOPE_TREE) == []
    assert parse_source_line("sciencecareers.org", SCOPE_TREE) == []  # must not swallow jobs.sciencecareers.org

    # AdGuard exact vs tree renderings must remain distinct.
    store = DomainStore()
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as f:
            f.write("tree\tads.example.test\n")
            f.write("exact\tapi.legacy.example.test\n")
            f.write("exact\tchild.ads.example.test\n")
            f.write("exact\troot.example.test\n")
            source_path = Path(f.name)
        try:
            store.add_source_file("test", source_path)
        finally:
            source_path.unlink(missing_ok=True)
        from io import StringIO
        output = StringIO()
        write_adguard(store, output, "TEST")
        rendered = output.getvalue()
        assert "||ads.example.test^" in rendered
        assert "api.legacy.example.test\n" in rendered
        assert "root.example.test\n" in rendered
        assert "child.ads.example.test\n" not in rendered  # covered by tree parent
        host_output = StringIO()
        write_hosts(store, host_output, "TEST")
        host_text = host_output.getvalue()
        assert "0.0.0.0 child.ads.example.test\n" in host_text
        assert "0.0.0.0 api.legacy.example.test\n" in host_text
    finally:
        store.close()

    # Exact parent does NOT cover children; tree parent does.
    assert rule_covered_by_tree("child.example.test", {"example.test"})
    assert not rule_covered_by_tree("example.test", {"child.example.test"})
    print("Self-tests: OK")


def rule_covered_by_tree(domain: str, tree_rules: set[str]) -> bool:
    return any(parent != domain and parent in tree_rules for parent in suffixes(domain))


def write_hosts(store: DomainStore, stream: TextIO, title: str) -> int:
    stream.write(f"# Hosts Aggregator - {title}\n")
    stream.write("# Exact hostnames only. Tree-feed roots and all known expanded hosts are listed.\n")
    stream.write("# Hosts format cannot block unknown/dynamic subdomains.\n")
    stream.write("# Generated automatically; do not edit manually.\n")
    stream.write("# Sources and attribution: https://github.com/TestingAvail/hosts-aggregator/blob/main/SOURCES.md\n\n")
    count = 0
    for (domain,) in store.all_domains():
        stream.write(f"0.0.0.0 {domain}\n")
        count += 1
    return count


def write_adguard(store: DomainStore, stream: TextIO, title: str) -> int:
    stream.write(f"! Title: Hosts Aggregator - {title}\n")
    stream.write("! Format: AdGuard DNS filtering syntax\n")
    stream.write("! ||domain^ = domain and all subdomains; bare domain = exact hostname only.\n")
    stream.write("! Generated automatically; do not edit manually.\n")
    stream.write("! Sources and attribution: https://github.com/TestingAvail/hosts-aggregator/blob/main/SOURCES.md\n\n")

    tree_rules: set[str] = set()
    tree_cursor = store.db.execute("SELECT domain FROM rules WHERE scope='tree' ORDER BY length(domain),domain")
    count = 0
    for (domain,) in tree_cursor:
        if rule_covered_by_tree(domain, tree_rules):
            continue
        stream.write(f"||{domain}^\n")
        tree_rules.add(domain)
        count += 1

    exact_cursor = store.db.execute("SELECT domain FROM rules WHERE scope='exact' ORDER BY domain")
    for (domain,) in exact_cursor:
        if rule_covered_by_tree(domain, tree_rules):
            continue
        stream.write(f"{domain}\n")
        count += 1

    return count


def stage_file(target: Path, writer: Callable[[TextIO], object]) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".blocklist-", dir=target.parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            writer(stream)
        os.chmod(temp_name, 0o644)
        return Path(temp_name)
    except Exception:
        Path(temp_name).unlink(missing_ok=True)
        raise


def atomic_publish(staged: dict[Path, Path]) -> None:
    backups: dict[Path, Path] = {}
    published: list[Path] = []
    preserve_backups = False
    try:
        for target in staged:
            if target.exists():
                fd, backup_name = tempfile.mkstemp(prefix=".backup-", dir=target.parent)
                os.close(fd)
                Path(backup_name).unlink(missing_ok=True)
                os.replace(target, backup_name)
                backups[target] = Path(backup_name)
        for target, temp in staged.items():
            os.replace(temp, target)
            published.append(target)
    except Exception:
        for target in published:
            target.unlink(missing_ok=True)
        errors = []
        for target, backup in backups.items():
            try:
                os.replace(backup, target)
            except OSError as error:
                errors.append(f"{target.name}: {error}")
        if errors:
            preserve_backups = True
            raise RuntimeError("Rollback failed; backups retained: " + "; ".join(errors))
        raise
    finally:
        for temp in staged.values():
            temp.unlink(missing_ok=True)
        if not preserve_backups:
            for backup in backups.values():
                backup.unlink(missing_ok=True)


def stage_source_map(profiles: list[dict]) -> tuple[Path, int]:
    """Stage a compressed provenance map: profile, source, scope, domain."""
    fd, temp_name = tempfile.mkstemp(prefix=".source-map-", suffix=".tsv.gz", dir=ROOT)
    os.close(fd)
    rows = 0
    try:
        with gzip.open(temp_name, "wt", encoding="utf-8", newline="\n", compresslevel=6) as stream:
            stream.write("profile\tsource_id\tdomain\tscope\n")
            for result in profiles:
                profile = result["profile"]
                cursor = result["store"].db.execute(
                    "SELECT source_id,domain,scope FROM source_domains ORDER BY source_id,domain"
                )
                for source_id, domain, scope in cursor:
                    stream.write(f"{profile}\t{source_id}\t{domain}\t{scope}\n")
                    rows += 1
        os.chmod(temp_name, 0o644)
        return Path(temp_name), rows
    except Exception:
        Path(temp_name).unlink(missing_ok=True)
        raise


def publish_generation(profiles: list[dict]) -> dict:
    staged: dict[Path, Path] = {}
    output_info: dict[str, dict] = {}
    report_path = ROOT / "build-report.json"
    checksum_path = ROOT / "SHA256SUMS"
    try:
        for result in profiles:
            profile = result["profile"]
            hosts_name, adguard_name = OUTPUTS[profile]
            hosts_target = ROOT / hosts_name
            adguard_target = ROOT / adguard_name
            staged[hosts_target] = stage_file(
                hosts_target, lambda stream, r=result: write_hosts(r["store"], stream, r["profile"])
            )
            staged[adguard_target] = stage_file(
                adguard_target, lambda stream, r=result: write_adguard(r["store"], stream, r["profile"])
            )
            output_info[hosts_name] = {
                "entries": result["domain_count"], "bytes": staged[hosts_target].stat().st_size,
                "sha256": sha256_file(staged[hosts_target]), "format": "hosts; exact hostnames",
            }
            with staged[adguard_target].open("r", encoding="utf-8") as stream:
                rule_count = sum(1 for line in stream if line.strip() and not line.lstrip().startswith(("!", "#")))
            output_info[adguard_name] = {
                "rules": rule_count, "bytes": staged[adguard_target].stat().st_size,
                "sha256": sha256_file(staged[adguard_target]), "format": "AdGuard DNS exact + domain-tree rules",
            }

        source_map_path, source_map_rows = stage_source_map(profiles)
        source_map_target = ROOT / "source-map.tsv.gz"
        staged[source_map_target] = source_map_path
        output_info["source-map.tsv.gz"] = {
            "rows": source_map_rows, "bytes": source_map_path.stat().st_size,
            "sha256": sha256_file(source_map_path),
            "format": "gzip TSV: profile, source_id, domain, scope",
        }

        report = {
            "schema_version": 2,
            "builder_version": VERSION,
            "generated_at_utc": iso_utc(),
            "semantics": {
                "hosts": "Exact hostnames only; legacy expanded feeds enumerate known subdomains, unknown/dynamic subdomains cannot be represented.",
                "adguard": "ABP ||domain^ rules retain domain-tree scope; bare domain rules retain exact-host scope.",
                "dns_audit": "Non-destructive only; no domain is automatically removed based on liveness checks.",
            },
            "policy": {
                "schakal_source_enabled": ENABLE_SCHAKAL_SOURCE,
                "schakal_redistribution_license_review": "Schakal is enabled by default as an exact-host FAT supplement; the reviewed public forum post did not identify an explicit open redistribution license, so maintain attribution and verify or obtain permission for public redistribution.",
                "all_configured_sources_required": True,
                "source_cache_max_age_days": CACHE_MAX_AGE_DAYS,
                "allow_source_shrink_override_enabled": ALLOW_SOURCE_SHRINK,
                "allowlisted_tree_count": len(WHITELIST_TREE),
                "allowlisted_exact_count": len(MANUAL_ALLOW_EXACT),
                "manual_force_block_tree_count": len(FORCE_BLOCK_TREE),
            },
            "profiles": [],
            "outputs": output_info,
        }
        for result in profiles:
            hosts_name, adguard_name = OUTPUTS[result["profile"]]
            report["profiles"].append({
                "name": result["profile"],
                "domain_count": result["domain_count"],
                "rule_counts": result["rule_counts"],
                "source_count": result["source_count"],
                "configured_source_count": result["configured_source_count"],
                "failed_source_count": result["failed_source_count"],
                "overlap_domain_count": result["overlap_domain_count"],
                "duration_seconds": result["duration_seconds"],
                "sources": result["sources"],
                "outputs": [hosts_name, adguard_name],
            })

        report_stage = stage_file(report_path, lambda stream: json.dump(report, stream, ensure_ascii=False, indent=2))
        with report_stage.open("a", encoding="utf-8") as stream:
            stream.write("\n")
        staged[report_path] = report_stage
        # source-map is a release-only diagnostic asset (ignored by git to
        # avoid a large daily repository diff). Its digest is recorded in
        # build-report.json; SHA256SUMS covers the four router files + report
        # that are also committed to main.
        checksum_content = "".join(
            f"{sha256_file(temp)}  {target.name}\n"
            for target, temp in staged.items()
            if target not in {checksum_path, source_map_target}
        )
        staged[checksum_path] = stage_file(checksum_path, lambda stream: stream.write(checksum_content))
        atomic_publish(staged)
        print("Published build generation:")
        for name, info in output_info.items():
            print(f"  {name}: {info.get('entries', info.get('rules', info.get('rows', 0))):,} entries/rules, {info['bytes']:,} bytes")
        return report
    except Exception:
        for path in staged.values():
            path.unlink(missing_ok=True)
        raise


async def async_main() -> None:
    run_self_tests()
    profiles_or_errors = await asyncio.gather(
        build_profile("FAT"), build_profile("SLIM"), return_exceptions=True
    )
    errors = [
        (name, result) for name, result in zip(("FAT", "SLIM"), profiles_or_errors)
        if isinstance(result, BaseException)
    ]
    if errors:
        for result in profiles_or_errors:
            if isinstance(result, dict):
                result["store"].close()
        raise RuntimeError("No outputs published: " + "; ".join(f"{name}: {err}" for name, err in errors))
    profiles = [profiles_or_errors[0], profiles_or_errors[1]]
    try:
        publish_generation(profiles)
    finally:
        for result in profiles:
            result["store"].close()
    print("\nFAT and SLIM successfully generated.")


def cli() -> None:
    parser = argparse.ArgumentParser(description="Build router-friendly FAT and SLIM hosts/AdGuard lists.")
    parser.add_argument("--self-test", action="store_true", help="run offline parser/output tests")
    parser.add_argument("--list-sources", action="store_true", help="show configured feeds and rule scopes")
    args = parser.parse_args()
    if args.self_test:
        run_self_tests()
        return
    if args.list_sources:
        for profile, sources in PROFILE_SOURCES.items():
            print(f"\n{profile}:")
            for source in sources:
                marker = " [PRIMARY]" if source.primary else ""
                print(f"- {source.name}{marker}\n  scope={source.default_scope}; purpose={source.purpose}\n  {source.url}")
        return
    asyncio.run(async_main())


if __name__ == "__main__":
    cli()
