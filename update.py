#!/usr/bin/env python3
"""Build router-friendly DNS/hosts blocklists from curated public sources.

The builder is deliberately conservative:
- source snapshots are cached and reused temporarily during upstream outages;
- no source is silently replaced by an empty download;
- every accepted hostname is attributed to its source for overlap reporting;
- all four public output filenames and formats remain stable;
- all outputs are staged and published as one recoverable generation.
"""
from __future__ import annotations

import argparse
import asyncio
import codecs
import hashlib
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
from typing import Callable, Iterable

import aiohttp

VERSION = "3.0.0"
ROOT = Path(__file__).resolve().parent
CACHE_DIR = Path(os.environ.get("SOURCE_CACHE_DIR", ROOT / ".source-cache"))
CACHE_MAX_AGE_DAYS = int(os.environ.get("SOURCE_CACHE_MAX_AGE_DAYS", "45"))
MAX_CONCURRENT_DOWNLOADS = 8
DOWNLOAD_ATTEMPTS = 3
MAX_LINE_LENGTH = 65536
INSERT_BATCH_SIZE = 5000
MIN_SOURCE_RATIO = {"FAT": 0.75, "SLIM": 0.50}
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=180, connect=20, sock_read=60)

@dataclass(frozen=True)
class Source:
    id: str
    name: str
    url: str
    primary: bool = False

HAGEZI_PRO_PLUS = (
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/"
    "wildcard/pro.plus-onlydomains.txt"
)
HAGEZI_TIF_MINI = (
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/"
    "wildcard/tif.mini-onlydomains.txt"
)
HAGEZI_LIGHT = (
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/"
    "wildcard/light-onlydomains.txt"
)

# FAT is deliberately a union of different curation approaches. StevenBlack
# already aggregates several well-known hosts feeds, so we do not separately
# add its component feeds (such as AdAway/Peter Lowe) and inflate duplication.
FAT_SOURCES = [
    Source("hagezi-pro-plus", "HaGeZi Pro++", HAGEZI_PRO_PLUS, True),
    Source("hagezi-tif-mini", "HaGeZi TIF Mini", HAGEZI_TIF_MINI),
    Source("oisd-big", "OISD Big", "https://big.oisd.nl/"),
    Source(
        "goodbyeads", "GoodbyeAds",
        "https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt",
    ),
    Source(
        "stevenblack-unified", "StevenBlack Unified",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    ),
    Source(
        "phishing-army", "Phishing Army Extended",
        "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    ),
]
SLIM_SOURCES = [
    Source("hagezi-light", "HaGeZi Light", HAGEZI_LIGHT, True),
    Source("oisd-small", "OISD Small", "https://small.oisd.nl/"),
]

OUTPUTS = {
    "FAT": ("hosts.txt", "abp.txt"),
    "SLIM": ("hosts-slim.txt", "abp-slim.txt"),
}
PROFILE_SOURCES = {"FAT": FAT_SOURCES, "SLIM": SLIM_SOURCES}

GOOGLE_PROTECTED_ZONES = {'google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com'}

AI_STUDIO_PROTECTED_ZONES = {'aistudio.google.com', 'makersuite.google.com', 'ai.google.dev', 'generativelanguage.googleapis.com', 'accounts.google.com', 'oauth2.googleapis.com', 'apis.google.com', 'www.googleapis.com', 'fonts.googleapis.com', 'fonts.gstatic.com'}

FORCE_BLOCK = {'alimama.alicdn.com', 'aecpm.alicdn.com', 'afp.alicdn.com', 'afpmm.alicdn.com', 'log.aliyuncs.com', 'arms.aliyuncs.com', 'beacon-api.aliyuncs.com', 'click.aliyun.com', 'tanx.com', 'alimama.com', 'aplus.qwen.ai', 'ss.qwen.ai', 'ut.qwen.ai', 'ads.vk.ru', 'ad.vk.ru', 'trk.vk.ru', 'mtrk.vk.ru', 'tracer.vk.ru', 'ads.mail.ru', 'ad.mail.ru', 'trk.mail.ru', 'yabs.yandex.ru', 'redirect.appmetrica.yandex.com', 's.click.aliexpress.com', 'aemetrics.aliexpress.ru', 'fourier.aliexpress.com', 'acjs.aliyun.com', 'mmstat.com', 'ru.mmstat.com', 'fourier.taobao.com', 'piwik.opendesktop.org', 'app-measurement.com', 'firebase-settings.crashlytics.com', 'googletagmanager.com', 'www.googletagmanager.com', 'adservice.google.com', 'doubleclick.net', 'doubleclick.com', 'googleads.g.doubleclick.net', 'googlesyndication.com', 'googleadservices.com', 'googletagservices.com', 'googleads.com', '2mdn.net'}

FAT_EXTRA_FORCE_BLOCK = {'appsflyer.com', 'branch.io', 'kochava.com', 'adjust.com', 'adjust.world', 'app.adjust.com', 'app.adjust.world'}

WHITELIST = {*GOOGLE_PROTECTED_ZONES, *AI_STUDIO_PROTECTED_ZONES, 'localhost', 'local', 'broadcasthost', 'ip6-localhost', 'vk.ru', 'vk.com', 'userapi.com', 'vk-cdn.net', 'cloud.mail.ru', 'mail.ru', 'imgsmail.ru', 'yt3.ggpht.com', 'redirector.googlevideo.com', 'gstaticadssl.l.google.com', 'audio-ak-spotify-com.akamaized.net', 'stat.online.sberbank.ru', 's3.amazonaws.com', 'dns.quad9.net', 'dns10.quad9.net', 'cloudflare-dns.com', 'security.cloudflare-dns.com', 'family.cloudflare-dns.com', 'one.one.one.one', '1dot1dot1dot1.cloudflare-dns.com', 'dns.google', 'common.dot.dns.yandex.net', 'safe.dot.dns.yandex.net', 'family.dot.dns.yandex.net', 'dns.comss.one', 'xbox-dns.ru', 'dns.dns-ai.ru', 'dns.bezmezhau.com', 'geohide.ru', 'eu.geohide.ru', 'us.geohide.ru', 'dns.malw.link', 'dns.zapret.moed.webshiftvpn.ru', 'dns.dagami.ru', 'freedns.controld.com', 'unfiltered.joindns4.eu', 'protective.joindns4.eu', 'child.joindns4.eu', 'web.telegram.org', 'pclead.co.uk', 'offshor.co.uk', 'cakeisalie.co.uk', 'noskomnadzor.co.uk', 'lovetrue.co.uk', 'sorokdva.co.uk', 'pyatdesyatdva.co.uk', 'kartoshka.co.uk', 'sorokodin.co.uk', 'pyatdesyatodin.co.uk', 'notelega.co.uk', 'ebally.co.uk', 'nebally.co.uk', 'havegreatday.co.uk', 'pomogite.co.uk', 'fixtelega.co.uk', 'sadnews.co.uk', 'onedaychamp.co.uk', 'stopblocking.co.uk', 'nothingthere.co.uk', 'qwen.ai', 'api.qwen.ai', 'qwenlm.ai', 'qwen.com', 'auth.qwen.ai', 'sg-entitlement.qwen.com', 'sg-member.qwen.com', 'img.alicdn.com', 'at.alicdn.com', 'p.alicdn.com', 'o.alicdn.com', 'g.alicdn.com', 'assets.alicdn.com', 'aliyunga0019.com', 'api.aliyuncs.com', 'dashscope.aliyuncs.com', 'dashscope-intl.aliyuncs.com', 'rutracker.org', 'rutracker.cc', 'static.rutracker.cc', 'gamecontent.io', 'ws6.gamecontent.io', 'challenges.cloudflare.com', 'connectivitycheck.gstatic.com', 'connectivitycheck.android.com', 'clients1.google.com', 'clients3.google.com', 'play.googleapis.com', 'android.clients.google.com', 'time.android.com', 'time.google.com', 'pool.ntp.org', 'ntp.org', 'connect.rom.miui.com', 'connectivitycheck.platform.hicloud.com', 'connectivitycheck.cbg-app.huawei.com', 'www.qualcomm.cn', 'captive.apple.com', 'time.apple.com', 'www.msftconnecttest.com', 'www.msftncsi.com', 'time.windows.com', 'detectportal.firefox.com', 'nmcheck.gnome.org', 'connectivity-check.ubuntu.com'}

# Additional manually curated Google ad endpoints are intentionally narrow.
# These override the broad Google service allowlist; do not add parent zones.
PROTECTED_SERVICE_HOSTS = set(AI_STUDIO_PROTECTED_ZONES) | set(GOOGLE_PROTECTED_ZONES)

DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
ABP_DOMAIN_RULE = re.compile(r"^\|\|([^|^*$]+)\^$")

# Every parent of a protected zone is protected too: e.g. a rule for
# googleapis.com must not be allowed to break generativelanguage.googleapis.com.
WHITELIST_PARENTS: set[str] = set()
for _zone in WHITELIST:
    _labels = _zone.split(".")
    for _index in range(1, len(_labels)):
        WHITELIST_PARENTS.add(".".join(_labels[_index:]))


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(value: datetime | None = None) -> str:
    return (value or utc_now()).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def valid_domain(value: str) -> bool:
    """Validate a normalized DNS hostname (IDNA A-labels are accepted)."""
    if not value or len(value) > 253:
        return False
    labels = value.split(".")
    if len(labels) < 2:
        return False
    if any(not label or len(label) > 63 or not DOMAIN_LABEL.fullmatch(label) for label in labels):
        return False
    try:
        for label in labels:
            if label.startswith("xn--"):
                label.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return False
    return True


def suffixes(domain: str) -> Iterable[str]:
    labels = domain.split(".")
    for index in range(len(labels)):
        yield ".".join(labels[index:])


def parse_line(line: str, force_block: set[str] | None = None) -> str | None:
    """Parse a hosts line, plain domain or exact domain-wide ABP rule.

    Unsupported ABP syntax is discarded rather than broadened into DNS rules.
    """
    if not isinstance(line, str):
        return None
    line = line.strip().lstrip("\ufeff")
    if not line or line.startswith(("#", "!", "[")):
        return None
    line = re.split(r"\s+[#!]", line, maxsplit=1)[0].strip()
    if not line:
        return None

    match = ABP_DOMAIN_RULE.fullmatch(line)
    if match:
        line = match.group(1)
    elif any(marker in line for marker in ("|", "^", "$", "*", "#")) or line.startswith("@@"):
        return None

    parts = line.split()
    if not parts:
        return None
    try:
        ipaddress.ip_address(parts[0])
        hosts_mapping = len(parts) > 1
    except ValueError:
        hosts_mapping = False

    if hosts_mapping:
        raw = parts[1]
    else:
        if len(parts) != 1:
            return None
        raw = parts[0]

    raw = raw.lower().strip().rstrip(".")
    if not raw:
        return None
    if not raw.isascii():
        try:
            raw = raw.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    try:
        ipaddress.ip_address(raw)
        return None
    except ValueError:
        pass
    if not valid_domain(raw):
        return None

    blocked = FORCE_BLOCK if force_block is None else force_block
    parts = tuple(suffixes(raw))

    # Explicit block rules take priority over broad allowlisted service zones.
    if any(part in blocked for part in parts):
        return raw

    # Do not block an allowlisted zone or any of its descendants.
    if any(part in WHITELIST for part in parts):
        return None
    # Do not block a parent of a protected zone either.
    if raw in WHITELIST_PARENTS:
        return None
    return raw


def parse_domains_from_line(line: str, force_block: set[str] | None = None) -> list[str]:
    """Return all host aliases from a hosts mapping, otherwise 0/1 domains."""
    stripped = line.strip().lstrip("\ufeff")
    parts = stripped.split()
    if len(parts) >= 2:
        try:
            ipaddress.ip_address(parts[0])
            is_hosts = True
        except ValueError:
            is_hosts = False
    else:
        is_hosts = False
    if is_hosts:
        result: list[str] = []
        for token in parts[1:]:
            if token.startswith(("#", "!")):
                break
            parsed = parse_line(token, force_block=force_block)
            if parsed:
                result.append(parsed)
        return result
    parsed = parse_line(stripped, force_block=force_block)
    return [parsed] if parsed else []


class DomainStore:
    """Disk-backed deduplication plus per-source provenance accounting."""
    def __init__(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="hosts-aggregator-")
        self.db_path = Path(self.tempdir.name) / "domains.sqlite3"
        self.db = sqlite3.connect(self.db_path)
        self.db.execute("PRAGMA journal_mode=OFF")
        self.db.execute("PRAGMA synchronous=OFF")
        self.db.execute("PRAGMA temp_store=FILE")
        self.db.execute("PRAGMA cache_size=-16384")  # 16 MiB
        self.db.execute("PRAGMA locking_mode=EXCLUSIVE")
        self.db.execute("CREATE TABLE domains (domain TEXT PRIMARY KEY) WITHOUT ROWID")
        self.db.execute(
            "CREATE TABLE source_domains (source_id TEXT NOT NULL, domain TEXT NOT NULL, "
            "PRIMARY KEY(source_id, domain)) WITHOUT ROWID"
        )

    def add_source_file(self, source_id: str, path: Path) -> int:
        before = self.db.total_changes
        batch: list[tuple[str, str]] = []
        with self.db:
            with path.open("r", encoding="utf-8") as stream:
                for line in stream:
                    domain = line.strip()
                    if domain:
                        batch.append((source_id, domain))
                    if len(batch) >= INSERT_BATCH_SIZE:
                        self.db.executemany(
                            "INSERT OR IGNORE INTO source_domains VALUES (?, ?)", batch
                        )
                        batch.clear()
            if batch:
                self.db.executemany(
                    "INSERT OR IGNORE INTO source_domains VALUES (?, ?)", batch
                )
            self.db.execute(
                "INSERT OR IGNORE INTO domains SELECT domain FROM source_domains WHERE source_id=?",
                (source_id,),
            )
        return self.db.total_changes - before

    def add_manual_domains(self, domains: Iterable[str]) -> None:
        # Manual policy rules belong in the final set, but must not distort
        # upstream source-overlap and exclusive-contribution statistics.
        with self.db:
            self.db.executemany(
                "INSERT OR IGNORE INTO domains VALUES (?)",
                ((domain,) for domain in domains),
            )

    def count(self) -> int:
        return int(self.db.execute("SELECT COUNT(*) FROM domains").fetchone()[0])

    def contains(self, domain: str) -> bool:
        return self.db.execute("SELECT 1 FROM domains WHERE domain=?", (domain,)).fetchone() is not None

    def source_metrics(self) -> dict[str, dict[str, int]]:
        rows = self.db.execute(
            "SELECT sd.source_id, COUNT(*) AS source_unique, "
            "SUM(CASE WHEN dc.source_count=1 THEN 1 ELSE 0 END) AS exclusive_count "
            "FROM source_domains sd "
            "JOIN (SELECT domain, COUNT(*) AS source_count FROM source_domains GROUP BY domain) dc "
            "ON dc.domain=sd.domain GROUP BY sd.source_id"
        ).fetchall()
        return {
            source_id: {"unique_domains": int(unique_count), "exclusive_domains": int(exclusive_count or 0)}
            for source_id, unique_count, exclusive_count in rows
        }

    def overlap_count(self) -> int:
        row = self.db.execute(
            "SELECT COUNT(*) FROM (SELECT domain FROM source_domains GROUP BY domain HAVING COUNT(*) > 1)"
        ).fetchone()
        return int(row[0])

    def close(self) -> None:
        self.db.close()
        self.tempdir.cleanup()


def _source_cache_paths(source: Source) -> tuple[Path, Path]:
    key = hashlib.sha256(f"{source.id}\n{source.url}".encode("utf-8")).hexdigest()
    return CACHE_DIR / f"{key}.txt", CACHE_DIR / f"{key}.json"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_copy(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".cache-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as output, source.open("rb") as input_stream:
            shutil.copyfileobj(input_stream, output, length=1024 * 1024)
        os.chmod(temp_name, 0o644)
        os.replace(temp_name, target)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def _atomic_json(data: dict, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".meta-", dir=target.parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.chmod(temp_name, 0o644)
        os.replace(temp_name, target)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def _read_cache(source: Source, force_block: set[str]) -> tuple[Path, dict] | None:
    data_path, meta_path = _source_cache_paths(source)
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        fetched = datetime.fromisoformat(meta["fetched_at"].replace("Z", "+00:00"))
        age = utc_now() - fetched
        if age.total_seconds() < 0 or age.total_seconds() > CACHE_MAX_AGE_DAYS * 86400:
            print(f"CACHE EXPIRED {source.name}: {age.days} дней")
            return None
        if meta.get("url") != source.url or not data_path.is_file():
            return None
        if _sha256_file(data_path) != meta.get("sha256"):
            print(f"CACHE CORRUPT {source.name}: checksum mismatch")
            return None

        fd, temp_name = tempfile.mkstemp(prefix="cache-normalized-", suffix=".txt")
        count = 0
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
                with data_path.open("r", encoding="utf-8") as cached:
                    for line in cached:
                        parsed = parse_line(line, force_block=force_block)
                        if parsed:
                            output.write(parsed + "\n")
                            count += 1
            if count == 0:
                os.unlink(temp_name)
                return None
        except Exception:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass
            raise
        meta = dict(meta)
        meta["cache_age_days"] = age.days
        meta["cached_domain_count"] = count
        print(f"CACHE {source.name}: использована последняя версия от {meta['fetched_at']} ({age.days} дн.)")
        return Path(temp_name), meta
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


async def _download_source(
    session: aiohttp.ClientSession,
    source: Source,
    semaphore: asyncio.Semaphore,
    force_block: set[str],
) -> tuple[Path, int]:
    headers = {
        "User-Agent": "HostsAggregator/3.0 (+https://github.com/TestingAvail/hosts-aggregator)",
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
                            status=response.status, message="HTTP error", headers=response.headers
                        )
                    content_type = response.headers.get("Content-Type", "").lower()
                    if "text/html" in content_type:
                        raise ValueError("источник вернул HTML вместо списка")
                    fd, temp_name = tempfile.mkstemp(prefix="source-", suffix=".txt")
                    spool_path = Path(temp_name)
                    line_count = domain_count = 0
                    decoder = codecs.getincrementaldecoder("utf-8-sig")("replace")
                    pending = ""
                    skipping_long_line = False

                    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as spool:
                        async for chunk in response.content.iter_chunked(65536):
                            pending += decoder.decode(chunk)
                            if skipping_long_line:
                                if "\n" not in pending:
                                    pending = ""
                                    continue
                                pending = pending.split("\n", 1)[1]
                                skipping_long_line = False
                            lines = pending.split("\n")
                            pending = lines.pop()
                            for line in lines:
                                line_count += 1
                                if len(line) > MAX_LINE_LENGTH:
                                    continue
                                for domain in parse_domains_from_line(line.rstrip("\r"), force_block=force_block):
                                    spool.write(domain + "\n")
                                    domain_count += 1
                            if len(pending) > MAX_LINE_LENGTH:
                                pending = ""
                                skipping_long_line = True
                        pending += decoder.decode(b"", final=True)
                        if pending and len(pending) <= MAX_LINE_LENGTH:
                            line_count += 1
                            for domain in parse_domains_from_line(pending.rstrip("\r"), force_block=force_block):
                                spool.write(domain + "\n")
                                domain_count += 1

                    if domain_count == 0:
                        raise ValueError("источник пуст или не содержит распознанных доменов")
                    print(f"OK {source.name}: строк {line_count:,}, доменов до дедупликации {domain_count:,}")
                    return spool_path, domain_count
            except Exception as error:
                last_error = error
                if spool_path and spool_path.exists():
                    spool_path.unlink()
                status = error.status if isinstance(error, aiohttp.ClientResponseError) else None
                retryable = status is None or status in {408, 425, 429} or (status is not None and status >= 500)
                print(f"Сбой {source.name} ({attempt + 1}/{DOWNLOAD_ATTEMPTS}): {error}")
                if not retryable:
                    break
                if attempt + 1 < DOWNLOAD_ATTEMPTS:
                    await asyncio.sleep((1.5 * (2 ** attempt)) + 0.2)
        raise RuntimeError(f"{source.name}: {last_error}")


async def fetch_source(
    session: aiohttp.ClientSession,
    source: Source,
    semaphore: asyncio.Semaphore,
    force_block: set[str],
) -> dict:
    """Download a source; fall back to its last verified snapshot if needed."""
    downloaded_path: Path | None = None
    try:
        downloaded_path, count = await _download_source(session, source, semaphore, force_block)
        fetched_at = iso_utc()
        data_path, meta_path = _source_cache_paths(source)
        try:
            _atomic_copy(downloaded_path, data_path)
            metadata = {
                "source_id": source.id,
                "source_name": source.name,
                "url": source.url,
                "fetched_at": fetched_at,
                "domain_count": count,
                "sha256": _sha256_file(data_path),
            }
            _atomic_json(metadata, meta_path)
        except OSError as cache_error:
            # A cache write problem must not discard a valid fresh download.
            print(f"WARNING: не удалось сохранить кэш {source.name}: {cache_error}")
        return {
            "source": source, "path": downloaded_path, "domain_count": count,
            "status": "fresh", "last_success": fetched_at,
            "cache_age_days": 0,
        }
    except Exception as error:
        if downloaded_path and downloaded_path.exists():
            downloaded_path.unlink(missing_ok=True)
        cached = _read_cache(source, force_block)
        if cached:
            path, metadata = cached
            return {
                "source": source, "path": path,
                "domain_count": metadata["cached_domain_count"],
                "status": "cached", "last_success": metadata["fetched_at"],
                "cache_age_days": metadata["cache_age_days"],
                "download_error": str(error),
            }
        return {"source": source, "status": "failed", "error": str(error)}


async def build_profile(profile: str) -> dict:
    started = time.monotonic()
    sources = PROFILE_SOURCES[profile]
    force_block = set(FORCE_BLOCK)
    if profile == "FAT":
        force_block.update(FAT_EXTRA_FORCE_BLOCK)

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_DOWNLOADS)
    connector = aiohttp.TCPConnector(
        limit=MAX_CONCURRENT_DOWNLOADS, ttl_dns_cache=300, enable_cleanup_closed=True
    )
    store = DomainStore()
    results: list[dict] = []
    try:
        async with aiohttp.ClientSession(connector=connector, raise_for_status=False) as session:
            results = await asyncio.gather(
                *(fetch_source(session, source, semaphore, force_block) for source in sources)
            )

        available = [item for item in results if item["status"] in {"fresh", "cached"}]
        primary_available = any(item["source"].primary for item in available)
        minimum = max(1, int(len(sources) * MIN_SOURCE_RATIO[profile] + 0.999999))
        failed = [item for item in results if item["status"] == "failed"]
        if len(available) < minimum or not primary_available:
            reasons = "; ".join(f"{item['source'].name}: {item['error']}" for item in failed)
            raise RuntimeError(
                f"{profile}: доступно {len(available)}/{len(sources)} источников, "
                f"минимум {minimum}; основной источник доступен: {primary_available}. {reasons}"
            )

        for item in available:
            store.add_source_file(item["source"].id, item["path"])
            if item["path"].exists() and item["path"].name.startswith(("source-", "cache-normalized-")):
                item["path"].unlink(missing_ok=True)

        manual = (parse_line(domain, force_block=force_block) for domain in force_block)
        store.add_manual_domains(domain for domain in manual if domain)

        if store.count() == 0:
            raise RuntimeError(f"{profile}: итоговый набор пуст; публикация отменена")

        previous_hosts = ROOT / OUTPUTS[profile][0]
        previous_count = 0
        if previous_hosts.is_file():
            with previous_hosts.open("r", encoding="utf-8", errors="replace") as previous:
                previous_count = sum(1 for line in previous if line.startswith("0.0.0.0 "))
        if previous_count >= 1000 and store.count() < int(previous_count * 0.55):
            raise RuntimeError(
                f"{profile}: новый набор содержит {store.count():,} доменов против "
                f"{previous_count:,} ранее опубликованных (падение более 45%). "
                "Возможна неполная загрузка источников; публикация отменена."
            )

        audit_protected_domains(store, profile)

        source_metrics = store.source_metrics()
        source_report = []
        for item in results:
            source = item["source"]
            metrics = source_metrics.get(source.id, {"unique_domains": 0, "exclusive_domains": 0})
            entry = {
                "id": source.id,
                "name": source.name,
                "url": source.url,
                "status": item["status"],
                "primary": source.primary,
                "accepted_domains_in_source": int(item.get("domain_count", 0)),
                **metrics,
            }
            if "last_success" in item:
                entry["last_success_utc"] = item["last_success"]
                entry["cache_age_days"] = item["cache_age_days"]
            if "error" in item:
                entry["error"] = item["error"]
            if "download_error" in item:
                entry["download_error"] = item["download_error"]
            source_report.append(entry)

        return {
            "profile": profile,
            "store": store,
            "domain_count": store.count(),
            "source_count": len(available),
            "configured_source_count": len(sources),
            "failed_source_count": len(failed),
            "overlap_domain_count": store.overlap_count(),
            "sources": source_report,
            "duration_seconds": round(time.monotonic() - started, 2),
        }
    except Exception:
        for item in results:
            path = item.get("path")
            if path:
                Path(path).unlink(missing_ok=True)
        store.close()
        raise


def audit_protected_domains(store: DomainStore, profile: str) -> None:
    """Fail closed if a generated entry could shadow a protected service."""
    for protected in PROTECTED_SERVICE_HOSTS:
        for parent in suffixes(protected):
            if store.contains(parent):
                raise RuntimeError(
                    f"{profile}: блокирующее правило {parent} перекрывает "
                    f"защищённый сервис {protected}; файлы не будут обновлены"
                )
    print(f"{profile}: проверка Google / AI Studio / Gemini / Auth: OK")


def run_self_tests() -> None:
    protected_samples = {
        "aistudio.google.com", "generativelanguage.googleapis.com",
        "accounts.google.com", "oauth2.googleapis.com", "fonts.gstatic.com",
    }
    for domain in protected_samples:
        if parse_line(domain) is not None:
            raise RuntimeError(f"Самопроверка: защищённый домен блокируется: {domain}")
    for domain in ("google.com", "googleapis.com", "gstatic.com", "googleusercontent.com"):
        if parse_line(domain) is not None:
            raise RuntimeError(f"Самопроверка: защищённая зона блокируется: {domain}")

    for domain in (
        "doubleclick.net", "googlesyndication.com", "adservice.google.com",
        "googletagmanager.com", "googleadservices.com",
    ):
        if parse_line(domain) is None:
            raise RuntimeError(f"Самопроверка: рекламный домен пропущен: {domain}")

    hosts = parse_domains_from_line(
        "0.0.0.0 ads.example.test aistudio.google.com ads2.example.test # test"
    )
    if hosts != ["ads.example.test", "ads2.example.test"]:
        raise RuntimeError(f"Самопроверка hosts aliases: {hosts!r}")
    if parse_line("@@||example.test^") is not None:
        raise RuntimeError("Самопроверка: ABP exception не должна быть блокировкой")
    if parse_line("||example.test^$third-party") is not None:
        raise RuntimeError("Самопроверка: ABP modifier нельзя расширять до DNS")
    if parse_line("||*.example.test^") is not None:
        raise RuntimeError("Самопроверка: wildcard нельзя превращать в exact DNS domain")
    if parse_line("пример.рф") != "xn--e1afmkfd.xn--p1ai":
        raise RuntimeError("Самопроверка IDNA/Punycode не пройдена")
    if parse_line("not a domain") is not None:
        raise RuntimeError("Самопроверка: произвольный текст принят как домен")
    print("Самопроверка парсера: OK")


def stage_file(target: Path, writer: Callable) -> Path:
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


def write_hosts(store: DomainStore, stream, title: str) -> int:
    stream.write(f"# Hosts Aggregator - {title}\n")
    stream.write("# Exact hostnames only; subdomains are blocked only when listed.\n")
    stream.write("# Generated automatically. Do not edit this file manually.\n\n")
    cursor = store.db.execute("SELECT domain FROM domains ORDER BY domain")
    count = 0
    for (domain,) in cursor:
        stream.write(f"0.0.0.0 {domain}\n")
        count += 1
    return count


def write_adguard(store: DomainStore, stream, title: str) -> int:
    stream.write(f"! Title: Hosts Aggregator - {title}\n")
    stream.write("! Format: AdGuard Home-compatible domain rules\n")
    stream.write("! Rules cover the listed domain and its subdomains.\n")
    stream.write("! Generated automatically. Do not edit this file manually.\n\n")
    # Parent zones are emitted before descendants. This reduces output size
    # without losing DNS-rule coverage in AdGuard Home.
    emitted: set[str] = set()
    cursor = store.db.execute("SELECT domain FROM domains ORDER BY length(domain), domain")
    count = 0
    for (domain,) in cursor:
        if any(parent in emitted for parent in suffixes(domain) if parent != domain):
            continue
        stream.write(f"||{domain}^\n")
        emitted.add(domain)
        count += 1
    return count


def atomic_publish(staged: dict[Path, Path]) -> None:
    """Publish all generated files together and restore previous files on failure."""
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
        for target, temp_path in staged.items():
            os.replace(temp_path, target)
            published.append(target)
    except Exception:
        for target in published:
            target.unlink(missing_ok=True)
        rollback_errors = []
        for target, backup in backups.items():
            try:
                os.replace(backup, target)
            except OSError as error:
                rollback_errors.append(f"{target.name}: {error}")
        if rollback_errors:
            preserve_backups = True
            raise RuntimeError("Rollback failed; backups preserved: " + "; ".join(rollback_errors))
        raise
    finally:
        for temp_path in staged.values():
            temp_path.unlink(missing_ok=True)
        for backup in backups.values():
            if not preserve_backups:
                backup.unlink(missing_ok=True)


def file_sha256(path: Path) -> str:
    return _sha256_file(path)


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
            hosts_stage = staged[hosts_target]
            adguard_stage = staged[adguard_target]
            output_info[hosts_name] = {
                "domain_entries": result["domain_count"],
                "bytes": hosts_stage.stat().st_size,
                "sha256": file_sha256(hosts_stage),
                "format": "hosts",
            }
            output_info[adguard_name] = {
                "domain_rules": None,
                "bytes": adguard_stage.stat().st_size,
                "sha256": file_sha256(adguard_stage),
                "format": "AdGuard Home domain rules",
            }

        report = {
            "schema_version": 1,
            "builder_version": VERSION,
            "generated_at_utc": iso_utc(),
            "description": "Aggregated router DNS/hosts blocklists. DNS liveness auditing is separate and never deletes entries automatically.",
            "profiles": [],
            "outputs": output_info,
        }
        for result in profiles:
            hosts_name, adguard_name = OUTPUTS[result["profile"]]
            report["profiles"].append({
                "name": result["profile"],
                "domain_count": result["domain_count"],
                "source_count": result["source_count"],
                "configured_source_count": result["configured_source_count"],
                "failed_source_count": result["failed_source_count"],
                "overlap_domain_count": result["overlap_domain_count"],
                "duration_seconds": result["duration_seconds"],
                "sources": result["sources"],
                "outputs": [hosts_name, adguard_name],
            })

        # Read the staged AdGuard headers/content once to count actual rules.
        for result in profiles:
            adguard_name = OUTPUTS[result["profile"]][1]
            adguard_stage = staged[ROOT / adguard_name]
            with adguard_stage.open("r", encoding="utf-8") as stream:
                rule_count = sum(1 for line in stream if line.startswith("||"))
            output_info[adguard_name]["domain_rules"] = rule_count

        report_stage = stage_file(report_path, lambda stream: json.dump(report, stream, ensure_ascii=False, indent=2))
        # json.dump writer gets a trailing newline for clean diffs.
        with report_stage.open("a", encoding="utf-8") as stream:
            stream.write("\n")
        staged[report_path] = report_stage

        checksum_lines = []
        for target, temp_path in staged.items():
            if target == checksum_path:
                continue
            checksum_lines.append(f"{file_sha256(temp_path)}  {target.name}")
        checksum_stage = stage_file(checksum_path, lambda stream: stream.write("\n".join(checksum_lines) + "\n"))
        staged[checksum_path] = checksum_stage
        atomic_publish(staged)
        print("Опубликовано поколение файлов:")
        for name, info in output_info.items():
            print(f"  {name}: {info.get('domain_entries', info.get('domain_rules')):,} записей, {info['bytes']:,} байт")
        return report
    except Exception:
        for path in staged.values():
            path.unlink(missing_ok=True)
        raise


async def main() -> None:
    run_self_tests()
    tasks = [build_profile("FAT"), build_profile("SLIM")]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    errors = [("FAT", results[0])] if isinstance(results[0], Exception) else []
    if isinstance(results[1], Exception):
        errors.append(("SLIM", results[1]))
    if errors:
        for result in results:
            if isinstance(result, dict):
                result["store"].close()
        raise RuntimeError("Поколение не опубликовано: " + "; ".join(f"{name}: {error}" for name, error in errors))
    profiles = [results[0], results[1]]
    try:
        publish_generation(profiles)
    finally:
        for result in profiles:
            result["store"].close()
    print("\nFAT и SLIM успешно собраны и опубликованы.")


def cli() -> None:
    parser = argparse.ArgumentParser(description="Build FAT and SLIM router blocklists.")
    parser.add_argument(
        "--self-test", action="store_true",
        help="run parser and compatibility tests without downloading sources",
    )
    parser.add_argument(
        "--list-sources", action="store_true",
        help="print the configured source URLs and exit",
    )
    args = parser.parse_args()
    if args.self_test:
        run_self_tests()
        return
    if args.list_sources:
        for profile, sources in PROFILE_SOURCES.items():
            print(f"\n{profile}:")
            for source in sources:
                marker = " [primary]" if source.primary else ""
                print(f"  - {source.name}{marker}\n    {source.url}")
        return
    asyncio.run(main())


if __name__ == "__main__":
    cli()
