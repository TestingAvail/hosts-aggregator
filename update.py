import asyncio
import aiohttp
import codecs
import ipaddress
import math
import os
import re
import sqlite3
import tempfile

# ============================================================
# SOURCE SETS
# ============================================================
# FAT: strong ad/tracker blocking + a separate threat-intelligence feed.
# SLIM: a smaller, compatibility-first set.
# Do not combine multiple HaGeZi main tiers: Pro++ already contains the
# lower tiers. TIF is a separate feed and can be added to a main tier.
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

FAT_URLS = [
    HAGEZI_PRO_PLUS,
    HAGEZI_TIF_MINI,
    "https://big.oisd.nl/",
    "https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt",
]

SLIM_URLS = [
    HAGEZI_LIGHT,
    "https://small.oisd.nl/",
]

# The builder outputs exactly the same four files and retains the same
# hosts / AdGuard domain-rule formats as the original script.
OUTPUTS = {
    "FAT": ("hosts.txt", "abp.txt"),
    "SLIM": ("hosts-slim.txt", "abp-slim.txt"),
}

# A build may continue when an individual mirror/source is temporarily down,
# but it must have at least half of the configured feeds and one core ad list.
MIN_SUCCESS_RATIO = 0.50
CORE_SOURCES = {
    "FAT": {HAGEZI_PRO_PLUS, "https://big.oisd.nl/"},
    "SLIM": {HAGEZI_LIGHT, "https://small.oisd.nl/"},
}

MAX_CONCURRENT_DOWNLOADS = 8
DOWNLOAD_ATTEMPTS = 3
REQUEST_TIMEOUT = aiohttp.ClientTimeout(
    total=240,
    connect=20,
    sock_read=60,
)
MAX_LINE_LENGTH = 65536
INSERT_BATCH_SIZE = 5000

# ============================================================
# PROTECTION / ALLOWLIST
# ============================================================
# Keep the Google service zones protected from imported source domains.
# This deliberately protects the broad Google service namespace. Known ad
# serving endpoints that live below google.com are force-blocked explicitly.
GOOGLE_PROTECTED_ZONES = {
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "googleusercontent.com",
}

AI_STUDIO_PROTECTED_ZONES = {
    "aistudio.google.com",
    "makersuite.google.com",
    "ai.google.dev",
    "generativelanguage.googleapis.com",
    "accounts.google.com",
    "oauth2.googleapis.com",
    "apis.google.com",
    "www.googleapis.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
}

# Explicit ad / analytics endpoints that can be blocked without blocking
# the parent Google service namespace. Keep this list narrow and intentional.
FORCE_BLOCK = {
    "alimama.alicdn.com", "aecpm.alicdn.com", "afp.alicdn.com", "afpmm.alicdn.com",
    "log.aliyuncs.com", "arms.aliyuncs.com", "beacon-api.aliyuncs.com", "click.aliyun.com",
    "tanx.com", "alimama.com",
    "aplus.qwen.ai", "ss.qwen.ai", "ut.qwen.ai",
    "ads.vk.ru", "ad.vk.ru", "trk.vk.ru", "mtrk.vk.ru", "tracer.vk.ru",
    "ads.mail.ru", "ad.mail.ru", "trk.mail.ru",
    "yabs.yandex.ru", "redirect.appmetrica.yandex.com",
    "s.click.aliexpress.com", "aemetrics.aliexpress.ru", "fourier.aliexpress.com",
    "acjs.aliyun.com", "mmstat.com", "ru.mmstat.com", "fourier.taobao.com",
    "piwik.opendesktop.org",
    "app-measurement.com", "firebase-settings.crashlytics.com",
    "googletagmanager.com", "www.googletagmanager.com",
    "adservice.google.com", "doubleclick.net", "doubleclick.com",
    "googleads.g.doubleclick.net", "googlesyndication.com",
    "googleadservices.com", "googletagservices.com", "googleads.com", "2mdn.net",
}

# Additional attribution SDK domains are kept in FAT only. These are useful
# privacy targets but may interfere with referral/deep links in some apps.
FAT_EXTRA_FORCE_BLOCK = {
    "appsflyer.com", "branch.io", "kochava.com",
    "adjust.com", "adjust.world", "app.adjust.com", "app.adjust.world",
}

WHITELIST = {
    *GOOGLE_PROTECTED_ZONES,
    *AI_STUDIO_PROTECTED_ZONES,
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
    "child.joindns4.eu",
    "web.telegram.org", "pclead.co.uk", "offshor.co.uk", "cakeisalie.co.uk", "noskomnadzor.co.uk",
    "lovetrue.co.uk", "sorokdva.co.uk", "pyatdesyatdva.co.uk", "kartoshka.co.uk", "sorokodin.co.uk",
    "pyatdesyatodin.co.uk", "notelega.co.uk", "ebally.co.uk", "nebally.co.uk", "havegreatday.co.uk",
    "pomogite.co.uk", "fixtelega.co.uk", "sadnews.co.uk", "onedaychamp.co.uk", "stopblocking.co.uk",
    "nothingthere.co.uk",
    "qwen.ai", "api.qwen.ai", "qwenlm.ai", "qwen.com", "auth.qwen.ai",
    "sg-entitlement.qwen.com", "sg-member.qwen.com",
    "img.alicdn.com", "at.alicdn.com", "p.alicdn.com", "o.alicdn.com",
    "g.alicdn.com", "assets.alicdn.com", "aliyunga0019.com",
    "api.aliyuncs.com", "dashscope.aliyuncs.com", "dashscope-intl.aliyuncs.com",
    "rutracker.org", "rutracker.cc", "static.rutracker.cc",
    "gamecontent.io", "ws6.gamecontent.io", "challenges.cloudflare.com",
    "connectivitycheck.gstatic.com", "connectivitycheck.android.com", "clients1.google.com",
    "clients3.google.com", "play.googleapis.com", "android.clients.google.com", "time.android.com",
    "time.google.com", "pool.ntp.org", "ntp.org", "connect.rom.miui.com",
    "connectivitycheck.platform.hicloud.com", "connectivitycheck.cbg-app.huawei.com",
    "www.qualcomm.cn", "captive.apple.com", "time.apple.com", "www.msftconnecttest.com",
    "www.msftncsi.com", "time.windows.com", "detectportal.firefox.com", "nmcheck.gnome.org",
    "connectivity-check.ubuntu.com",
}

# Precompute suffixes/parents once. This keeps domain checks fast even when
# hundreds of thousands of domains are imported.
WHITELIST_PARENTS = set()
for _wl_domain in WHITELIST:
    _parts = _wl_domain.split(".")
    for _i in range(1, len(_parts)):
        WHITELIST_PARENTS.add(".".join(_parts[_i:]))

DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
ABP_DOMAIN_RULE = re.compile(r"^\|\|([^|^*$]+)\^$")


def valid_domain(value):
    """Validate DNS names, including IDNA A-labels."""
    if not value or len(value) > 253:
        return False
    labels = value.split(".")
    if len(labels) < 2:
        return False
    if any(
        not label or len(label) > 63 or not DOMAIN_LABEL.fullmatch(label)
        for label in labels
    ):
        return False
    try:
        for label in labels:
            if label.startswith("xn--"):
                label.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return False
    return True


def _suffixes(domain_parts):
    """Yield domain and each parent zone, from most specific to least."""
    for index in range(len(domain_parts)):
        yield ".".join(domain_parts[index:])


def parse_line(line_str, force_block=FORCE_BLOCK):
    """Convert a hosts/domain/canonical ABP line to one DNS hostname."""
    line_str = line_str.strip()
    if not line_str or line_str.startswith(("#", "!", "[")):
        return None

    line_str = re.split(r"\s+[#!]", line_str, maxsplit=1)[0].strip()
    if not line_str:
        return None

    # Only a canonical domain-wide rule can be represented exactly as DNS.
    abp_match = ABP_DOMAIN_RULE.fullmatch(line_str)
    if abp_match:
        line_str = abp_match.group(1)
    elif any(marker in line_str for marker in ("|", "^", "$", "*", "#")) or line_str.startswith("@@"):
        return None

    parts = line_str.split()
    if not parts:
        return None

    try:
        ipaddress.ip_address(parts[0])
        is_hosts_mapping = len(parts) > 1
    except ValueError:
        is_hosts_mapping = False

    if is_hosts_mapping:
        raw_domain = parts[1]
    else:
        if len(parts) != 1:
            return None
        raw_domain = parts[0]

    raw_domain = raw_domain.lower().strip().rstrip(".")
    if not raw_domain.isascii():
        try:
            raw_domain = raw_domain.encode("idna").decode("ascii")
        except UnicodeError:
            return None

    try:
        ipaddress.ip_address(raw_domain)
        return None
    except ValueError:
        pass

    if not valid_domain(raw_domain):
        return None

    domain_parts = raw_domain.split(".")

    # Explicit ad/tracker exceptions take precedence over general allowlists.
    if any(suffix in force_block for suffix in _suffixes(domain_parts)):
        return raw_domain

    # Whitelist exact domains and all descendants of those domains.
    if any(suffix in WHITELIST for suffix in _suffixes(domain_parts)):
        return None

    # Also avoid blocking a parent zone when a protected child exists.
    if raw_domain in WHITELIST_PARENTS:
        return None

    return raw_domain


def parse_domains_from_line(line_str, force_block=FORCE_BLOCK):
    """Return all hostnames in a hosts mapping; plain rules yield 0 or 1."""
    parts = line_str.strip().split()
    if len(parts) >= 2:
        try:
            ipaddress.ip_address(parts[0])
            is_hosts_mapping = True
        except ValueError:
            is_hosts_mapping = False
    else:
        is_hosts_mapping = False

    if is_hosts_mapping:
        domains = []
        for token in parts[1:]:
            if token.startswith(("#", "!")):
                break
            domain = parse_line(token, force_block=force_block)
            if domain:
                domains.append(domain)
        return domains

    domain = parse_line(line_str, force_block=force_block)
    return [domain] if domain else []


class DomainStore:
    """Disk-backed exact deduplication with a bounded SQLite page cache."""

    def __init__(self):
        self.tempdir = tempfile.TemporaryDirectory(prefix="blocklist-build-")
        self.db_path = os.path.join(self.tempdir.name, "domains.sqlite3")
        self.db = sqlite3.connect(self.db_path)
        self.db.execute("PRAGMA journal_mode=OFF")
        self.db.execute("PRAGMA synchronous=OFF")
        self.db.execute("PRAGMA temp_store=FILE")
        self.db.execute("PRAGMA cache_size=-16384")  # 16 MiB
        self.db.execute("PRAGMA locking_mode=EXCLUSIVE")
        self.db.execute("CREATE TABLE domains (domain TEXT PRIMARY KEY) WITHOUT ROWID")

    def add_files(self, paths):
        """Insert all parsed spool files in one transaction."""
        before = self.db.total_changes
        batch = []
        with self.db:
            for path in paths:
                with open(path, "r", encoding="utf-8") as source:
                    for line in source:
                        domain = line.strip()
                        if domain:
                            batch.append((domain,))
                        if len(batch) >= INSERT_BATCH_SIZE:
                            self.db.executemany(
                                "INSERT OR IGNORE INTO domains VALUES (?)", batch
                            )
                            batch.clear()
            if batch:
                self.db.executemany(
                    "INSERT OR IGNORE INTO domains VALUES (?)", batch
                )
        return self.db.total_changes - before

    def add_domains(self, domains):
        with self.db:
            self.db.executemany(
                "INSERT OR IGNORE INTO domains VALUES (?)",
                ((domain,) for domain in domains),
            )

    def count(self):
        return self.db.execute("SELECT COUNT(*) FROM domains").fetchone()[0]

    def contains(self, domain):
        return self.db.execute(
            "SELECT 1 FROM domains WHERE domain=?", (domain,)
        ).fetchone() is not None

    def close(self):
        self.db.close()
        self.tempdir.cleanup()


def _parse_download_line(line, spool, force_block):
    parsed = parse_domains_from_line(line, force_block=force_block)
    if parsed:
        for domain in parsed:
            spool.write(domain + "\n")
    return len(parsed)


async def fetch_url_async(session, url, semaphore, spool_dir, force_block):
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; BlocklistBuilder/2.0)",
        "Accept": "text/plain, */*;q=0.8",
    }

    async with semaphore:
        last_error = None
        for attempt in range(DOWNLOAD_ATTEMPTS):
            spool_path = None
            try:
                async with session.get(
                    url,
                    headers=headers,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                ) as response:
                    if response.status != 200:
                        raise aiohttp.ClientResponseError(
                            response.request_info,
                            response.history,
                            status=response.status,
                            message="HTTP error",
                            headers=response.headers,
                        )

                    content_type = response.headers.get("Content-Type", "").lower()
                    if "text/html" in content_type:
                        raise ValueError("вместо списка получена HTML-страница")

                    fd, spool_path = tempfile.mkstemp(
                        prefix="source-", suffix=".txt", dir=spool_dir
                    )
                    line_count = domain_count = 0
                    decoder = codecs.getincrementaldecoder("utf-8-sig")("ignore")
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
                                domain_count += _parse_download_line(
                                    line.rstrip("\r"), spool, force_block
                                )

                            if len(pending) > MAX_LINE_LENGTH:
                                pending = ""
                                skipping_long_line = True

                        pending += decoder.decode(b"", final=True)
                        if pending and len(pending) <= MAX_LINE_LENGTH:
                            line_count += 1
                            domain_count += _parse_download_line(
                                pending.rstrip("\r"), spool, force_block
                            )

                    if domain_count == 0:
                        raise ValueError("источник не содержит распознанных доменов")

                    print(
                        f"OK {url}: строк {line_count:,}, "
                        f"доменов после фильтрации {domain_count:,}"
                    )
                    return spool_path, domain_count

            except Exception as error:
                last_error = error
                if spool_path and os.path.exists(spool_path):
                    os.unlink(spool_path)

                # Permanent client errors (for example 404) do not benefit
                # from repeating the same request. Rate limits and server
                # errors remain retryable.
                status = error.status if isinstance(error, aiohttp.ClientResponseError) else None
                retryable = (
                    status is None
                    or status in {408, 425, 429}
                    or (status is not None and status >= 500)
                )
                print(
                    f"Сбой {url} (попытка {attempt + 1}/{DOWNLOAD_ATTEMPTS}): "
                    f"{error}"
                )
                if not retryable:
                    break
                if attempt + 1 < DOWNLOAD_ATTEMPTS:
                    await asyncio.sleep(1.0 + attempt * 1.5)

        raise RuntimeError(f"Источник недоступен: {url}: {last_error}")


async def fetch_all_async(urls_list, profile, extra_force_block=None):
    store = DomainStore()
    force_block = set(FORCE_BLOCK)
    if extra_force_block:
        force_block.update(extra_force_block)

    semaphore = asyncio.Semaphore(MAX_CONCURRENT_DOWNLOADS)
    connector = aiohttp.TCPConnector(
        limit=MAX_CONCURRENT_DOWNLOADS,
        ttl_dns_cache=300,
        enable_cleanup_closed=True,
    )

    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [
                fetch_url_async(
                    session, url, semaphore, store.tempdir.name, force_block
                )
                for url in urls_list
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        successful = []
        failed = []
        for url, result in zip(urls_list, results):
            if isinstance(result, Exception):
                failed.append((url, result))
            else:
                successful.append((url, result[0], result[1]))

        for url, error in failed:
            print(f"ПРОПУСК источника {url}: {error}")

        minimum_success = max(1, math.ceil(len(urls_list) * MIN_SUCCESS_RATIO))
        successful_urls = {url for url, _, _ in successful}
        has_core_source = bool(successful_urls.intersection(CORE_SOURCES[profile]))

        if len(successful) < minimum_success or not has_core_source:
            raise RuntimeError(
                f"Недостаточно надёжных источников для {profile}: "
                f"успешно {len(successful)}/{len(urls_list)}, "
                f"минимум {minimum_success}; "
                f"основной источник доступен: {'да' if has_core_source else 'нет'}. "
                "Старые файлы не будут перезаписаны."
            )

        inserted = store.add_files([path for _, path, _ in successful])
        for _, path, _ in successful:
            os.unlink(path)

        manual_domains = (
            parse_line(domain, force_block=force_block) for domain in force_block
        )
        store.add_domains(domain for domain in manual_domains if domain)

        total = store.count()
        source_domains = sum(count for _, _, count in successful)
        print(
            f"{profile}: источников {len(successful)}/{len(urls_list)}, "
            f"добавлено уникальных доменов {total:,} "
            f"(до дедупликации {source_domains:,}; новых из источников {inserted:,})"
        )

        if inserted == 0 or total == 0:
            raise RuntimeError(
                f"Источники {profile} не вернули пригодных доменов; "
                "файлы не будут перезаписаны"
            )

        audit_protected_domains(store, profile)
        return store

    except Exception:
        store.close()
        raise


def audit_protected_domains(store, profile):
    """Fail closed if any generated rule could block an AI Studio host."""
    for protected in AI_STUDIO_PROTECTED_ZONES:
        parts = protected.split(".")
        for index in range(len(parts) - 1):
            possible_blocking_parent = ".".join(parts[index:])
            if store.contains(possible_blocking_parent):
                raise RuntimeError(
                    f"Защитная проверка {profile} не пройдена: правило "
                    f"{possible_blocking_parent} перекрывает {protected}. "
                    "Файлы не будут перезаписаны."
                )

    print(
        f"Проверка исключений {profile}: AI Studio / Gemini / Google Auth "
        "не перекрываются правилами сборки"
    )


def run_self_tests():
    """Quick parser regression tests; no network access required."""
    allowed = AI_STUDIO_PROTECTED_ZONES | {
        "aistudio.google.com",
        "generativelanguage.googleapis.com",
    }
    for domain in allowed:
        if parse_line(domain) is not None:
            raise RuntimeError(f"Самопроверка: защищённый домен попал в блок: {domain}")

    must_block = {
        "doubleclick.net",
        "googlesyndication.com",
        "adservice.google.com",
        "googletagmanager.com",
    }
    for domain in must_block:
        if parse_line(domain) is None:
            raise RuntimeError(f"Самопроверка: рекламный домен не блокируется: {domain}")

    hosts = parse_domains_from_line(
        "0.0.0.0 ads.example.test aistudio.google.com ads2.example.test # local test"
    )
    if hosts != ["ads.example.test", "ads2.example.test"]:
        raise RuntimeError(f"Самопроверка hosts не пройдена: {hosts!r}")

    if parse_line("@@||aistudio.google.com^") is not None:
        raise RuntimeError("Самопроверка: ABP-исключение распознано как блокировка")
    if parse_line("||example.test^$third-party") is not None:
        raise RuntimeError("Самопроверка: ABP-правило с модификатором ошибочно расширено")

    print("Самопроверка парсера: OK")


def save_files(store, hosts_name, abp_name, title_prefix):
    print(f"Формируем {hosts_name} и {abp_name}...")
    staged = {}
    backups = {}
    published = []
    preserve_backups = False

    try:
        staged[hosts_name] = stage_file(
            hosts_name, lambda stream: write_hosts(store, stream, title_prefix)
        )
        staged[abp_name] = stage_file(
            abp_name, lambda stream: write_abp(store, stream, title_prefix)
        )

        # Both outputs are staged completely before published files are touched.
        # If either replace fails, restore the previous pair.
        for target in staged:
            if os.path.lexists(target):
                directory = os.path.dirname(os.path.abspath(target))
                fd, backup = tempfile.mkstemp(
                    prefix=".blocklist-backup-", dir=directory
                )
                os.close(fd)
                os.unlink(backup)
                os.replace(target, backup)
                backups[target] = backup

        for target, temp_path in staged.items():
            os.replace(temp_path, target)
            staged[target] = None
            published.append(target)

    except Exception:
        for target in published:
            try:
                os.unlink(target)
            except FileNotFoundError:
                pass

        rollback_errors = []
        for target, backup in backups.items():
            try:
                os.replace(backup, target)
                backups[target] = None
            except OSError as error:
                rollback_errors.append(f"{target}: {error}")

        if rollback_errors:
            preserve_backups = True
            raise RuntimeError(
                "Не удалось полностью откатить публикацию файлов; "
                "резервные копии сохранены: " + "; ".join(rollback_errors)
            )
        raise

    finally:
        for path in (*staged.values(), *backups.values()):
            if path and os.path.exists(path):
                if preserve_backups and path in backups.values():
                    continue
                os.unlink(path)

    print(f"Сохранено записей hosts: {store.count():,}")


def write_hosts(store, stream, title_prefix):
    stream.write(f"# Hosts blocklist ({title_prefix})\n")
    stream.write("# Exact domain names only.\n\n")
    cursor = store.db.execute("SELECT domain FROM domains ORDER BY domain")
    for (domain,) in cursor:
        stream.write(f"0.0.0.0 {domain}\n")


def write_abp(store, stream, title_prefix):
    stream.write(
        f"! Title: Hosts Aggregator DNS Filter ({title_prefix})\n"
        "! Format: AdGuard Home-compatible domain rules\n\n"
    )

    # Domains are ordered from shortest to longest. Remember only emitted
    # parent zones: if one is already present, it also covers this subdomain.
    emitted_parents = set()
    cursor = store.db.execute(
        "SELECT domain FROM domains ORDER BY length(domain), domain"
    )
    count = 0
    for (domain,) in cursor:
        parts = domain.split(".")
        if any(".".join(parts[index:]) in emitted_parents for index in range(1, len(parts))):
            continue
        stream.write(f"||{domain}^\n")
        emitted_parents.add(domain)
        count += 1

    print(
        "Сохранено DNS-правил для AdGuard Home после удаления покрытых "
        f"поддоменов: {count:,}"
    )


def stage_file(path, writer):
    directory = os.path.dirname(os.path.abspath(path))
    fd, temp_path = tempfile.mkstemp(
        prefix=".blocklist-", dir=directory, text=True
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            writer(stream)
        os.chmod(temp_path, 0o644)
        return temp_path
    except Exception:
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass
        raise


async def build_profile(profile, urls, extra_force_block=None):
    hosts_name, abp_name = OUTPUTS[profile]
    print(f"\n--- Сборка {profile} ---")
    store = await fetch_all_async(
        urls, profile=profile, extra_force_block=extra_force_block
    )
    try:
        save_files(store, hosts_name, abp_name, profile)
    finally:
        store.close()


async def main():
    run_self_tests()

    # Build both profiles concurrently. One profile can still finish if the
    # other has a source outage; a failed profile keeps its previous files.
    tasks = [
        build_profile("FAT", FAT_URLS, extra_force_block=FAT_EXTRA_FORCE_BLOCK),
        build_profile("SLIM", SLIM_URLS),
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    errors = []
    for profile, result in zip(("FAT", "SLIM"), results):
        if isinstance(result, Exception):
            errors.append((profile, result))
            print(f"ОШИБКА профиля {profile}: {result}")

    if errors:
        raise RuntimeError(
            "Не все профили обновлены: "
            + "; ".join(f"{profile}: {error}" for profile, error in errors)
        )

    print("\nОба профиля успешно собраны.")


if __name__ == "__main__":
    asyncio.run(main())
