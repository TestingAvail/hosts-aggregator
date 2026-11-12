import asyncio
import aiohttp
import re
import ipaddress
import os
import tempfile
import sqlite3
import codecs

# ==========================================
# ИСХОДНЫЕ СПИСКИ
# ==========================================
FAT_URLS = [
    "https://big.oisd.nl/",
    "https://badmojr.github.io/1Hosts/Lite/hosts.txt",
    "https://filters.adtidy.org/extension/ublock/filters/1.txt",
    "https://filters.adtidy.org/extension/ublock/filters/2.txt",
    "https://filters.adtidy.org/extension/ublock/filters/207.txt",
    "https://filters.adtidy.org/extension/ublock/filters/6.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.plus-onlydomains.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.huawei-onlydomains.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.winoffice-onlydomains.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.apple-onlydomains.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.samsung-onlydomains.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.tiktok.extended-onlydomains.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.xiaomi-onlydomains.txt",
    "https://ublockorigin.github.io/uAssets/filters/badware.txt",
    "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    "https://v.firebog.net/hosts/RPiList-Malware.txt",
    "https://v.firebog.net/hosts/RPiList-Phishing.txt",
    "https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Extension/GoodbyeAds-YouTube-AdBlock.txt",
    "https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt",
    "https://adaway.org/hosts.txt",
    "https://someonewhocares.org/hosts/zero/hosts",
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt"
]

SLIM_URLS = [
    "https://small.oisd.nl/",
    "https://filters.adtidy.org/extension/ublock/filters/2.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/light-onlydomains.txt",
    "https://ublockorigin.github.io/uAssets/filters/badware.txt",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://someonewhocares.org/hosts/zero/hosts"
]

GOOGLE_PROTECTED_ZONES = {
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
}

# Explicit exceptions for cases where a source misses a known ad/tracker zone.
FORCE_BLOCK = {
    "alimama.alicdn.com", "aecpm.alicdn.com", "afp.alicdn.com", "afpmm.alicdn.com",
    "log.aliyuncs.com", "arms.aliyuncs.com", "beacon-api.aliyuncs.com", "click.aliyun.com",
    "tanx.com", "alimama.com", "alibabadns.com",
    "aplus.qwen.ai", "ss.qwen.ai", "ut.qwen.ai",
    "ads.vk.ru", "ad.vk.ru", "trk.vk.ru", "mtrk.vk.ru", "tracer.vk.ru",
    "ads.mail.ru", "ad.mail.ru", "trk.mail.ru",
    "yabs.yandex.ru", "redirect.appmetrica.yandex.com", "s.click.aliexpress.com", "piwik.opendesktop.org",
    "volces.com", "gator.volces.com", "portal101.cn", "fp-it-acc.portal101.cn",
    "snssdk.com", "byteoversea.com", "pstatp.com", "ibytedtos.com",
    "aliapp.org", "aplus.aliyun.com", "log.alipay.com",
    "aemetrics.aliexpress.ru", "fourier.aliexpress.com", "acjs.aliyun.com",
    "mmstat.com", "ru.mmstat.com", "fourier.taobao.com",
    "s-cdn.anthropic.com",
    "app-measurement.com", "firebase-settings.crashlytics.com",
    "googletagmanager.com", "www.googletagmanager.com", "doubleclick.net", "googleads.g.doubleclick.net",
    "appsflyer.com", "branch.io", "kochava.com",
    "intercom.io", "intercomcdn.com",
    "adjust.com", "adjust.world", "app.adjust.com", "app.adjust.world",
    "ucweb.com", "tbcache.com"
}

WHITELIST = {
    # Protect these zones from imported blocklist entries in both outputs.
    *GOOGLE_PROTECTED_ZONES,
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
    "qwen.ai", "api.qwen.ai", "qwenlm.ai", "qwen.com", "auth.qwen.ai", "sg-entitlement.qwen.com", "sg-member.qwen.com",
    "img.alicdn.com", "at.alicdn.com", "p.alicdn.com", "o.alicdn.com", "g.alicdn.com", "assets.alicdn.com", "aliyunga0019.com",
    "api.aliyuncs.com", "dashscope.aliyuncs.com", "dashscope-intl.aliyuncs.com",
    "rutracker.org", "rutracker.cc", "static.rutracker.cc",
    "gamecontent.io", "ws6.gamecontent.io", "challenges.cloudflare.com",
    "connectivitycheck.gstatic.com", "connectivitycheck.android.com", "clients1.google.com",
    "clients3.google.com", "play.googleapis.com", "android.clients.google.com", "time.android.com",
    "time.google.com", "pool.ntp.org", "ntp.org", "connect.rom.miui.com",
    "connectivitycheck.platform.hicloud.com", "connectivitycheck.cbg-app.huawei.com",
    "www.qualcomm.cn", "captive.apple.com", "time.apple.com", "www.msftconnecttest.com",
    "www.msftncsi.com", "time.windows.com", "detectportal.firefox.com", "nmcheck.gnome.org",
    "connectivity-check.ubuntu.com"
}

# ==========================================
# ОПТИМИЗИРОВАННЫЕ СЕТЫ ДЛЯ ПРОВЕРКИ O(1)
# ==========================================
# Заранее вычисляем всех предков белого списка
WHITELIST_PARENTS = set()
for wl_domain in WHITELIST:
    parts = wl_domain.split('.')
    for i in range(1, len(parts)):
        WHITELIST_PARENTS.add('.'.join(parts[i:]))

# Поддержка обычных доменов и Punycode (xn--)
DOMAIN_LABEL = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
ABP_DOMAIN_RULE = re.compile(r'^\|\|([^|^*$]+)\^$')
ABP_HOST_ANCHOR = re.compile(r'^\|\|(?:\*\.)?([a-z0-9.-]+)(?:\^|/|\$)', re.IGNORECASE)
ABP_URL_HOST_ANCHOR = re.compile(r'^\|https?://([a-z0-9.-]+)(?=[:/?^$|])', re.IGNORECASE)
WEB_ONLY_ABP_OPTIONS = {
    "script", "image", "stylesheet", "object", "xmlhttprequest", "subdocument",
    "font", "media", "websocket", "ping", "other", "document", "third-party",
    "popup", "popunder", "generichide", "elemhide", "specifichide", "sitekey",
    "redirect", "redirect-rule", "removeparam", "csp", "header", "replace",
    "permissions", "urlskip", "stealth", "domain",
}

def domains_overlap(first, second):
    """Whether either DNS zone is the same as, or an ancestor of, the other."""
    return first == second or first.endswith('.' + second) or second.endswith('.' + first)

def anchored_rule_host(rule):
    """Extract an ABP domain anchor, including one after an exception prefix."""
    candidate = rule[2:] if rule.startswith('@@') else rule
    match = ABP_HOST_ANCHOR.match(candidate) or ABP_URL_HOST_ANCHOR.match(candidate)
    if not match:
        return None
    host = match.group(1).lower().rstrip('.')
    labels = host.split('.')
    # ABP may anchor to a single label such as "com" or "ru".  Those are
    # not accepted as imported DNS domains, but must be recognized here so a
    # broad filter cannot evade whitelist/force overlap checks.
    if len(host) > 253 or any(
        not label or len(label) > 63 or not DOMAIN_LABEL.fullmatch(label)
        for label in labels
    ):
        return None
    return host

def valid_domain(value):
    """Validate DNS names, including IDNA A-labels and newer numeric TLDs."""
    if len(value) > 253 or not value:
        return False
    labels = value.split('.')
    if len(labels) < 2 or any(not label or len(label) > 63 or not DOMAIN_LABEL.fullmatch(label) for label in labels):
        return False
    try:
        # Reject malformed IDNA labels while accepting valid xn-- labels.
        for label in labels:
            if label.startswith('xn--'):
                label.encode('ascii').decode('idna')
    except (UnicodeError, ValueError):
        return False
    return True

def parse_line(line_str):
    line_str = line_str.strip()
    # Comments are whole lines in hosts/ABP lists. Do not truncate valid data
    # at an embedded # or ! character.
    if not line_str or line_str.startswith(('#', '!', '[')):
        return None

    # Strip inline comments only when separated from the rule by whitespace.
    line_str = re.split(r'\s+[#!]', line_str, maxsplit=1)[0].strip()
    if not line_str:
        return None

    # Only exact domains, hosts mappings, and canonical domain-wide ABP
    # rules have an unambiguous DNS equivalent. Reject all other syntax.
    abp_match = ABP_DOMAIN_RULE.fullmatch(line_str)
    if abp_match:
        line_str = abp_match.group(1)
    elif any(marker in line_str for marker in ("|", "^", "$", "*", "#")) or line_str.startswith('@@'):
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
        # A plain DNS source line must contain exactly one domain. This keeps
        # arbitrary tokens and malformed filter syntax from becoming blocks.
        if len(parts) != 1:
            return None
        raw_domain = parts[0]

    raw_domain = raw_domain.lower().strip().rstrip('.')
    
    if not raw_domain.isascii():
        try:
            raw_domain = raw_domain.encode('idna').decode('ascii')
        except UnicodeError:
            return None

    # Hosts files can contain IPv6 literals; blocklists should keep only names.
    try:
        ipaddress.ip_address(raw_domain)
        return None
    except ValueError:
        pass

    if not valid_domain(raw_domain):
        return None

    domain_parts = raw_domain.split('.')

    # Explicit blocks take precedence over false-positive allowlist entries.
    if any(
        raw_domain == forced or raw_domain.endswith('.' + forced)
        for forced in FORCE_BLOCK
    ):
        return raw_domain

    # Protect exact allowlist entries, descendants, and parent zones.
    if raw_domain in WHITELIST:
        return None
    for i in range(len(domain_parts) - 1):
        candidate = '.'.join(domain_parts[i:])
        if candidate in WHITELIST:
            return None

    # 3. Защита родителей из WHITELIST (O(1) проверка)
    if raw_domain in WHITELIST_PARENTS:
        return None

    return raw_domain

def parse_exception_line(line_str):
    """DNS blocklists have no exception syntax, so discard ABP exceptions."""
    return None

def parse_extra_abp_rule(line_str):
    """Discard ABP rules that cannot be represented as exact DNS names."""
    return None

def parse_subdomain_wildcard(line_str):
    """Wildcards are not emitted into exact-domain DNS or hosts lists."""
    return None

def parse_domains_from_line(line_str):
    """Return every hostname in a hosts mapping; ordinary rules yield 0/1."""
    stripped = line_str.strip()
    parts = stripped.split()
    if len(parts) >= 2:
        try:
            ipaddress.ip_address(parts[0])
            is_hosts_mapping = True
        except ValueError:
            is_hosts_mapping = False
    else:
        is_hosts_mapping = False
    if is_hosts_mapping:
        # Remove a trailing hosts-file comment, then keep all aliases.
        names = []
        for token in parts[1:]:
            if token.startswith(('#', '!')):
                break
            domain = parse_line(token)
            if domain:
                names.append(domain)
        return names
    domain = parse_line(line_str)
    return [domain] if domain else []

class DomainStore:
    """Disk-backed exact deduplication with a capped SQLite page cache."""
    def __init__(self):
        self.tempdir = tempfile.TemporaryDirectory(prefix="blocklist-build-")
        self.db_path = os.path.join(self.tempdir.name, "domains.sqlite3")
        self.db = sqlite3.connect(self.db_path)
        self.db.execute("PRAGMA journal_mode=OFF")
        self.db.execute("PRAGMA synchronous=OFF")
        self.db.execute("PRAGMA temp_store=FILE")
        self.db.execute("PRAGMA cache_size=-8192")  # 8 MiB SQLite cache
        self.db.execute("CREATE TABLE domains (domain TEXT PRIMARY KEY) WITHOUT ROWID")
        self.db.execute("CREATE TABLE exceptions (rule TEXT PRIMARY KEY) WITHOUT ROWID")
        self.db.execute("CREATE TABLE extra_rules (rule TEXT PRIMARY KEY) WITHOUT ROWID")

    def add_file(self, path):
        before = self.db.total_changes
        batch = []
        with open(path, encoding="utf-8") as source:
            for line in source:
                domain = line.strip()
                if domain:
                    batch.append((domain,))
                if len(batch) >= 2000:
                    self.db.executemany("INSERT OR IGNORE INTO domains VALUES (?)", batch)
                    batch.clear()
        if batch:
            self.db.executemany("INSERT OR IGNORE INTO domains VALUES (?)", batch)
        self.db.commit()
        return self.db.total_changes - before

    def add_domains(self, domains):
        self.db.executemany("INSERT OR IGNORE INTO domains VALUES (?)", ((d,) for d in domains))
        self.db.commit()

    def add_exception_file(self, path):
        before = self.db.total_changes
        batch = []
        with open(path, encoding="utf-8") as source:
            for line in source:
                rule = line.rstrip("\n")
                if rule:
                    batch.append((rule,))
                if len(batch) >= 1000:
                    self.db.executemany("INSERT OR IGNORE INTO exceptions VALUES (?)", batch)
                    batch.clear()
        if batch:
            self.db.executemany("INSERT OR IGNORE INTO exceptions VALUES (?)", batch)
        self.db.commit()
        return self.db.total_changes - before

    def add_rule_file(self, path):
        before = self.db.total_changes
        batch = []
        with open(path, encoding="utf-8") as source:
            for line in source:
                rule = line.rstrip("\n")
                if rule:
                    batch.append((rule,))
                if len(batch) >= 1000:
                    self.db.executemany("INSERT OR IGNORE INTO extra_rules VALUES (?)", batch)
                    batch.clear()
        if batch:
            self.db.executemany("INSERT OR IGNORE INTO extra_rules VALUES (?)", batch)
        self.db.commit()
        return self.db.total_changes - before

    def count(self):
        return self.db.execute("SELECT COUNT(*) FROM domains").fetchone()[0]

    def close(self):
        self.db.close()
        self.tempdir.cleanup()

async def fetch_url_async(session, url, semaphore, spool_dir):
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:159.0) Gecko/20100101 Firefox/159.0",
        "Accept": "*/*"
    }
    timeout = aiohttp.ClientTimeout(total=300, connect=20, sock_read=60)
    async with semaphore:
        for attempt in range(3):
            spool_path = None
            exception_path = None
            rules_path = None
            try:
                async with session.get(url, headers=headers, timeout=timeout) as response:
                    if response.status == 200:
                        if "text/html" in response.headers.get("Content-Type", "").lower():
                            raise ValueError("вместо списка получена HTML-страница")
                        fd, spool_path = tempfile.mkstemp(prefix="source-", suffix=".txt", dir=spool_dir)
                        exception_fd, exception_path = tempfile.mkstemp(prefix="exceptions-", suffix=".txt", dir=spool_dir)
                        rules_fd, rules_path = tempfile.mkstemp(prefix="rules-", suffix=".txt", dir=spool_dir)
                        line_count = count = exception_count = extra_count = wildcard_count = 0
                        decoder = codecs.getincrementaldecoder("utf-8")("ignore")
                        pending = ""
                        skipping_long_line = False
                        with os.fdopen(fd, "w", encoding="utf-8") as spool, os.fdopen(exception_fd, "w", encoding="utf-8") as exception_spool, os.fdopen(rules_fd, "w", encoding="utf-8") as rules_spool:
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
                                    exception = parse_exception_line(line)
                                    if exception:
                                        exception_spool.write(exception + "\n")
                                        exception_count += 1
                                        continue
                                    if len(line) > 65536:
                                        continue
                                    stripped_line = line.strip()
                                    if stripped_line.startswith(("||*.", "*.")) and "$" not in stripped_line:
                                        wildcard = parse_subdomain_wildcard(stripped_line)
                                        if wildcard:
                                            rules_spool.write(wildcard + "\n")
                                            wildcard_count += 1
                                            extra_count += 1
                                        continue
                                    # Scope-modified ABP rules must stay ABP rules;
                                    # converting them to hosts would broaden them.
                                    if "$" in line:
                                        extra = parse_extra_abp_rule(line)
                                        if extra:
                                            rules_spool.write(extra + "\n")
                                            extra_count += 1
                                        continue
                                    parsed_domains = parse_domains_from_line(line.rstrip("\r"))
                                    for domain in parsed_domains:
                                        spool.write(domain + "\n")
                                        count += 1
                                    if not parsed_domains:
                                        extra = parse_extra_abp_rule(line)
                                        if extra:
                                            rules_spool.write(extra + "\n")
                                            extra_count += 1
                                if len(pending) > 65536:
                                    pending = ""
                                    skipping_long_line = True
                            pending += decoder.decode(b"", final=True)
                            if pending:
                                line_count += 1
                                exception = parse_exception_line(pending)
                                if exception:
                                    exception_spool.write(exception + "\n")
                                    exception_count += 1
                                elif len(pending) <= 65536:
                                    stripped_pending = pending.strip()
                                    if stripped_pending.startswith(("||*.", "*.")) and "$" not in stripped_pending:
                                        wildcard = parse_subdomain_wildcard(stripped_pending)
                                        if wildcard:
                                            rules_spool.write(wildcard + "\n")
                                            wildcard_count += 1
                                            extra_count += 1
                                    elif "$" in pending:
                                        extra = parse_extra_abp_rule(pending)
                                        if extra:
                                            rules_spool.write(extra + "\n")
                                            extra_count += 1
                                    else:
                                        parsed_domains = parse_domains_from_line(pending.rstrip("\r"))
                                        for domain in parsed_domains:
                                            spool.write(domain + "\n")
                                            count += 1
                                        if not parsed_domains:
                                            extra = parse_extra_abp_rule(pending)
                                            if extra:
                                                rules_spool.write(extra + "\n")
                                                extra_count += 1
                        if count + exception_count + extra_count == 0:
                            raise ValueError("источник пуст или не содержит распознанных доменов")
                        print(f"{url}: строк {line_count}, доменов {count}, ABP-правил только для поддоменов {wildcard_count}, прочих правил ABP {extra_count - wildcard_count}, исключений {exception_count}")
                        return spool_path, exception_path, rules_path
                    raise aiohttp.ClientResponseError(
                        response.request_info, response.history,
                        status=response.status, message="HTTP error", headers=response.headers
                    )
            except Exception as e:
                if spool_path and os.path.exists(spool_path):
                    os.unlink(spool_path)
                if exception_path and os.path.exists(exception_path):
                    os.unlink(exception_path)
                if rules_path and os.path.exists(rules_path):
                    os.unlink(rules_path)
                if attempt == 2:
                    print(f"Сбой скачивания {url}: {e}")
            if attempt < 2:
                await asyncio.sleep(2)
    raise RuntimeError(f"Источник недоступен после 3 попыток: {url}")

async def fetch_all_async(urls_list):
    store = DomainStore()
    semaphore = asyncio.Semaphore(15)
    connector = aiohttp.TCPConnector(limit=15)
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [fetch_url_async(session, url, semaphore, store.tempdir.name) for url in urls_list]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        failures = [result for result in results if isinstance(result, Exception)]
        if failures:
            raise RuntimeError(f"Не загружено источников: {len(failures)}/{len(urls_list)}; файлы не будут перезаписаны") from failures[0]

        total_inserted = exception_total = rules_total = 0
        for spool_path, exception_path, rules_path in results:
            total_inserted += store.add_file(spool_path)
            exception_total += store.add_exception_file(exception_path)
            rules_total += store.add_rule_file(rules_path)
            os.unlink(spool_path)
            os.unlink(exception_path)
            os.unlink(rules_path)
        forced_domains = (parse_line(domain) for domain in FORCE_BLOCK)
        store.add_domains(domain for domain in forced_domains if domain)
        print(f"Уникальных доменов: {store.count()} (новых из источников: {total_inserted})")
        if total_inserted == 0 or store.count() == 0:
            raise RuntimeError("Источники не вернули ни одного домена; файлы не будут перезаписаны")
        return store
    except Exception:
        store.close()
        raise

def save_files(store, hosts_name, abp_name, title_prefix):
    print(f"Формируем {hosts_name}...")
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

        # Stage both complete outputs before touching either published file.
        # Keep same-directory backups so a failure during the second rename
        # can restore the previous pair instead of leaving mixed generations.
        for target in staged:
            if os.path.lexists(target):
                directory = os.path.dirname(os.path.abspath(target))
                fd, backup = tempfile.mkstemp(prefix='.blocklist-backup-', dir=directory)
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
                "Не удалось полностью откатить публикацию файлов; резервные копии сохранены: "
                + "; ".join(rollback_errors)
            )
        raise
    finally:
        for path in (*staged.values(), *backups.values()):
            if path and os.path.exists(path) and not (preserve_backups and path in backups.values()):
                os.unlink(path)
    print(f"Сохранено записей hosts: {store.count()}")

def write_hosts(store, stream, title_prefix):
    stream.write(f"# Hosts blocklist ({title_prefix})\n")
    stream.write("# Exact domain names only.\n\n")
    cursor = store.db.execute("SELECT domain FROM domains ORDER BY domain")
    for (domain,) in cursor:
        stream.write(f"0.0.0.0 {domain}\n")

def write_abp(store, stream, title_prefix):
    stream.write(f"! Title: Hosts Aggregator DNS Filter ({title_prefix})\n! Format: AdGuard Home-compatible domain rules\n\n")
    cursor = store.db.execute("SELECT domain FROM domains ORDER BY length(domain), domain")
    count = 0
    for (domain,) in cursor:
        parts = domain.split('.')
        covered = False
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if store.db.execute("SELECT 1 FROM domains WHERE domain=?", (parent,)).fetchone():
                covered = True
                break
        if not covered:
            stream.write(f"||{domain}^\n")
            count += 1
    print(f"Сохранено DNS-правил для AdGuard Home после удаления покрытых поддоменов: {count}")

def stage_file(path, writer):
    directory = os.path.dirname(os.path.abspath(path))
    fd, temp_path = tempfile.mkstemp(prefix='.blocklist-', dir=directory, text=True)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            writer(stream)
        # mkstemp creates mode 0600; published blocklists must be readable by
        # the web server or download client that serves them to routers.
        os.chmod(temp_path, 0o644)
        return temp_path
    except Exception:
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass
        raise

if __name__ == "__main__":
    print("--- Сборка FAT версии ---")
    fat_domains = asyncio.run(fetch_all_async(FAT_URLS))
    try:
        save_files(fat_domains, "hosts.txt", "abp.txt", "FAT")
    finally:
        fat_domains.close()
    
    print("\n--- Сборка SLIM версии ---")
    slim_domains = asyncio.run(fetch_all_async(SLIM_URLS))
    try:
        save_files(slim_domains, "hosts-slim.txt", "abp-slim.txt", "SLIM")
    finally:
        slim_domains.close()
