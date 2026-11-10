import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==========================================
# ИСХОДНЫЕ СПИСКИ (Ссылки на блоклисты)
# ==========================================
FAT_URLS = [
    "https://big.oisd.nl/",
    "https://badmojr.github.io/1Hosts/Lite/hosts.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.plus-onlydomains.txt",
    "https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Extension/GoodbyeAds-YouTube-AdBlock.txt",
    "https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt",
    "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    "https://v.firebog.net/hosts/RPiList-Malware.txt",
    "https://v.firebog.net/hosts/RPiList-Phishing.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.huawei-onlydomains.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.winoffice-onlydomains.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.apple-onlydomains.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.samsung-onlydomains.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.tiktok.extended-onlydomains.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.xiaomi-onlydomains.txt",
    "https://adaway.org/hosts.txt",
    "https://someonewhocares.org/hosts/zero/hosts",
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt"
]

SLIM_URLS = [
    "https://big.oisd.nl/",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.plus-onlydomains.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.winoffice-onlydomains.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.apple-onlydomains.txt"
]

# ==========================================
# БЕЛЫЙ СПИСОК (РАЗРЕШАЕМ РАБОТАТЬ)
# ==========================================
# ВАЖНО: Здесь только то, без чего сервисы сломаются.
# Никаких трекеров (yabs, trk.mail.ru и т.д.) здесь быть не должно!
WHITELIST = {
    # Базовое
    "localhost", "local", "broadcasthost", "ip6-localhost",

    # ВК (сайт и приложение)
    "vk.ru", "vk.com", "userapi.com", "vk-cdn.net",

    # Почта Mail.ru (без трекеров)
    "cloud.mail.ru", "mail.ru", "imgsmail.ru",

    # YouTube (CDN)
    "yt3.ggpht.com", "redirector.googlevideo.com", "gstaticadssl.l.google.com",

    # Spotify (CDN)
    "audio-ak-spotify-com.akamaized.net",

    # Сбербанк
    "stat.online.sberbank.ru", "s3.amazonaws.com",

    # DoH / DoT (чтобы DNS не сломался)
    "dns.quad9.net", "dns10.quad9.net", "cloudflare-dns.com", "security.cloudflare-dns.com",
    "family.cloudflare-dns.com", "one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com",
    "dns.google", "common.dot.dns.yandex.net", "safe.dot.dns.yandex.net", "family.dot.dns.yandex.net",
    "dns.comss.one", "xbox-dns.ru", "dns.dns-ai.ru", "dns.bezmezhau.com", "geohide.ru",
    "eu.geohide.ru", "us.geohide.ru", "dns.malw.link", "dns.zapret.moed.webshiftvpn.ru",
    "dns.dagami.ru", "freedns.controld.com", "unfiltered.joindns4.eu", "protective.joindns4.eu",
    "child.joindns4.eu",

    # TG WS Proxy
    "web.telegram.org", "pclead.co.uk", "offshor.co.uk", "cakeisalie.co.uk", "noskomnadzor.co.uk",
    "lovetrue.co.uk", "sorokdva.co.uk", "pyatdesyatdva.co.uk", "kartoshka.co.uk", "sorokodin.co.uk",
    "pyatdesyatodin.co.uk", "notelega.co.uk", "ebally.co.uk", "nebally.co.uk", "havegreatday.co.uk",
    "pomogite.co.uk", "fixtelega.co.uk", "sadnews.co.uk", "onedaychamp.co.uk", "stopblocking.co.uk",
    "nothingthere.co.uk",

    # Qwen (только функциональные домены)
    "qwen.ai", "api.qwen.ai", "qwenlm.ai",
    
    # Alibaba CDN (только для картинок и шрифтов Qwen)
    "img.alicdn.com", "at.alicdn.com", "p.alicdn.com",
    "api.aliyuncs.com", "dashscope.aliyuncs.com", "dashscope-intl.aliyuncs.com",

    # Проверка интернета (Captive Portal)
    "connectivitycheck.gstatic.com", "connectivitycheck.android.com", "clients1.google.com",
    "clients3.google.com", "play.googleapis.com", "android.clients.google.com", "time.android.com",
    "time.google.com", "pool.ntp.org", "ntp.org", "connect.rom.miui.com",
    "connectivitycheck.platform.hicloud.com", "connectivitycheck.cbg-app.huawei.com",
    "www.qualcomm.cn", "captive.apple.com", "time.apple.com", "www.msftconnecttest.com",
    "www.msftncsi.com", "time.windows.com", "detectportal.firefox.com", "nmcheck.gnome.org",
    "connectivity-check.ubuntu.com"
}

# ==========================================
# ЧЕРНЫЙ СПИСОК (БЛОКИРУЕМ ВСЕГДА)
# ==========================================
# Эти домены блокируются, даже если их "родитель" в белом списке.
FORCE_BLOCK = {
    # Реклама и трекинг Alibaba
    "alimama.alicdn.com", "aecpm.alicdn.com", "afp.alicdn.com", "afpmm.alicdn.com",
    "log.aliyuncs.com", "arms.aliyuncs.com", "beacon-api.aliyuncs.com", "click.aliyun.com",
    "tanx.com", "alimama.com",

    # Аналитика Qwen
    "aplus.qwen.ai", "ss.qwen.ai", "ut.qwen.ai",
    
    # Реклама и трекеры ВК/Mail.ru
    "ads.vk.ru", "ad.vk.ru", "trk.vk.ru", "mtrk.vk.ru", "tracer.vk.ru",
    "ads.mail.ru", "ad.mail.ru", "trk.mail.ru",
    
    # Трекеры Яндекса
    "yabs.yandex.ru", "redirect.appmetrica.yandex.com", "s.click.aliexpress.com",
    "piwik.opendesktop.org",

    # Глобальные трекеры (со скриншотов)
    "googletagmanager.com", 
    "doubleclick.net",
    "adjust.com", 
    "adjust.world",
    "ucweb.com"
}
# ==========================================
# ЛОГИКА ОБРАБОТКИ
# ==========================================
def parse_line(line_str):
    line_str = line_str.strip()
    if not line_str or line_str.startswith("!") or line_str.startswith("#"):
        return None

    line_str = line_str.lstrip("|").rstrip("^")
    if "$" in line_str:
        line_str = line_str.split("$")[0]

    parts = line_str.split()
    if not parts:
        return None

    if parts[0] in ("0.0.0.0", "127.0.0.1") and len(parts) > 1:
        domain = parts[1]
    else:
        domain = parts[0]

    domain = domain.lower().strip()

    # 1. ПРИНУДИТЕЛЬНАЯ БЛОКИРОВКА (проверка поддоменов тоже)
    if any(domain == fb or domain.endswith("." + fb) for fb in FORCE_BLOCK):
        return domain

    # 2. БЕЛЫЙ СПИСОК (точное совпадение или поддомен)
    if any(domain == wl or domain.endswith("." + wl) for wl in WHITELIST):
        return None

    # 3. ЗАЩИТА ОТ ЛОМАНИЯ БЕЛЫХ ПОДДОМЕНОВ В ABP
    # Если текущий домен является "родителем" для чего-то из белого списка,
    # мы его не блокируем. Иначе в ABP формате `||alicdn.com^` заблокирует
    # наш `img.alicdn.com` и Qwen сломается.
    if any(wl.endswith("." + domain) for wl in WHITELIST):
        return None

    # 4. Всё остальное блокируем
    if domain and "." in domain and len(domain) < 253 and " " not in domain:
        return domain
    return None

def fetch_url(url):
    domains = set()
    print(f"качаем базу: {url}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as response:
            for line in response:
                clean_domain = parse_line(line.decode("utf-8", errors="ignore"))
                if clean_domain:
                    domains.add(clean_domain)
        print(f"успешно скачано из {url}: {len(domains)} доменов")
    except Exception as e:
        print(f"ошибка при скачивании {url}: {e}")
    return domains

def collapse_subdomains(domains_set):
    print("схлопываем вложенные поддомены для разгрузки роутера...")
    sorted_domains = sorted(list(domains_set), key=len)
    result = set()

    for domain in sorted_domains:
        parts = domain.split('.')
        is_sub = False
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if parent in result:
                is_sub = True
                break
        if not is_sub:
            result.add(domain)

    print(f"после схлопывания осталось уникальных правил: {len(result)}")
    return sorted(list(result))

def fetch_all(urls_list):
    all_domains = set()
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(fetch_url, url): url for url in urls_list}
        for future in as_completed(futures):
            all_domains.update(future.result())

    return collapse_subdomains(all_domains)

def save_files(domains, hosts_name, abp_name, title_prefix):
    print(f"сохраняем {len(domains)} доменов в {hosts_name}")
    with open(hosts_name, "w", encoding="utf-8") as f:
        f.write(f"# optimized mega hosts file ({title_prefix})\n\n")
        for domain in domains:
            f.write(f"0.0.0.0 {domain}\n")

    print(f"сохраняем ABP список в {abp_name}")
    with open(abp_name, "w", encoding="utf-8") as f:
        f.write(f"[Adblock Plus]\n! Title: Hosts Aggregator ABP List ({title_prefix})\n! Description: Lean and mean blocklist\n\n")
        for domain in domains:
            f.write(f"||{domain}^\n")

if __name__ == "__main__":
    print("--- сборка FAT версии ---")
    fat_domains = fetch_all(FAT_URLS)
    if fat_domains:
        save_files(fat_domains, "hosts.txt", "abp.txt", "FAT")
    
    print("\n--- сборка SLIM версии ---")
    slim_domains = fetch_all(SLIM_URLS)
    if slim_domains:
        save_files(slim_domains, "hosts-slim.txt", "abp-slim.txt", "SLIM")
