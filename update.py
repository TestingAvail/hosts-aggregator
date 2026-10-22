import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

# Жирный набор для нормального железа
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

# Слим-набор для слабого железа (OISD + самое необходимое без археологии)
SLIM_URLS = [
    "https://big.oisd.nl/",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.plus-onlydomains.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.winoffice-onlydomains.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.apple-onlydomains.txt"
]

WHITELIST = {
    # Старая база
    "localhost", "local", "broadcasthost", "ip6-localhost", "vk.ru",
    "cloud.mail.ru", "s.youtube.com", "piwik.opendesktop.org", "yt3.ggpht.com",
    "suggestqueries.google.com", "redirector.googlevideo.com",
    "gstaticadssl.l.google.com", "audio-ak-spotify-com.akamaized.net",
    "stat.online.sberbank.ru", "s3.amazonaws.com",

    # Трекеры и прочая муть
    "yabs.yandex.ru", "redirect.appmetrica.yandex.com", "trk.mail.ru", "s.click.aliexpress.com",

    # DoH / DoT серверы
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

    # Проверка интернета и время (NTP / Connectivity Check)
    "connectivitycheck.gstatic.com", "connectivitycheck.android.com", "clients1.google.com",
    "clients3.google.com", "play.googleapis.com", "android.clients.google.com", "time.android.com",
    "time.google.com", "pool.ntp.org", "ntp.org", "connect.rom.miui.com",
    "connectivitycheck.platform.hicloud.com", "connectivitycheck.cbg-app.huawei.com",
    "www.qualcomm.cn", "captive.apple.com", "time.apple.com", "www.msftconnecttest.com",
    "www.msftncsi.com", "time.windows.com", "detectportal.firefox.com", "nmcheck.gnome.org",
    "connectivity-check.ubuntu.com"
}

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

    if domain and domain not in WHITELIST and "." in domain and len(domain) < 253 and " " not in domain:
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
        f.write(f"# optimized mega hosts file ({title_prefix}) by p1vov pipeline\n\n")
        for domain in domains:
            f.write(f"0.0.0.0 {domain}\n")

    print(f"сохраняем ABP список в {abp_name}")
    with open(abp_name, "w", encoding="utf-8") as f:
        f.write(f"[Adblock Plus]\n! Title: P1vov OpenWrt-Safe ABP List ({title_prefix})\n! Description: Lean and mean blocklist\n\n")
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
