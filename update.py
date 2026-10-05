import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

URLS = [
    "https://big.oisd.nl/",
    "https://badmojr.github.io/1Hosts/Lite/hosts.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt",
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
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt"
]

WHITELIST = {
    "localhost", "local", "broadcasthost", "ip6-localhost", "vk.ru",
    "cloud.mail.ru", "s.youtube.com", "piwik.opendesktop.org", "yt3.ggpht.com",
    "suggestqueries.google.com", "redirector.googlevideo.com",
    "gstaticadssl.l.google.com", "audio-ak-spotify-com.akamaized.net",
    "stat.online.sberbank.ru", "s3.amazonaws.com"
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
    # Сортируем по длине, чтобы родительские домены обрабатывались раньше поддоменов
    sorted_domains = sorted(list(domains_set), key=len)
    result = set()

    for domain in sorted_domains:
        parts = domain.split('.')
        is_sub = False
        # Проверяем, есть ли уже родительский домен в базе
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if parent in result:
                is_sub = True
                break
        if not is_sub:result.add(domain)

    print(f"после схлопывания осталось уникальных правил: {len(result)}")
    return sorted(list(result))

def fetch_all():
    all_domains = set()
    # Качаем всё параллельно в 5 потоков, чтобы не тупить
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(fetch_url, url): url for url in URLS}
        for future in as_completed(futures):
            all_domains.update(future.result())

    return collapse_subdomains(all_domains)

def save_files(domains):
    print(f"сохраняем {len(domains)} доменов в hosts.txt")
    with open("hosts.txt", "w", encoding="utf-8") as f:
        f.write("# optimized mega hosts file by p1vov pipeline\n\n")
        for domain in domains:
            f.write(f"0.0.0.0 {domain}\n")

    abp_filename = "abp.txt"
    print(f"сохраняем оптимизированный ABP список в {abp_filename}")
    with open(abp_filename, "w", encoding="utf-8") as f:
        f.write("[Adblock Plus]\n! Title: P1vov OpenWrt-Safe ABP List\n! Description: Lean and mean blocklist for routers and extensions\n\n")
        for domain in domains:
            f.write(f"||{domain}^\n")

if __name__ == "__main__":
    final_domains = fetch_all()
    if final_domains:
        save_files(final_domains)
    else:
        print("хуйня малясь, ни одного домена не выкачалось")
