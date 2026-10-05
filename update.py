import re
import urllib.request

# список ебанутых блеклистов (hosts-формат и списки доменов)
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
WHITELIST = {"localhost", "local", "broadcasthost", "ip6-localhost", "vk.ru", "cloud.mail.ru", "s.youtube.com", "piwik.opendesktop.org", "yt3.ggpht.com", "suggestqueries.google.com", "redirector.googlevideo.com", "gstaticadssl.l.google.com", "audio-ak-spotify-com.akamaized.net", "stat.online.sberbank.ru", "s3.amazonaws.com"}

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

def fetch_domains():
    domains = set()
    for url in URLS:
        print(f"качаем базу с: {url}")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=30) as response:
                for line in response:
                    clean_domain = parse_line(line.decode("utf-8", errors="ignore"))
                    if clean_domain:
                        domains.add(clean_domain)
        except Exception as e:
            print(f"ошибка при скачивании {url}: {e}")

    return sorted(list(domains))

def save_files(domains):
    # 1. Оставляем классический hosts (если где-то на роутере пригодится)
    print(f"сохраняем {len(domains)} доменов в hosts.txt")
    with open("hosts.txt", "w", encoding="utf-8") as f:
        f.write("# paranoid mega hosts file by p1vov pipeline\n\n")
        for domain in domains:
            f.write(f"0.0.0.0 {domain}\n")

    # 2. Генерируем правильный ABP-формат для расширений в браузере
    abp_filename = "abp.txt"
    print(f"сохраняем {len(domains)} доменов в ABP-формате в {abp_filename}")
    with open(abp_filename, "w", encoding="utf-8") as f:
        f.write("[Adblock Plus]\n! Title: P1vov Optimized ABP List\n! Description: High-efficiency blocklist for extensions\n\n")
        for domain in domains:
            f.write(f"||{domain}^\n")

if __name__ == "__main__":
    all_domains = fetch_domains()
    if all_domains:
        save_files(all_domains)
    else:
        print("хуйня малясь, ни одного домена не выкачалось")
