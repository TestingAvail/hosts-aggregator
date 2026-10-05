import re
import urllib.request

# список ебанутых блеклистов (hosts-формат и списки доменов)
URLS = [
    "https://schakal.ru/hosts/hosts.txt",
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
]

WHITELIST = {"localhost", "local", "broadcasthost", "ip6-localhost", "vk.ru", "cloud.mail.ru"}

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

def save_hosts(domains):
    filename = "hosts.txt"
    print(f"сохраняем {len(domains)} уникальных доменов в {filename}")
    with open(filename, "w", encoding="utf-8") as f:
        f.write("# paranoid mega hosts file by p1vov pipeline\n\n")
        for domain in domains:
            f.write(f"0.0.0.0 {domain}\n")

if __name__ == "__main__":
    all_domains = fetch_domains()
    if all_domains:
        save_hosts(all_domains)
    else:
        print("хуйня малясь, ни одного домена не выкачалось")
