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

# регулярка для вытаскивания доменов из всякого мусора
DOMAIN_REGEX = re.compile(
    r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9][-a-zA-Z0-9.]+)$"
)

# белые списки, чтобы не заблокировать себе важную хуйню
WHITELIST = {"localhost", "local", "broadcasthost", "ip6-localhost", "vk.ru"}


def fetch_domains():
  domains = set()
  for url in URLS:
    print(
        f"качаем порцию говна с: {url}"
    )  # без капса, чисто рабочая атмосфера
    try:
      req = urllib.request.Request(
          url, headers={"User-Agent": "Mozilla/5.0"}
      )
      with urllib.request.urlopen(req, timeout=30) as response:
        for line in response:
          line_str = line.decode("utf-8", errors="ignore").strip()

          # пропускаем комменты и пустые строки
          if not line_str or line_str.startswith("!") or line_str.startswith("#"):
            continue
            
          line_str = line_str.lstrip("|").rstrip("^")
          if "$" in line_str:
           line_str = line_str.split("$")[0]
          # если это формат hosts
          match = DOMAIN_REGEX.match(line_str)
          if match:
            domain = match.group(1).lower()
          else:
            # если это чистый домен (как в oisd)
            domain = line_str.lower().split()[0]

          if (
              domain
              and domain not in WHITELIST
              and "." in domain
              and len(domain) < 253
          ):
            domains.add(domain)
    except Exception as e:
      print(f"ошибка при скачивании {url}: {e}")

  return sorted(list(domains))


def save_hosts(domains):
  filename = "hosts.txt"
  print(f"сохраняем {len(domains)} уникальных доменов в {filename}")
  with open(filename, "w", encoding="utf-8") as f:
    f.write(
        "# auto-generated mega hosts file by p1vov-like pipeline\n\n"
    )
    for domain in domains:
      f.write(f"0.0.0.0 {domain}\n")


if __name__ == "__main__":
  all_domains = fetch_domains()
  if all_domains:
    save_hosts(all_domains)
  else:
    print("хуйня малясь, ни одного домена не выкачалось")
