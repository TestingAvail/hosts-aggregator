# 🛡️ hosts-aggregator

[![Update](https://img.shields.io/github/actions/workflow/status/TestingAvail/hosts-aggregator/update.yml?branch=main&label=update&logo=github-actions)](https://github.com/TestingAvail/hosts-aggregator/actions/workflows/update.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Скрипт собирает несколько публичных списков блокировки доменов, убирает дубликаты и вложенные поддомены, а затем публикует готовые файлы в формате hosts и Adblock Plus. Обновление выполняется ежедневно через GitHub Actions.

## 📦 Готовые списки

| Файл | Формат | Для чего |
| :--- | :--- | :--- |
| `hosts.txt` | hosts | Полный список для Pi-hole, AdGuard Home, ПК |
| `hosts-slim.txt` | hosts | Облегчённый список для слабых устройств и роутеров |
| `abp.txt` | Adblock Plus | Полный список для uBlock Origin, AdGuard и других |
| `abp-slim.txt` | Adblock Plus | Облегчённый список для расширений и мобильных клиентов |

Для каждого файла есть `.sha256` для проверки целостности. Прямая ссылка выглядит так:
`https://raw.githubusercontent.com/TestingAvail/hosts-aggregator/main/hosts.txt`

## 🚀 Использование

Скачать список и проверить контрольную сумму:

```bash
curl -sSL -o hosts.txt https://raw.githubusercontent.com/TestingAvail/hosts-aggregator/main/hosts.txt
curl -sSL -o hosts.txt.sha256 https://raw.githubusercontent.com/TestingAvail/hosts-aggregator/main/hosts.txt.sha256
sha256sum -c hosts.txt.sha256
```

- **Pi-hole / AdGuard Home:** добавьте прямую ссылку на `hosts.txt` в список блокировки.
- **uBlock Origin / AdGuard:** подключите `abp.txt` как пользовательский фильтр по URL.

## ⚙️ Как это работает

1. Workflow `.github/workflows/update.yml` запускается каждый день в 03:00 UTC или вручную.
2. `update.py` скачивает списки: 18 источников для полного набора и 4 для облегчённого.
3. Скрипт разбирает строки hosts и adblock-синтаксиса, отбрасывает комментарии и сайты из белого списка.
4. Домены, которые уже покрыты родительским доменом, удаляются. Например, если есть `example.com`, то `ads.example.com` не попадёт в список.
5. Создаются четыре файла и их `.sha256`. Workflow коммитит их в репозиторий и публикует релиз с тегом вида `hosts-YYYY.MM.DD-HHMM`.

<details>
<summary>Источники полного набора</summary>

- oisd (big.oisd.nl)
- 1Hosts Lite
- HaGeZi: pro.plus, native.huawei, native.winoffice, native.apple, native.samsung, native.tiktok.extended, native.xiaomi
- GoodbyeAds (YouTube и общий список)
- Phishing Army (extended)
- Firebog: RPiList Malware, RPiList Phishing
- AdAway
- someonewhocares.org
- pgl.yoyo.org
- StevenBlack/hosts
- hoshsadiq/adblock-nocoin-list

Облегчённый набор: oisd, HaGeZi pro.plus, native.winoffice, native.apple.

</details>

## 🛠️ Локальный запуск

Скрипт использует только стандартную библиотеку Python, отдельные зависимости не нужны.

```bash
git clone https://github.com/TestingAvail/hosts-aggregator.git
cd hosts-aggregator
python3 update.py
```

Требуется Python 3.11 или новее (так настроен workflow).

## 📄 Лицензия

Распространяется под лицензией MIT. См. [LICENSE](LICENSE).
