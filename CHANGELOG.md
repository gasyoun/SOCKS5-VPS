# Changelog

Все заметные изменения набора SOCKS5-VPS. Формат — по мотивам
[Keep a Changelog](https://keepachangelog.com/); даты в ISO (YYYY-MM-DD).

## [0.1.0] — 2026-06-16 (ветка `add-socks5-vps-toolkit`, еще не в `main`)

Первый сбор тулкита: цепочка для доступа к Claude / Google Antigravity из РФ —
ваш трафик выходит в интернет с иностранного (или резидентного) IP.

### Added — инструменты

- **Гайд** [`claude-antigravity-socks5-vps.md`](claude-antigravity-socks5-vps.md):
  **сценарии использования** (роутинг-таблица «задача → инструмент», включая
  Telegram), выбор VPS и локации, оплата из РФ (карта/крипта/PayPal), пошаговая
  настройка, Proxifier, Chrome, Telegram, Jio/Plati/G2A, цены, troubleshooting.
- **Выходной узел** [`scripts/setup-foreign-vps.sh`](scripts/setup-foreign-vps.sh):
  Dante SOCKS5 на зарубежном VPS с обязательной авторизацией.
- **РФ-релей** [`scripts/setup-ru-relay.sh`](scripts/setup-ru-relay.sh):
  3proxy SOCKS5 с авторизацией, parent → зарубежный Dante (работает при плавающем
  домашнем IP).
- **WireGuard** [`scripts/setup-foreign-wireguard.sh`](scripts/setup-foreign-wireguard.sh):
  полноценный VPN для телефона/всех приложений (конфиг + QR).
- **MTProto для Telegram** [`scripts/setup-foreign-mtproxy.sh`](scripts/setup-foreign-mtproxy.sh):
  личный mtg-прокси с Fake TLS (не в публичных списках).
- **SSH-ключ + бастион**: [`scripts/setup-ru-sshkey.sh`](scripts/setup-ru-sshkey.sh)
  (ключ РФ→зарубеж с `from=`/`restrict`), [`scripts/setup-foreign-bastion.sh`](scripts/setup-foreign-bastion.sh)
  (запереть SSH зарубежного на IP РФ-сервера, v4+v6).
- **Windows**: [`scripts/proxy-tunnel.ps1`](scripts/proxy-tunnel.ps1) (SSH-туннель
  SOCKS5 с автоперезапуском + Scheduled Task), [`scripts/make-proxifier-profile.ps1`](scripts/make-proxifier-profile.ps1)
  (генератор профиля Proxifier `.ppx`).
- **Residential-выход (способ A и B)**: Proxifier прямо на residential-шлюз ИЛИ
  residential как `parent` РФ-релея (`RESI_*`) — резидентный IP в обход фильтров
  серверных ASN (Antigravity). Раздел «A vs B — когда какой» в гайде.
- **Общая библиотека** [`scripts/_lib.sh`](scripts/_lib.sh): единый источник
  валидаторов, детекторов и анти-локаут-логики для всех `setup-*.sh`.

### Security & hardening (заложено сразу, усилено после нескольких ревью)

- **Анти-локаут.** `ufw` сначала разрешает реальные SSH-порты (детект учитывает
  socket-активацию `ssh.socket`, нестандартные порты, `sshd_config.d`), и
  включается ТОЛЬКО если хоть одно SSH-allow применилось; `ufw_is_active` —
  fail-closed (сбой статуса → не переоткрываем SSH); `ufw_clear_port` НИКОГДА не
  удаляет SSH-правила; LC_ALL=C против локали; ufw-мутации не валят скрипт.
- **Цепочка поставки.** mtg — SHA256 fail-closed (+ опц. out-of-band пин);
  3proxy — пин commit-SHA / явное предупреждение при неаутентифицированном `.deb`.
- **Секреты.** РФ-релей — privacy-logformat (без «кто→куда» на подсанкционном
  узле); SSH-ключ ограничен `from="<egress>",restrict,port-forwarding`;
  Fake-TLS-секрет и приватный ключ WG — за интерактивным TTY (не в CI/логи);
  конфиги с паролями `chmod 600`.
- **Изоляция/валидация.** systemd-sandbox для danted/3proxy/mtg
  (`RestrictAddressFamilies` включает `AF_UNIX`/`AF_NETLINK` для резолва имен);
  строгая валидация портов (base-10), IP/CIDR, кредов (whitespace/`:`).
- **WireGuard.** IPv6-форвардинг выключен (стек v4-only, без открытого v6-релея).
- **Git.** [`.gitattributes`](.gitattributes) пинит `*.sh` на `eol=lf`, чтобы при
  checkout на Windows скрипты не получили CRLF и не сломались на сервере.

### Notes

- Скрипты **НЕ самодостаточны**: `_lib.sh` должен лежать рядом с `setup-*.sh`, и
  запускать их надо **файлом** (`sudo bash setup-*.sh`), а не через `ssh … bash -s
  < …` (там путь к `_lib.sh` не определить).
- Ядра `ufw_orchestrate` и `ufw_clear_port` проверены симуляцией (все ветки /
  SSH-исключение); скрипты проходят `bash -n`, `.ps1` — парсинг.
- Принятые как low/edge (не чинились): краткое окно delete→add правила порта на
  re-run; `ip6tables FORWARD DROP` не персистится между ребутами (нужен boot-hook);
  косметика баннеров и переустановка fail2ban на re-run.

### Next

- Боевой прогон на реальном зарубежном VPS + РФ-сервере (с аварийной консолью
  провайдера как страховкой), затем merge ветки в `main`.
