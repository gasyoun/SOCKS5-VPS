# SOCKS5-VPS

_Created: 03-07-2026 · Last updated: 03-07-2026_

Набор скриптов + гайд для доступа к **Claude** и **Google Antigravity** из РФ:
поднимаем SOCKS5-прокси (или полноценный WireGuard VPN) на зарубежном VPS и
заворачиваем в него трафик нужных программ через Proxifier или SSH-туннель.

```
[Твой ПК] → Proxifier → (интернет) → [VPS за рубежом, SOCKS5] → Claude / Antigravity
```

## С чего начать

- **[claude-antigravity-socks5-vps.md](claude-antigravity-socks5-vps.md)** — полный гайд «с нуля»:
  выбор и оплата VPS, установка Dante, Proxifier, альтернативы (SSH-туннель, резидентный
  прокси), Telegram через MTProto, цены.
- **[scripts/README.md](scripts/README.md)** — назначение каждого скрипта, порядок запуска,
  таблица переменных для цепочки РФ-релей → зарубежный выходной узел.
- **[CHANGELOG.md](CHANGELOG.md)** — история версий тулкита.
- **[.ai_state.md](.ai_state.md)** — журнал сессии: что сделано, что дальше, известные trade-off'ы.

## Скрипты

| Скрипт | Где запускать | Что делает |
|---|---|---|
| [scripts/setup-foreign-vps.sh](scripts/setup-foreign-vps.sh) | зарубежный VPS | Выходной SOCKS5-узел (Dante) с авторизацией |
| [scripts/setup-ru-relay.sh](scripts/setup-ru-relay.sh) | РФ-сервер | Релей (3proxy) перед зарубежным узлом |
| [scripts/setup-foreign-wireguard.sh](scripts/setup-foreign-wireguard.sh) | зарубежный VPS | Полноценный VPN (WireGuard) |
| [scripts/setup-foreign-mtproxy.sh](scripts/setup-foreign-mtproxy.sh) | зарубежный VPS | Личный MTProto-прокси для Telegram |
| [scripts/setup-foreign-bastion.sh](scripts/setup-foreign-bastion.sh) | зарубежный VPS | Запереть SSH на IP РФ-сервера |
| [scripts/setup-ru-sshkey.sh](scripts/setup-ru-sshkey.sh) | РФ-сервер | SSH-ключ РФ → зарубеж |
| [scripts/_lib.sh](scripts/_lib.sh) | подключается всеми | Общая библиотека (валидаторы, анти-локаут) — не запускается сама |
| [scripts/proxy-tunnel.ps1](scripts/proxy-tunnel.ps1) / [scripts/make-proxifier-profile.ps1](scripts/make-proxifier-profile.ps1) | Windows-клиент | Вспомогательные PowerShell-инструменты |

Подробности и порядок запуска — в [scripts/README.md](scripts/README.md).

## Статус

Ветка `add-socks5-vps-toolkit`, ещё не влита в `main` — ждёт боевого прогона на
реальном VPS (см. [.ai_state.md](.ai_state.md) → Next Steps).

---

_Dr. Mārcis Gasūns_
