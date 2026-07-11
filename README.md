# SOCKS5-VPS

_Created: 03-07-2026 · Last updated: 11-07-2026_

Набор скриптов + гайд для доступа к **Claude** и **Google Antigravity** из РФ:
поднимаем SOCKS5-прокси (или полноценный WireGuard VPN) на зарубежном VPS и
заворачиваем в него трафик нужных программ через Proxifier или SSH-туннель.

```
[Твой ПК] → Proxifier → (интернет) → [VPS за рубежом, SOCKS5] → Claude / Antigravity
```

## С чего начать

- **[claude-antigravity-socks5-vps.md](https://github.com/gasyoun/SOCKS5-VPS/blob/main/claude-antigravity-socks5-vps.md)** — полный гайд «с нуля»:
  выбор и оплата VPS, установка Dante, Proxifier, альтернативы (SSH-туннель, резидентный
  прокси), Telegram через MTProto, цены.
- **[scripts/README.md](https://github.com/gasyoun/SOCKS5-VPS/blob/main/scripts/README.md)** — назначение каждого скрипта, порядок запуска,
  таблица переменных для цепочки РФ-релей → зарубежный выходной узел.
- **[CHANGELOG.md](https://github.com/gasyoun/SOCKS5-VPS/blob/main/CHANGELOG.md)** — история версий тулкита.
- **[.ai_state.md](https://github.com/gasyoun/SOCKS5-VPS/blob/main/.ai_state.md)** — журнал сессии: что сделано, что дальше, известные trade-off'ы.

## Скрипты

| Скрипт | Где запускать | Что делает |
|---|---|---|
| [scripts/setup-foreign-vps.sh](https://github.com/gasyoun/SOCKS5-VPS/blob/main/scripts/setup-foreign-vps.sh) | зарубежный VPS | Выходной SOCKS5-узел (Dante) с авторизацией |
| [scripts/setup-ru-relay.sh](https://github.com/gasyoun/SOCKS5-VPS/blob/main/scripts/setup-ru-relay.sh) | РФ-сервер | Релей (3proxy) перед зарубежным узлом |
| [scripts/setup-foreign-wireguard.sh](https://github.com/gasyoun/SOCKS5-VPS/blob/main/scripts/setup-foreign-wireguard.sh) | зарубежный VPS | Полноценный VPN (WireGuard) |
| [scripts/setup-foreign-mtproxy.sh](https://github.com/gasyoun/SOCKS5-VPS/blob/main/scripts/setup-foreign-mtproxy.sh) | зарубежный VPS | Личный MTProto-прокси для Telegram |
| [scripts/setup-foreign-bastion.sh](https://github.com/gasyoun/SOCKS5-VPS/blob/main/scripts/setup-foreign-bastion.sh) | зарубежный VPS | Запереть SSH на IP РФ-сервера |
| [scripts/setup-ru-sshkey.sh](https://github.com/gasyoun/SOCKS5-VPS/blob/main/scripts/setup-ru-sshkey.sh) | РФ-сервер | SSH-ключ РФ → зарубеж |
| [scripts/_lib.sh](https://github.com/gasyoun/SOCKS5-VPS/blob/main/scripts/_lib.sh) | подключается всеми | Общая библиотека (валидаторы, анти-локаут) — не запускается сама |
| [scripts/proxy-tunnel.ps1](https://github.com/gasyoun/SOCKS5-VPS/blob/main/scripts/proxy-tunnel.ps1) / [scripts/make-proxifier-profile.ps1](https://github.com/gasyoun/SOCKS5-VPS/blob/main/scripts/make-proxifier-profile.ps1) | Windows-клиент | Вспомогательные PowerShell-инструменты |

Подробности и порядок запуска — в [scripts/README.md](https://github.com/gasyoun/SOCKS5-VPS/blob/main/scripts/README.md).

## Безопасность

- Скрипты — это шаблоны: секреты (пароли, IP, ключи) задаются оператором при
  запуске и **не хранятся в репозитории**. В коммит попадают только значения по
  умолчанию (порты, имена служебных учёток вроде `proxyuser`) — не реальные креды.
- **Не коммитьте заполненные реальными значениями скрипты, конфиги и `.ppx`-профили**
  — `FOREIGN_VPS_IP` / порт / пользователь и egress-IP раскрывают топологию доступа.
- Полные сводки предупреждений (анти-локаут, brute-force, приватность логов на
  РФ-узле, цепочка поставки, юридический риск) — в
  [scripts/README.md](https://github.com/gasyoun/SOCKS5-VPS/blob/main/scripts/README.md).

## Статус

Тулкит влит в `main` (8 скриптов + 2 PowerShell + `_lib.sh` + гайд). Анти-локаут-ядра
(`ufw_orchestrate`, `ufw_clear_port`) проверены симуляцией; скрипты проходят `bash -n`.
Ещё **не было** боевого прогона на реальном зарубежном VPS + РФ-сервере — это следующий
шаг перед тем, как считать набор проверенным в бою (см.
[.ai_state.md](https://github.com/gasyoun/SOCKS5-VPS/blob/main/.ai_state.md) → Next Steps).

---

_Dr. Mārcis Gasūns_
