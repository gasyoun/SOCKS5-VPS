#!/usr/bin/env bash
###############################################################################
# setup-foreign-vps.sh
#
# НАЗНАЧЕНИЕ:
#   Запускается на ЗАРУБЕЖНОМ VPS (Ubuntu 24.04 / Debian 12-13).
#   Превращает чистый сервер в SOCKS5-прокси на базе Dante (dante-server)
#   с обязательной аутентификацией по логину/паролю. Это ВЫХОДНОЙ узел цепочки:
#
#     [ПК/телефон] -> [РФ-сервер] -> [ЭТОТ зарубежный VPS] -> Claude/интернет
#
#   Наружу трафик уходит с иностранного IP этого VPS.
#
# БЕЗОПАСНОСТЬ:
#   * SOCKS5 ВСЕГДА требует username/password (socksmethod: username) —
#     никаких открытых портов без аутентификации.
#   * ufw сначала разрешает OpenSSH и РЕАЛЬНЫЙ текущий SSH-порт (в т.ч. при
#     socket-активации ssh.socket на Ubuntu 22.10+/24.04), и ТОЛЬКО ПОТОМ
#     включается — чтобы не отрезать себе доступ.
#   * По умолчанию SOCKS-порт открывается в ufw ТОЛЬКО для ALLOW_FROM
#     (IP/CIDR РФ-сервера). Открыть порт всему интернету можно лишь явным
#     ALLOW_FROM="0.0.0.0/0" (выводится громкое предупреждение).
#   * umask 077 на весь скрипт; конфиг с паролем — chmod 600.
#   * Пароль НЕ пишется в syslog (logoutput только в файл с правами 600),
#     и НЕ логируется при каждом коннекте.
#
# ИДЕМПОТЕНТНОСТЬ:
#   Повторный запуск не падает: пакеты доустанавливаются при необходимости,
#   пользователь создаётся при отсутствии, пароль перезадаётся, конфиг
#   перезаписывается, правила ufw добавляются без дублей.
#
# ВНИМАНИЕ (см. residual_risks):
#   * Не передавайте PROXY_PASS в командной строке так, чтобы он попал в
#     ~/.bash_history. Либо оставьте пустым (автоген), либо экспортируйте в
#     отдельной сессии / через файл окружения с правами 600.
###############################################################################

set -euo pipefail
umask 077   # все создаваемые файлы — только для владельца (root)

# --- Подключаем общую библиотеку из каталога этого скрипта -------------------
# Общие функции (log/warn/err, валидаторы, детекторы интерфейса/SSH-портов,
# ufw-хелперы) вынесены в _lib.sh рядом со скриптом — НЕ дублируем их здесь.
_SLV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)"
if [[ -z "${_SLV_DIR}" || ! -r "${_SLV_DIR}/_lib.sh" ]]; then
  echo "ОШИБКА: рядом со скриптом не найден _lib.sh. Скопируйте _lib.sh в тот же" >&2
  echo "        каталог и запускайте как файл (sudo bash $0), а не через stdin/pipe." >&2
  exit 1
fi
# shellcheck source=/dev/null
source "${_SLV_DIR}/_lib.sh"

###############################################################################
# КОНФИГУРАЦИЯ (правьте здесь или передавайте через переменные окружения)
###############################################################################

# Порт, на котором SOCKS5 слушает входящие подключения (от РФ-сервера).
# Нестандартный по умолчанию, чтобы меньше попадать под сканеры.
SOCKS_PORT="${SOCKS_PORT:-39847}"

# Адрес, на котором Dante принимает входящие подключения.
# По умолчанию 0.0.0.0 (доступ контролируется аутентификацией + ufw ALLOW_FROM).
LISTEN_ADDR="${LISTEN_ADDR:-0.0.0.0}"

# Источник, которому ufw разрешит доступ к SOCKS-порту.
# ПО УМОЛЧАНИЮ ПУСТО => порт НЕ открывается в ufw вообще (безопасно по умолчанию):
# вы обязаны указать IP/CIDR вашего РФ-сервера, например ALLOW_FROM="203.0.113.5".
# Чтобы открыть всему интернету (НЕ рекомендуется) — ALLOW_FROM="0.0.0.0/0".
ALLOW_FROM="${ALLOW_FROM:-}"

# Имя системного пользователя для SOCKS-аутентификации (nologin-аккаунт).
PROXY_USER="${PROXY_USER:-proxyuser}"

# Пароль для SOCKS-аутентификации. Пусто => сгенерируется через openssl.
PROXY_PASS="${PROXY_PASS:-}"

# Путь к конфигу Dante (стандартный путь пакета dante-server).
DANTE_CONF="/etc/danted.conf"

# Отдельный лог-файл Dante (а не общий syslog), чтобы не размазывать
# чувствительные строки по /var/log/syslog. Права на него — 640 root:adm.
DANTE_LOG="/var/log/danted.log"

###############################################################################
# СЛУЖЕБНЫЕ ПРОВЕРКИ И ВАЛИДАТОРЫ
###############################################################################

if [[ "${EUID}" -ne 0 ]]; then
  echo "ОШИБКА: запустите скрипт от root (sudo bash $0)." >&2
  exit 1
fi

# Валидаторы (valid_port / valid_ipv4_or_cidr / valid_ipv4 / no_whitespace /
# no_colon) предоставляет _lib.sh — здесь только их вызовы.

# Валидация порта (1..65535), чтобы не сгенерировать битый конфиг/ufw-правило.
if ! valid_port "${SOCKS_PORT}"; then
  echo "ОШИБКА: некорректный SOCKS_PORT='${SOCKS_PORT}' (нужно 1..65535)." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

###############################################################################
# 1. УСТАНОВКА ПАКЕТОВ
###############################################################################
echo "==> [1/8] Установка пакетов (dante-server, fail2ban, ufw, openssl, iproute2)..."

apt-get update -y

# dante-server есть в стандартных репах Ubuntu 24.04 и Debian 12/13.
# 3proxy в стандартных репах НЕТ — поэтому используем именно Dante (см. residual_risks).
PKGS=(dante-server fail2ban ufw openssl iproute2 ca-certificates curl)
apt-get install -y "${PKGS[@]}"

###############################################################################
# 2. АВТООПРЕДЕЛЕНИЕ ВНЕШНЕГО ИНТЕРФЕЙСА И IP
###############################################################################
echo "==> [2/8] Определение внешнего интерфейса и IP..."

# Интерфейс из маршрута по умолчанию (ens3/eth0/enp1s0 на разных cloud-VPS).
# Детект вынесен в _lib.sh (detect_ext_iface, robust dev-keyword).
EXT_IF="$(detect_ext_iface || true)"

if [[ -z "${EXT_IF}" ]]; then
  echo "ОШИБКА: не удалось определить внешний интерфейс (нет default route?)." >&2
  exit 1
fi

# IP на этом интерфейсе. Привязка external к конкретному IP надёжнее, чем к имени
# интерфейса (имя без IP на раннем старте даёт сбой danted — см. drop-in ниже).
EXT_IP="$(ip -o -4 addr show dev "${EXT_IF}" scope global 2>/dev/null \
  | awk '{print $4}' | cut -d/ -f1 | head -n1 || true)"

# external для конфига: предпочитаем IP, при отсутствии — имя интерфейса.
if [[ -n "${EXT_IP}" ]]; then
  EXTERNAL_VAL="${EXT_IP}"
else
  EXTERNAL_VAL="${EXT_IF}"
  echo "    ВНИМАНИЕ: IP на ${EXT_IF} не найден — использую имя интерфейса как external."
fi
echo "    Внешний интерфейс: ${EXT_IF}; IP: ${EXT_IP:-<нет>}"

###############################################################################
# 3. ОПРЕДЕЛЕНИЕ ТЕКУЩЕГО SSH-ПОРТА (ЗАЩИТА ОТ ЛОКАУТА)
###############################################################################
echo "==> [3/8] Определение текущего SSH-порта (учитываем socket-активацию)..."

# Соберём кандидатов из нескольких источников и разрешим ИХ ВСЕ в ufw —
# так безопаснее, чем угадать один порт.
#
# Канонический детектор SSH-портов (detect_ssh_ports) вынесен в _lib.sh:
# учитывает socket-активацию (ss + ListenStream у ssh.socket/sshd.socket +
# sshd_config), анкорится только к кавыченным "sshd"/"ssh"/ssh.socket и всегда
# добавляет порт 22 как анти-локаут fallback.
mapfile -t SSH_PORTS < <(detect_ssh_ports)

echo "    SSH-порты, которые будут разрешены в ufw: ${SSH_PORTS[*]}"

###############################################################################
# 4. ПОЛЬЗОВАТЕЛЬ ДЛЯ SOCKS-АУТЕНТИФИКАЦИИ
###############################################################################
echo "==> [4/8] Настройка пользователя '${PROXY_USER}'..."

PASS_WAS_GENERATED="no"
if [[ -z "${PROXY_PASS}" ]]; then
  # 24 символа из base64 (24 байта энтропии), без +/= для удобства URL.
  PROXY_PASS="$(openssl rand -base64 24 | tr -d '+/=\n' | cut -c1-24)"
  PASS_WAS_GENERATED="yes"
fi

# Валидация PROXY_USER/PROXY_PASS ДО useradd/chpasswd (finding #13: newline-injection).
# Делаем это ДО создания пользователя: иначе useradd успевал бы создать аккаунт с
# заведомо невалидным именем ещё до того, как мы его отвергнем (грязный side-effect).
# chpasswd читает строки 'user:pass'; перевод строки в любом из полей разорвал бы
# одну запись на две (инъекция чужого пароля/пользователя), а двоеточие в имени/пароле
# сместило бы разделитель полей. Поэтому отвергаем whitespace (в т.ч. \n/\t — через
# no_whitespace() из _lib.sh) и явный ':' (no_colon() из _lib.sh) — с понятным
# сообщением и exit 1.
if ! no_whitespace "${PROXY_USER}"; then
  echo "ОШИБКА: PROXY_USER не должен содержать пробелов/переводов строки." >&2
  exit 1
fi
if ! no_colon "${PROXY_USER}"; then
  echo "ОШИБКА: PROXY_USER не должен содержать символ ':' (разделитель полей chpasswd)." >&2
  exit 1
fi
# Assert на непустой пароль: пустой PROXY_PASS дал бы запись 'user:' в chpasswd
# (пустой/удалённый пароль) — это открытый SOCKS-аккаунт без аутентификации.
# В норме сюда не попадаем (выше делаем автоген при пустом), но защищаемся явно.
if [[ -z "${PROXY_PASS}" ]]; then
  echo "ОШИБКА: PROXY_PASS пуст — пустой пароль недопустим (открытый аккаунт)." >&2
  exit 1
fi
if ! no_whitespace "${PROXY_PASS}"; then
  echo "ОШИБКА: PROXY_PASS не должен содержать пробелов/переводов строки." >&2
  exit 1
fi
if ! no_colon "${PROXY_PASS}"; then
  echo "ОШИБКА: PROXY_PASS не должен содержать символ ':' (разделитель полей chpasswd)." >&2
  exit 1
fi

# Пользователя создаём ТОЛЬКО после успешной валидации обоих полей выше.
if id -u "${PROXY_USER}" >/dev/null 2>&1; then
  echo "    Пользователь '${PROXY_USER}' уже существует — пропускаю создание."
else
  useradd --no-create-home --shell /usr/sbin/nologin "${PROXY_USER}"
  echo "    Пользователь '${PROXY_USER}' создан (nologin)."
fi

# Неинтерактивно (пере)задаём пароль. chpasswd читает stdin — пароль не попадает
# в список процессов/историю.
printf '%s:%s\n' "${PROXY_USER}" "${PROXY_PASS}" | chpasswd
echo "    Пароль для '${PROXY_USER}' установлен."

###############################################################################
# 5. КОНФИГУРАЦИЯ DANTE (/etc/danted.conf)  [синтаксис Dante 1.4.x]
###############################################################################
echo "==> [5/8] Запись ${DANTE_CONF}..."

# Готовим лог-файл заранее (640 root:adm), чтобы пароль/трафик не текли в общий syslog.
touch "${DANTE_LOG}"
chown root:adm "${DANTE_LOG}" 2>/dev/null || chown root:root "${DANTE_LOG}"
chmod 640 "${DANTE_LOG}"

cat > "${DANTE_CONF}" <<EOF
# /etc/danted.conf — сгенерировано setup-foreign-vps.sh
# SOCKS5 с обязательной аутентификацией username/password (Dante 1.4.x).

# Пишем в отдельный файл (640), НЕ в общий syslog — чтобы не размазывать
# строки соединений по доступным многим логам.
logoutput: ${DANTE_LOG}

# Привилегированные/непривилегированные права рабочих процессов.
user.privileged: root
user.unprivileged: nobody

# Слушаем входящие SOCKS-подключения.
internal: ${LISTEN_ADDR} port = ${SOCKS_PORT}

# Исходящий трафик — через внешний IP/интерфейс VPS.
external: ${EXTERNAL_VAL}

# На этапе TCP-рукопожатия клиента не проверяем; реальная аутентификация —
# методом username (системные учётки через PAM) на уровне SOCKS.
clientmethod: none
socksmethod: username

# Кому разрешено вообще устанавливать TCP-соединение с прокси.
# Логируем только error/disconnect (не каждый connect) — меньше шума и утечек.
client pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: error disconnect
}

# Собственно SOCKS-проброс — только прошедшим аутентификацию методом username.
socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    socksmethod: username
    log: error disconnect
}
EOF

chown root:root "${DANTE_CONF}"
chmod 600 "${DANTE_CONF}"
echo "    Конфиг записан (root:root, 600)."

###############################################################################
# 6. SYSTEMD DROP-IN: ждать сеть, перезапускать при сбое
###############################################################################
echo "==> [6/8] systemd drop-in для danted (network-online.target, Restart=on-failure)..."

# Пакетный юнит danted не дожидается появления IP на интерфейсе => при загрузке
# danted может падать ('interface has no usable IP-addresses'). Drop-in чинит это,
# НЕ перетирая пакетный unit и не завися от пути к бинарю.
#
# Дополнительно (finding #11): пакетный юнит danted поставляется БЕЗ systemd-
# хардненинга (в отличие от drop-in'ов 3proxy/mtg в siblings-скриптах). Добавляем
# тот же набор директив изоляции по образцу siblings. ВАЖНО для danted:
#   * процесс стартует от root (user.privileged: root) и аутентифицирует через PAM,
#     читая /etc/shadow — поэтому НЕ используем DynamicUser/User= и НЕ запрещаем
#     чтение /etc целиком;
#   * ProtectSystem=strict делает / (включая /etc) read-only — это ОК: и /etc/shadow,
#     и /etc/danted.conf нужны только на чтение, запись в них не требуется;
#   * ProtectHome=yes — danted не обращается к /home/root-домашке;
#   * лог danted пишется в ${DANTE_LOG} (/var/log/...), поэтому /var/log делаем
#     записываемым через ReadWritePaths — иначе ProtectSystem=strict сломал бы
#     logoutput (единственное место, куда danted реально пишет);
#   * NoNewPrivileges НЕ мешает PAM: проверка пароля идёт внутри уже-root процесса,
#     без повышения привилегий через setuid-хелперы.
#   * RestrictAddressFamilies ОБЯЗАН включать AF_UNIX и AF_NETLINK помимо
#     AF_INET/AF_INET6 — иначе glibc getaddrinfo() в danted не может резолвить
#     имена (AF_NETLINK нужен для enumeration интерфейсов и RFC-3484-выбора
#     source-адреса; AF_UNIX — для nss/systemd-resolved). Без них danted стартует
#     «зелёным», но ЛЮБОЙ CONNECT по ИМЕНИ падает — это ядро функции SOCKS.
#     Набор синхронизирован с sibling-скриптом mtproxy.
DROPIN_DIR="/etc/systemd/system/danted.service.d"
mkdir -p "${DROPIN_DIR}"
cat > "${DROPIN_DIR}/override.conf" <<EOF
[Unit]
After=network-online.target
Wants=network-online.target

[Service]
Restart=on-failure
RestartSec=3s

# --- Хардненинг (по образцу siblings 3proxy/mtg), finding #11 ---------------
# danted остаётся root + PAM-чтение /etc/shadow: ProtectSystem=strict оставляет
# /etc read-only (чтение shadow/конфига работает), запись разрешена только в
# /var/log для logoutput.
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/log
ProtectHome=yes
PrivateTmp=yes
ProtectControlGroups=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
SystemCallArchitectures=native
EOF
chmod 644 "${DROPIN_DIR}/override.conf"

# Чтобы Wants=network-online.target реально работал, нужен включённый
# *-wait-online сервис (systemd-networkd-wait-online / NetworkManager-wait-online).
systemctl enable systemd-networkd-wait-online.service >/dev/null 2>&1 || true
systemctl enable NetworkManager-wait-online.service    >/dev/null 2>&1 || true

systemctl daemon-reload

###############################################################################
# 7. ФАЕРВОЛ (ufw): СНАЧАЛА SSH, ПОТОМ ВКЛЮЧЕНИЕ
###############################################################################
echo "==> [7/8] Настройка ufw (SSH разрешаем ДО enable)..."

# Анти-локаут-оркестрация (гейт активности, first-run allow всех SSH-портов со
# счётчиком успехов, 'ufw --force enable' и re-run-добавление сервис-порта)
# вынесена в _lib.sh::ufw_orchestrate — раньше этот блок копировался по всем
# setup-*.sh и расходился. Здесь мы определяем ТОЛЬКО свою сервис-функцию и
# передаём её имя оркестратору.
#
# Валидацию ALLOW_FROM делаем ДО оркестрации: кривой IP/CIDR не должен молча
# проглотиться (finding #8) и не должен «упасть» в середине ufw-настройки
# (после SSH-правил, но до enable). Пустой ALLOW_FROM — это валидный безопасный
# дефолт (порт просто не открываем), поэтому валидируем лишь НЕпустое значение.
if [[ -n "${ALLOW_FROM}" && "${ALLOW_FROM}" != "0.0.0.0/0" ]]; then
  if ! valid_ipv4_or_cidr "${ALLOW_FROM}"; then
    echo "ОШИБКА: некорректный ALLOW_FROM='${ALLOW_FROM}' (нужен IPv4 или CIDR, напр. 203.0.113.5 или 203.0.113.0/24)." >&2
    exit 1
  fi
fi

# Сервис-правила ЭТОГО скрипта: открыть SOCKS_PORT/tcp (Dante).
# ИДЕМПОТЕНТНО (ufw сам пропускает дубли) и БЕЗОПАСНО как на первом запуске, так
# и на re-run. SSH-правила/enable здесь НЕ трогаем — это делает ufw_orchestrate.
# Все ufw-мутации через ufw_safe (из _lib.sh): транзиентный сбой не валит скрипт.
#
# ОЧИСТКА ПЕРЕД ДОБАВЛЕНИЕМ (находка HIGH #2): сначала ufw_clear_port для текущего
# SOCKS_PORT/tcp, затем добавляем актуальное правило. Зачем: 'ufw allow' ИДЕМПОТЕНТНА
# лишь по ТОЧНОМУ совпадению правила. Без очистки re-run с сужением ALLOW_FROM
# (например с '0.0.0.0/0' или пустого на конкретный IP) лишь ДОБАВИЛ бы новое
# правило 'from <IP>', НЕ сняв прежнюю широкую форму 'SOCKS_PORT/tcp ALLOW Anywhere'
# — старый широкий доступ остался бы открытым. ufw_clear_port "${SOCKS_PORT}" tcp
# снимает ВСЕ прежние формы правила для этого порта (SSH-порты функция исключает),
# после чего мы добавляем единственную актуальную форму. Это REWRITE (очистка +
# добавление), а не дублирование существующего allow. ОСОБЫЙ СЛУЧАЙ пустого
# ALLOW_FROM: ufw_clear_port уберёт прежнее правило и ничего не добавит — порт
# корректно ЗАКРОЕТСЯ (а не останется открытым с предыдущего прогона).
add_service_rules() {
  # Снимаем любые прежние формы правила для SOCKS_PORT/tcp ДО ветвления —
  # так корректно отрабатывают и сужение ALLOW_FROM, и его обнуление (закрытие).
  ufw_clear_port "${SOCKS_PORT}" tcp

  if [[ -z "${ALLOW_FROM}" ]]; then
    # Безопасный дефолт: без ALLOW_FROM SOCKS-порт НЕ открываем вовсе.
    # Прежнее правило уже снято ufw_clear_port выше — порт остаётся закрытым.
    warn "ALLOW_FROM пуст — SOCKS-порт ${SOCKS_PORT} НЕ открыт в ufw (безопасный дефолт)."
    warn "      Укажите IP РФ-сервера и перезапустите, например:"
    warn "        ALLOW_FROM=203.0.113.5 bash $0"
  elif [[ "${ALLOW_FROM}" == "0.0.0.0/0" ]]; then
    echo "    !!! ВНИМАНИЕ: ALLOW_FROM=0.0.0.0/0 — SOCKS-порт ${SOCKS_PORT} будет открыт"
    echo "        ВСЕМУ ИНТЕРНЕТУ. Единственный барьер — пароль. Это НЕ рекомендуется."
    ufw_safe allow "${SOCKS_PORT}/tcp"
  else
    # ALLOW_FROM уже провалидирован выше (valid_ipv4_or_cidr) до оркестрации.
    ufw_safe allow from "${ALLOW_FROM}" to any port "${SOCKS_PORT}" proto tcp
    echo "    SOCKS-порт ${SOCKS_PORT} открыт только для ${ALLOW_FROM}."
  fi
}

# Единый вызов: при первом запуске разрешит SSH-порты и включит ufw (или
# прекратит работу через return 1, если ни одно SSH-правило не применилось — мы
# обязаны выйти и НЕ включать фаервол); на re-run только добавит сервис-порт.
# Ставит глобал UFW_FINAL_STATE (active|unknown) для итогового баннера.
# Код возврата ловим в отдельную переменную ДО любой другой команды (#7): под
# set -euo pipefail цепочка '... || exit 1' тоже работает, но явный __rc делает
# намерение очевидным и не зависит от того, что оркестратор — последняя команда.
ufw_orchestrate add_service_rules; __rc=$?; (( __rc == 0 )) || exit 1

# Баннер про SSH/ufw отражает РЕАЛЬНОЕ положение через UFW_FINAL_STATE
# (finding #4): «активен» только при подтверждении, иначе честное предупреждение,
# что фаервол мог не включиться (OpenVZ/без nf_tables).
if [[ "${UFW_FINAL_STATE}" == "active" ]]; then
  echo "    ufw активен. SSH-порты [${SSH_PORTS[*]}] разрешены."
else
  warn "состояние ufw НЕ подтверждено — фаервол МОГ не включиться (OpenVZ/без nf_tables?)."
  warn "      SSH-правила подготовлены, но без активного фаервола они не действуют."
  warn "      Проверьте вручную: 'ufw status verbose'."
fi

###############################################################################
# 8. FAIL2BAN ДЛЯ DANTED + ЗАПУСК СЕРВИСОВ
###############################################################################
echo "==> [8/8] fail2ban-фильтр для danted, валидация конфига, запуск сервисов..."

# Реальный фильтр под Dante 1.4.x (на основе протестированного шаблона
# fail2ban PR #3410). Ловит провал system-password-аутентификации.
cat > /etc/fail2ban/filter.d/danted.conf <<'EOF'
# Fail2Ban filter for Dante (danted) 1.4.x — auth failures
[Definition]
_daemon = danted
failregex = ^.*danted\[\d+\]: info: block\(\d+\): tcp/accept \]: <HOST>\.\d+ [\d.]+: error after reading \d+ bytes? in \d+ seconds?: (?:could not access |system password authentication failed for )user "[^"]+".*$
ignoreregex =
EOF
chmod 644 /etc/fail2ban/filter.d/danted.conf

# Jail для danted, читает наш отдельный лог. local-файл не перетирает jail.conf.
cat > /etc/fail2ban/jail.d/danted.local <<EOF
[danted]
enabled  = true
filter   = danted
backend  = auto
logpath  = ${DANTE_LOG}
port     = ${SOCKS_PORT}
protocol = tcp
maxretry = 5
findtime = 600
bantime  = 3600
EOF
chmod 644 /etc/fail2ban/jail.d/danted.local

# Валидируем конфиг Dante до запуска: -V = verify config and exit.
# Бинарь в Debian/Ubuntu называется danted; на случай иных имён пробуем sockd.
DANTE_BIN="$(command -v danted || command -v sockd || true)"
if [[ -n "${DANTE_BIN}" ]]; then
  if ! "${DANTE_BIN}" -V -f "${DANTE_CONF}" >/dev/null 2>&1; then
    echo "ОШИБКА: проверка конфига Dante не прошла (${DANTE_BIN} -V). Конфиг: ${DANTE_CONF}" >&2
    "${DANTE_BIN}" -V -f "${DANTE_CONF}" || true
    exit 1
  fi
  echo "    Конфиг Dante валиден."
else
  echo "    ВНИМАНИЕ: бинарь danted/sockd не найден в PATH — пропускаю -V проверку."
fi

# Запуск/автозапуск danted.
systemctl enable danted >/dev/null 2>&1 || true
systemctl restart danted

# Валидируем конфиг fail2ban ДО рестарта: -t = test configuration and exit.
# Битый фильтр/jail иначе уронил бы только сам fail2ban, а баннер ниже всё равно
# обещал бы brute-force-защиту. Не роняем скрипт под set -e (тест необязателен —
# fail2ban-client может отсутствовать в PATH), но громко предупреждаем.
if command -v fail2ban-client >/dev/null 2>&1; then
  if ! fail2ban-client -t >/dev/null 2>&1; then
    echo "    ВНИМАНИЕ: 'fail2ban-client -t' сообщил об ошибке в конфигурации fail2ban." >&2
    echo "             Проверьте /etc/fail2ban/jail.d/danted.local и filter.d/danted.conf." >&2
  fi
fi

# Запуск/автозапуск fail2ban (после создания jail, чтобы он подхватился).
systemctl enable fail2ban >/dev/null 2>&1 || true
systemctl restart fail2ban

if ! systemctl is-active --quiet danted; then
  echo "ОШИБКА: сервис danted не активен. Логи: journalctl -u danted -n 50 --no-pager" >&2
  exit 1
fi

# Проверяем и fail2ban (по образцу проверки danted): без is-active баннер ниже
# обещал бы защиту от brute-force, тогда как при битом jail SOCKS-порт остался бы
# открыт вовсе без неё, а оператор считал бы себя защищённым. НЕ роняем скрипт
# (прокси сам по себе работоспособен и при выключенном fail2ban) — но предупреждаем.
if ! systemctl is-active --quiet fail2ban; then
  echo "    ВНИМАНИЕ: сервис fail2ban НЕ активен — brute-force-защита SOCKS-порта"  >&2
  echo "             ${SOCKS_PORT} НЕ работает! Диагностика: systemctl status fail2ban;" >&2
  echo "             journalctl -u fail2ban -n 50 --no-pager" >&2
else
  echo "    danted и fail2ban запущены и в автозагрузке."
fi

###############################################################################
# ИТОГ
###############################################################################

SERVER_IP="${EXT_IP:-<IP_ЭТОГО_VPS>}"

echo
echo "============================================================"
echo " SOCKS5 (Dante) НАСТРОЕН И ЗАПУЩЕН"
echo "============================================================"
echo " IP сервера   : ${SERVER_IP}"
echo " Порт SOCKS   : ${SOCKS_PORT}"
echo " Слушает на   : ${LISTEN_ADDR}"
echo " Доступ ufw   : ${ALLOW_FROM:-<порт НЕ открыт: задайте ALLOW_FROM>}"
echo " Логин        : ${PROXY_USER}"
echo " Пароль       : ${PROXY_PASS}"
if [[ "${PASS_WAS_GENERATED}" == "yes" ]]; then
  echo "                (пароль сгенерирован автоматически — СОХРАНИТЕ ЕГО!)"
fi
echo "------------------------------------------------------------"
echo " Самопроверка с самого VPS (вернётся иностранный IP):"
echo "   curl --socks5 ${PROXY_USER}:'<ПАРОЛЬ>'@127.0.0.1:${SOCKS_PORT} https://api.ipify.org"
echo
echo " ВНИМАНИЕ: не вставляйте пароль в общие логи/историю. Пароль выше —"
echo "          только в этом выводе; при необходимости сотрите экран."
echo "============================================================"
