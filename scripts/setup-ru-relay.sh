#!/usr/bin/env bash
#
# setup-ru-relay.sh
# =================
# Запускается НА СЕРВЕРЕ В РФ.
#
# Назначение: сделать РФ-сервер аутентифицированным SOCKS5-релеем на базе 3proxy.
#   Цепочка целиком: [ПК/телефон Proxifier] -> [этот РФ-сервер :LOCAL_PORT, логин/пароль]
#                    -> [зарубежный Dante-VPS :FOREIGN_SOCKS_PORT, логин/пароль]
#                    -> Claude/интернет (выход с иностранного IP).
#
#   Преимущество перед autossh: у релея своя авторизация, поэтому он работает при
#   плавающем домашнем IP — клиент подключается по паролю, а не по доверенному IP.
#
# Идемпотентность: скрипт можно запускать многократно. Уже установленный 3proxy,
#   существующий конфиг, юнит и правила ufw переписываются/проверяются, а не дублируются.
#   Ключи/пароли не перетираются без необходимости (LOCAL_PASS подхватывается из
#   отдельного файла /etc/3proxy/relay_pass при повторном запуске, см. ниже).
#
# Совместимость: Ubuntu 24.04 (и Debian 12/13). Требует root (sudo).
#
set -euo pipefail

# --- Подключаем общую библиотеку из каталога этого скрипта ---
# Общие функции (log/warn/err, валидаторы, detect_ssh_ports, ufw-гейт и т.п.)
# вынесены в _lib.sh — единый источник правды для всех setup-*.sh.
_SLV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)"
if [[ -z "${_SLV_DIR}" || ! -r "${_SLV_DIR}/_lib.sh" ]]; then
  echo "ОШИБКА: рядом со скриптом не найден _lib.sh. Скопируйте _lib.sh в тот же" >&2
  echo "        каталог и запускайте как файл (sudo bash $0), а не через stdin/pipe." >&2
  exit 1
fi
# shellcheck source=/dev/null
source "${_SLV_DIR}/_lib.sh"

# ============================================================================
#  КОНФИГУРАЦИЯ — отредактируйте значения ниже под себя
# ============================================================================

# --- Вышестоящий (parent) прокси: зарубежный Dante-VPS из setup-foreign-vps.sh ---
FOREIGN_VPS_IP="203.0.113.10"      # ПУБЛИЧНЫЙ IP зарубежного VPS (ОБЯЗАТЕЛЬНО заменить!)
FOREIGN_SOCKS_PORT="39847"         # порт, на котором слушает Dante на зарубежном VPS
FOREIGN_USER="proxyuser"           # логин для аутентификации на зарубежном Dante
FOREIGN_PASS="CHANGE_ME_FOREIGN"   # пароль Dante (ОБЯЗАТЕЛЬНО заменить!)

# --- Способ B: ОПЦИОНАЛЬНЫЙ residential-выход (резидентный IP вместо датацентрового) ---
# Когда RESI_HOST задан, выход релея идёт ЧЕРЕЗ residential-прокси (выходной IP = резидентный,
# НЕ датацентровый), а хоп через зарубежный Dante НЕ используется. Нужно, когда сервис
# (Antigravity и агрессивные анти-бот-фильтры) режет датацентровые IP.
# Чейн в этом режиме: [клиент] -> [этот релей] -> [residential] -> интернет.
RESI_HOST=""        # хост residential-шлюза (IP или домен). ПУСТО => режим прежний (выход через зарубежный Dante).
RESI_PORT=""        # порт residential-шлюза
RESI_USER=""        # логин residential-провайдера
RESI_PASS=""        # пароль residential-провайдера
RESI_TYPE="socks5"  # тип residential-прокси: socks5 | http

# --- Локальный SOCKS5-листенер на этом РФ-сервере ---
LOCAL_PORT="1080"                  # порт, который слушает 3proxy на РФ-сервере
LOCAL_USER="relayuser"             # логин, который будут указывать клиенты (Proxifier)
LOCAL_PASS=""                      # пароль клиента; если пусто — будет переиспользован из
                                   #   отдельного файла /etc/3proxy/relay_pass либо сгенерирован openssl.
# Опционально: ограничить, с каких источников можно подключаться к LOCAL_PORT.
# Пусто = принимать отовсюду (порт виден из интернета, защищён только логином/паролем).
# Пример: ALLOW_FROM_CIDR="203.0.113.0/24" — тогда ufw откроет порт только этому диапазону.
ALLOW_FROM_CIDR=""

# --- Сервисный системный пользователь, от которого работает 3proxy (непривилегированный) ---
SERVICE_USER="proxy3"              # отдельный аккаунт без shell для демона 3proxy

# --- Параметры установки 3proxy ---
# Последний официальный релиз 3proxy/3proxy на момент написания: 0.9.6 (2024-04-11).
# Приоритет установки (#8/#9): если задан PINNED_COMMIT — собираем из git с запиненного
# commit-SHA (проверяемая подлинность). Иначе пробуем официальный .deb релиза (с громким
# предупреждением о неаутентифицированности, если EXPECTED_DEB_SHA256 пуст). Если же и .deb
# недоступен (offline/odd-arch/404) — ПОСЛЕДНИЙ РУБЕЖ ДОСТУПНОСТИ (#availability): сборка из
# запиненного ТЕГА с громким предупреждением (тег mutable, подлинность не проверена). На
# плавающий master НЕ откатываемся никогда.
THREEPROXY_VERSION="0.9.6"
# Канонический репозиторий теперь 3proxy/3proxy (старый z3APA3A/3proxy лишь редиректит).
THREEPROXY_REPO="https://github.com/3proxy/3proxy"

# (#8) Supply-chain: при сборке из git НЕ полагаемся на mutable-тег (тег можно передвинуть на
# другой коммит) и НЕ откатываемся на плавающий master. Пинимся на КОНКРЕТНЫЙ commit-SHA и
# проверяем, что после checkout HEAD равен именно ему.
# Иерархия путей по убыванию доверия:
#   1) PINNED_COMMIT задан                 -> ПРОВЕРЯЕМАЯ подлинность (HEAD == SHA);
#   2) EXPECTED_DEB_SHA256 задан            -> .deb с ПРОВЕРЯЕМОЙ суммой;
#   3) ни то, ни другое (stock)            -> сначала неаутентифицированный .deb (громкое
#      预предупреждение), а если .deb-путь недоступен (пустой DEB_ARCH / 404 / переименован
#      asset) — ПОСЛЕДНИЙ РУБЕЖ ДОСТУПНОСТИ: сборка из ЗАПИНЕННОГО ТЕГА 3proxy-${THREEPROXY_VERSION}
#      с ГРОМКИМ предупреждением (тег mutable, подлинность НЕ проверена). На плавающий master
#      НЕ откатываемся НИКОГДА (#availability).
# TODO: впишите проверенный полный 40-символьный commit-SHA, соответствующий тегу
#       3proxy-${THREEPROXY_VERSION}, сверив его на доверенной машине
#       (например: git ls-remote ${THREEPROXY_REPO} refs/tags/3proxy-${THREEPROXY_VERSION}^{}).
PINNED_COMMIT=""

# ОПЦИОНАЛЬНАЯ проверка подлинности .deb по SHA256.
# ВНИМАНИЕ: апстрим 3proxy НЕ публикует подписанных контрольных сумм. Поэтому по умолчанию
# здесь пусто и выполняется только integrity-проверка (что файл — валидный .deb, а не 404-HTML).
# Если вы вычислили хэш доверенного .deb вне канала (например, на другой машине) — впишите его
# сюда, и скрипт ЖЁСТКО его проверит. Формат: ровно 64 hex-символа суммы 'sha256sum'.
EXPECTED_DEB_SHA256=""

# --- DNS-резолвер, который 3proxy использует для разрешения имён (nserver) ---
# Берём публичные резолверы, чтобы не зависеть от /etc/resolv.conf.
NSERVER_1="1.1.1.1"
NSERVER_2="8.8.8.8"

# --- Пути ---
CFG_DIR="/etc/3proxy"
CFG_FILE="${CFG_DIR}/3proxy.cfg"
PASS_FILE="${CFG_DIR}/relay_pass"  # пароль релея хранится ОТДЕЛЬНО (не привязан к LOCAL_USER)
BIN_PATH="/usr/local/bin/3proxy"   # куда кладём бинарь ПРИ СБОРКЕ из исходников
LOG_DIR="/var/log/3proxy"
UNIT_NAME="3proxy-relay.service"   # ОТДЕЛЬНОЕ имя юнита, чтобы НЕ конфликтовать с юнитом из .deb
UNIT_FILE="/etc/systemd/system/${UNIT_NAME}"
# WORK_DIR — временный каталог установки/сборки.
# (#14) НЕ используем фиксированный /tmp/3proxy-build в world-writable /tmp (TOCTOU/symlink-атака:
# злоумышленник может заранее создать каталог/симлинк по предсказуемому имени). Создаём приватный
# каталог через 'mktemp -d' (режим 700, владелец root) и удаляем его в trap EXIT — как делает
# sibling-скрипт mtproxy. mktemp инициализируем ниже, в разделе предварительных проверок.
WORK_DIR=""

# ============================================================================
#  СЛУЖЕБНЫЕ ФУНКЦИИ
# ============================================================================
# log/warn/err, valid_port, valid_ipv4_or_cidr, no_whitespace, no_colon и
# detect_ssh_ports теперь приходят из _lib.sh (подключён выше) — локальных копий
# здесь больше нет. Ниже остаётся только то, что специфично для этого скрипта.

# Проверка, что скрипт запущен от root (нужно для apt, ufw, systemd).
require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        err "Запустите скрипт от root: sudo bash $0"
        exit 1
    fi
}

# Валидаторы (valid_port, valid_ipv4_or_cidr, no_whitespace, no_colon) и детект
# SSH-портов (detect_ssh_ports) приходят из _lib.sh. Семантика прежняя:
# valid_port — целое 1..65535 (base-10); valid_ipv4_or_cidr — IPv4(/CIDR) с
# октетами <=255 и префиксом <=32; no_whitespace/no_colon — для кредов 3proxy
# (двоеточие в 3proxy.cfg разделяет поля записи users U:CL:P и parent ... USER PASS,
# поэтому ':' внутри логина/пароля ломает аутентификацию). При провале валидатора
# вызывающий код ниже сам делает exit 1 (НЕ '|| true').

# --- Правило ufw для порта релея — единое место (вызывается из add_service_rules) (#1) ---
# Поведение:
#   - ALLOW_FROM_CIDR ЗАДАН  -> fail-CLOSED: 'ufw allow from <cidr>' (порт виден только источнику).
#   - ALLOW_FROM_CIDR ПУСТ   -> порт открыт всему интернету и защищён ТОЛЬКО логином/паролем.
#       Домашний IP в РФ плавающий, поэтому жёсткий allowlist по IP сделать нельзя. Чтобы НЕ
#       открывать порт молча и fail-OPEN, здесь: (a) печатаем ГРОМКОЕ предупреждение; (b) вместо
#       'ufw allow' используем 'ufw limit' — ufw сам rate-limit'ит частые новые подключения с
#       одного адреса (тормозит онлайн-брутфорс пароля). fail2ban (см. setup_fail2ban) добавляет
#       второй слой защиты.
remove_relay_port_rules() {
    # (#9 / HIGH #1) Снести ВСЕ прежние формы правила ufw для LOCAL_PORT перед добавлением
    # актуальной — rewrite, а не duplicate — чтобы переключение ALLOW_FROM_CIDR (задан <-> пуст)
    # между запусками НЕ оставляло устаревшую противоположную форму в действии.
    #
    # Делегируем единой ufw_clear_port (_lib.sh) "${LOCAL_PORT}" tcp. КРИТИЧНО (HIGH #1):
    # прежняя локальная реализация удаляла ЛЮБОЕ правило, чья строка содержала LOCAL_PORT —
    # включая якорное SSH-allow, если LOCAL_PORT случайно совпадал с SSH-портом. На первом
    # запуске (ufw неактивен -> ufw_orchestrate сперва открывает SSH, потом зовёт нас) это
    # снесло бы только что добавленное SSH-allow ДО enable => default-deny без SSH = ЛОКАУТ.
    # ufw_clear_port исключает SSH-порты (detect_ssh_ports) by design: при совпадении
    # LOCAL_PORT с SSH-портом она warn'ит и НИЧЕГО не удаляет. Реализация ufw_clear_port уже
    # безопасна под set -euo pipefail (LC_ALL=C, захват в переменную без SIGPIPE, удаление по
    # убыванию номеров, fail-soft '|| true', no-op на неактивном ufw).
    ufw_clear_port "${LOCAL_PORT}" tcp
}

# --- Сервис-правила этого скрипта для ufw_orchestrate (#14) ---
# ufw_orchestrate (_lib.sh) сам делает анти-локаут (SSH-порты + enable на первом запуске,
# ничего не трогает при re-run). От нас он ждёт ИМЯ функции, которая ИДЕМПОТЕНТНО добавляет
# ТОЛЬКО сервис-правила релея через ufw_safe и НЕ трогает SSH/enable. Это и есть add_service_rules.
add_service_rules() {
    # (#9) Сначала сносим все прежние формы правила для LOCAL_PORT, затем добавляем актуальную —
    # rewrite, а не duplicate. Снос — fail-soft (правил могло не быть): см. remove_relay_port_rules.
    remove_relay_port_rules
    if [[ -n "${ALLOW_FROM_CIDR}" ]]; then
        log "Разрешаю порт релея ${LOCAL_PORT}/tcp только из ${ALLOW_FROM_CIDR} (fail-closed)..."
        # ufw_safe (_lib.sh): транзиентный сбой ufw (xtables-lock / OpenVZ без nf_tables) под
        # set -e иначе оборвал бы оркестрацию между SSH-allow и enable — ufw_safe warn'ит и идёт дальше.
        ufw_safe allow from "${ALLOW_FROM_CIDR}" to any port "${LOCAL_PORT}" proto tcp
    else
        warn "############################################################################"
        warn "# ВНИМАНИЕ: ПОРТ РЕЛЕЯ ${LOCAL_PORT}/tcp ОТКРЫТ ВСЕМУ ИНТЕРНЕТУ"
        warn "#   ALLOW_FROM_CIDR пуст — список разрешённых источников НЕ задан."
        warn "#   Любой в интернете может ДОСТУЧАТЬСЯ до SOCKS5-порта; единственная"
        warn "#   защита — логин '${LOCAL_USER}' и пароль (длинный openssl rand)."
        warn "#   Применяю 'ufw limit' (rate-limit новых подключений) вместо 'ufw allow'"
        warn "#   и ставлю fail2ban как второй слой против брутфорса пароля."
        warn "#   РЕКОМЕНДАЦИЯ: при возможности задайте ALLOW_FROM_CIDR (даже широкий"
        warn "#   диапазон провайдера снижает площадь атаки)."
        warn "############################################################################"
        log "Применяю rate-limit на порт релея: ufw limit ${LOCAL_PORT}/tcp ..."
        ufw_safe limit "${LOCAL_PORT}/tcp"
    fi
}

# --- fail2ban: второй слой против брутфорса, когда порт открыт всему интернету (#1) ---
# Ставим всегда, когда ALLOW_FROM_CIDR пуст. Пытаемся завести jail по логу 3proxy; если
# подходящего фильтра нет (jail сложен/лог-формат не распознан), как минимум оставляем
# fail2ban установленным и громко рекомендуем настроить jail вручную.
setup_fail2ban() {
    log "Устанавливаю fail2ban (второй слой против брутфорса пароля релея)..."
    apt-get install -y fail2ban

    local filter_dir="/etc/fail2ban/filter.d"
    local jail_dir="/etc/fail2ban/jail.d"
    local filter_file="${filter_dir}/3proxy-relay.conf"
    local jail_file="${jail_dir}/3proxy-relay.conf"
    mkdir -p "${filter_dir}" "${jail_dir}"

    # Фильтр failregex по строкам 3proxy с кодом ошибки аутентификации. ВНИМАНИЕ: с
    # privacy-минимальным logformat (#2) клиентский IP в лог НЕ пишется, поэтому fail2ban
    # не сможет извлечь <HOST> из лога 3proxy. Альтернативный надёжный источник адресов —
    # системный journal/auth. Чтобы НЕ обещать неработающий jail, ставим фильтр-заглушку и
    # ОТКЛЮЧЁННЫЙ по умолчанию jail с понятной пометкой — пусть оператор осознанно включит,
    # выбрав источник логов с IP. Сам fail2ban при этом установлен и активен в системе.
    cat > "${filter_file}" <<'F2BEOF'
# fail2ban filter для 3proxy-релея.
# ПРИМЕЧАНИЕ: privacy-минимальный logformat 3proxy НЕ содержит client IP (см. fix #2),
# поэтому <HOST> из лога 3proxy извлечь нельзя. Этот фильтр — заготовка. Чтобы блокировать
# брутфорс по IP, направьте источник с адресами (например, ufw/iptables-LOG drop'ов на порт
# релея в journal) и допишите failregex под него.
[Definition]
failregex =
ignoreregex =
F2BEOF

    cat > "${jail_file}" <<F2BEOF
# Jail для порта SOCKS5-релея. По умолчанию ВЫКЛЮЧЕН (enabled = false), т.к. при
# privacy-минимальном логе 3proxy нет client IP для бана. Включите осознанно, выбрав
# источник логов с IP-адресами неудачных подключений к порту ${LOCAL_PORT}.
[3proxy-relay]
enabled  = false
port     = ${LOCAL_PORT}
protocol = tcp
filter   = 3proxy-relay
logpath  = ${LOG_DIR}/3proxy.log
maxretry = 5
findtime = 600
bantime  = 3600
F2BEOF

    systemctl enable fail2ban 2>/dev/null || true
    systemctl restart fail2ban 2>/dev/null || true
    warn "fail2ban установлен и включён. Jail [3proxy-relay] создан, но ВЫКЛЮЧЕН: лог 3proxy"
    warn "  с privacy-минимальным форматом (#2) не содержит client IP. Чтобы реально банить"
    warn "  брутфорс, настройте источник логов с IP и включите jail (enabled = true в"
    warn "  ${jail_file}). До этого защиту от брутфорса обеспечивает 'ufw limit'."
}

# ============================================================================
#  0. ПРЕДВАРИТЕЛЬНЫЕ ПРОВЕРКИ
# ============================================================================

require_root

# --- Выбор активного выхода (parent): residential (Способ B) или зарубежный Dante ---
# RESI_HOST задан => РЕЖИМ RESIDENTIAL: выход через residential-прокси, FOREIGN_* НЕ нужны.
# RESI_HOST пуст  => прежнее поведение: parent = зарубежный Dante, валидация FOREIGN_*.
RESI_MODE=0
if [[ -n "${RESI_HOST}" ]]; then
    RESI_MODE=1
fi

if [[ "${RESI_MODE}" -eq 1 ]]; then
    # --- РЕЖИМ RESIDENTIAL: валидация residential-апстрима; FOREIGN_* пропускаем ---
    # Тип residential-прокси.
    case "${RESI_TYPE}" in
        socks5|http) : ;;
        *)
            err "RESI_TYPE='${RESI_TYPE}' некорректен — допустимо только 'socks5' или 'http'."
            exit 1
            ;;
    esac
    # Порт residential-шлюза.
    if ! valid_port "${RESI_PORT}"; then
        err "RESI_PORT='${RESI_PORT}' некорректен — нужен целый порт 1..65535."
        exit 1
    fi
    # Хост: непустой и похож на IPv4 ЛИБО на хостнейm (буквы/цифры/.-, без ведущих/хвостовых .-).
    if ! valid_ipv4 "${RESI_HOST}" \
       && [[ ! "${RESI_HOST}" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; then
        err "RESI_HOST='${RESI_HOST}' некорректен — ожидается IPv4 или хостнейм (буквы/цифры/.-)."
        exit 1
    fi
    # (#8) Креды residential ОБЯЗАТЕЛЬНЫ: residential-апстрим требует аутентификации, а пустой
    # логин/пароль породил бы битую строку 'parent 1000 socks5+ HOST PORT  ' (недостающие поля
    # USER/PASS) — 3proxy либо отвергнет конфиг, либо пойдёт без auth. no_whitespace/no_colon
    # ниже на ПУСТОЙ строке проходят (пустая строка не содержит ни пробела, ни ':'), поэтому
    # сами по себе непустоту НЕ гарантируют — добавляем явный guard, как у RESI_HOST/RESI_PORT.
    if [[ -z "${RESI_USER}" ]]; then
        err "RESI_USER пуст — в residential-режиме логин residential-провайдера ОБЯЗАТЕЛЕН (задайте RESI_USER)."
        exit 1
    fi
    if [[ -z "${RESI_PASS}" ]]; then
        err "RESI_PASS пуст — в residential-режиме пароль residential-провайдера ОБЯЗАТЕЛЕН (задайте RESI_PASS)."
        exit 1
    fi
    # Креды residential: пробел/перевод строки и двоеточие ломают токенизацию 3proxy-конфига.
    if ! no_whitespace "${RESI_USER}"; then
        err "RESI_USER содержит пробел/перевод строки — это сломает токенизацию 3proxy-конфига. Уберите пробелы."
        exit 1
    fi
    if ! no_colon "${RESI_USER}"; then
        err "RESI_USER содержит двоеточие ':' — 3proxy использует ':' как разделитель полей, это сломает аутентификацию. Уберите двоеточие."
        exit 1
    fi
    if ! no_whitespace "${RESI_PASS}"; then
        err "RESI_PASS содержит пробел/перевод строки — это сломает токенизацию 3proxy-конфига. Уберите пробелы."
        exit 1
    fi
    if ! no_colon "${RESI_PASS}"; then
        err "RESI_PASS содержит двоеточие ':' — 3proxy использует ':' как разделитель полей, это сломает аутентификацию. Уберите двоеточие."
        exit 1
    fi
    log "Режим RESIDENTIAL: выход через ${RESI_HOST}:${RESI_PORT} (тип ${RESI_TYPE}); FOREIGN_* не используются."
else
    # --- Прежний режим: parent = зарубежный Dante. Защита от незаполненных плейсхолдеров ---
    if [[ "${FOREIGN_VPS_IP}" == "203.0.113.10" || "${FOREIGN_PASS}" == "CHANGE_ME_FOREIGN" || -z "${FOREIGN_VPS_IP}" || -z "${FOREIGN_PASS}" ]]; then
        err "Заполните FOREIGN_VPS_IP и FOREIGN_PASS в начале скрипта реальными значениями зарубежного VPS (или задайте RESI_HOST для residential-выхода)."
        exit 1
    fi
    # (#10) FOREIGN_VPS_IP идёт прямо в строку 'parent 1000 socks5+ ${FOREIGN_VPS_IP} ...' конфига.
    # Раньше проверялись только -z и != плейсхолдер; whitespace внутри сместил бы поля parent
    # (битый upstream), а мусорное значение (опечатка/случайный текст) тихо сломало бы цепочку.
    # Валидируем формат так же, как RESI_HOST: no_whitespace + (IPv4 ЛИБО хостнейм).
    if ! no_whitespace "${FOREIGN_VPS_IP}"; then
        err "FOREIGN_VPS_IP содержит пробел/перевод строки — это сместит поля строки 'parent ...' в 3proxy-конфиге. Уберите пробелы."
        exit 1
    fi
    if ! valid_ipv4 "${FOREIGN_VPS_IP}" \
       && [[ ! "${FOREIGN_VPS_IP}" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; then
        err "FOREIGN_VPS_IP='${FOREIGN_VPS_IP}' некорректен — ожидается IPv4 или хостнейм (буквы/цифры/.-)."
        exit 1
    fi
fi

# --- Валидация портов (#7): неверный порт -> exit 1, НЕ молчаливое продолжение ---
if ! valid_port "${LOCAL_PORT}"; then
    err "LOCAL_PORT='${LOCAL_PORT}' некорректен — нужен целый порт 1..65535."
    exit 1
fi
# FOREIGN_SOCKS_PORT нужен только в прежнем режиме (в residential-режиме Dante не используется).
if [[ "${RESI_MODE}" -eq 0 ]] && ! valid_port "${FOREIGN_SOCKS_PORT}"; then
    err "FOREIGN_SOCKS_PORT='${FOREIGN_SOCKS_PORT}' некорректен — нужен целый порт 1..65535."
    exit 1
fi

# --- Валидация ALLOW_FROM_CIDR, если задан ---
if [[ -n "${ALLOW_FROM_CIDR}" ]] && ! valid_ipv4_or_cidr "${ALLOW_FROM_CIDR}"; then
    err "ALLOW_FROM_CIDR='${ALLOW_FROM_CIDR}' некорректен — ожидается IPv4 или CIDR (например 203.0.113.0/24)."
    exit 1
fi

# --- Валидация кред: пробел/перевод строки ломают токенизацию 3proxy-конфига (#6) ---
# users/parent в 3proxy.cfg — это поля, разделяемые пробелами; любой whitespace в логине
# или пароле сместит токены и сломает аутентификацию. Поэтому жёстко запрещаем.
# FOREIGN_* проверяем ТОЛЬКО в прежнем режиме (в residential-режиме Dante не используется;
# residential-креды уже проверены выше).
if [[ "${RESI_MODE}" -eq 0 ]]; then
    if ! no_whitespace "${FOREIGN_USER}"; then
        err "FOREIGN_USER содержит пробел/перевод строки — это сломает токенизацию 3proxy-конфига. Уберите пробелы."
        exit 1
    fi
    # (#2) Двоеточие в кредах сдвигает поля colon-разделённой записи 3proxy -> битая аутентификация.
    if ! no_colon "${FOREIGN_USER}"; then
        err "FOREIGN_USER содержит двоеточие ':' — 3proxy использует ':' как разделитель полей, это сломает аутентификацию. Уберите двоеточие."
        exit 1
    fi
    if ! no_whitespace "${FOREIGN_PASS}"; then
        err "FOREIGN_PASS содержит пробел/перевод строки — это сломает токенизацию 3proxy-конфига. Уберите пробелы."
        exit 1
    fi
    if ! no_colon "${FOREIGN_PASS}"; then
        err "FOREIGN_PASS содержит двоеточие ':' — 3proxy использует ':' как разделитель полей, это сломает аутентификацию. Уберите двоеточие."
        exit 1
    fi
fi
if ! no_whitespace "${LOCAL_USER}"; then
    err "LOCAL_USER содержит пробел/перевод строки — это сломает токенизацию 3proxy-конфига. Уберите пробелы."
    exit 1
fi
if ! no_colon "${LOCAL_USER}"; then
    err "LOCAL_USER содержит двоеточие ':' — 3proxy использует ':' как разделитель полей (users U:CL:P), это сломает аутентификацию. Уберите двоеточие."
    exit 1
fi
# LOCAL_PASS может быть пуст здесь (тогда подхватим/сгенерируем ниже); если задан вручную — проверяем.
if [[ -n "${LOCAL_PASS}" ]] && ! no_whitespace "${LOCAL_PASS}"; then
    err "LOCAL_PASS содержит пробел/перевод строки — это сломает токенизацию 3proxy-конфига. Уберите пробелы."
    exit 1
fi
if [[ -n "${LOCAL_PASS}" ]] && ! no_colon "${LOCAL_PASS}"; then
    err "LOCAL_PASS содержит двоеточие ':' — 3proxy использует ':' как разделитель полей (users U:CL:P), это сломает аутентификацию. Уберите двоеточие."
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive

# --- Приватный временный каталог сборки (#14) ---
# mktemp -d создаёт каталог с непредсказуемым именем, режимом 700 и владельцем root —
# исключает TOCTOU/symlink-подмену, возможную при фиксированном пути в world-writable /tmp.
# trap ... EXIT гарантированно удаляет каталог при любом выходе (успех/ошибка/прерывание),
# как и sibling-скрипт mtproxy.
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/3proxy-build.XXXXXXXX")"
trap 'rm -rf "${WORK_DIR}"' EXIT
log "Временный каталог сборки: ${WORK_DIR} (будет удалён по завершении)."

# ============================================================================
#  1. БАЗОВЫЕ ПАКЕТЫ
# ============================================================================

log "Обновляю списки пакетов и ставлю зависимости..."
apt-get update -y
# curl/ca-certificates — для проверки и финального теста; ufw — фаервол;
# openssl — генерация пароля; dpkg — валидация .deb; iproute2 (ss) — фолбэк-детект SSH-порта;
# coreutils — sha256sum/install.
apt-get install -y curl ca-certificates ufw coreutils openssl dpkg iproute2

# Сгенерировать/переиспользовать пароль клиента ПОСЛЕ установки openssl.
# Идемпотентность (#9): пароль релея хранится в ОТДЕЛЬНОМ файле ${PASS_FILE} (chmod 600),
# НЕ привязан к текущему LOCAL_USER. При повторном запуске берём пароль оттуда — даже если
# логин сменили или конфиг переформатировали, действующие клиенты не отваливаются.
if [[ -z "${LOCAL_PASS}" ]]; then
    if [[ -f "${PASS_FILE}" ]]; then
        EXISTING_PASS="$(head -n1 "${PASS_FILE}" 2>/dev/null || true)"
        # (#9) Переиспользуемый из ${PASS_FILE} пароль валидируем ТЕМ ЖЕ набором правил, что и
        # введённый вручную LOCAL_PASS: не только no_whitespace, но и no_colon. Двоеточие в
        # пароле сдвигает поля colon-разделённой записи 'users ${LOCAL_USER}:CL:${LOCAL_PASS}'
        # в 3proxy.cfg => битая аутентификация. Файл мог быть записан вручную/прошлой версией
        # без этой проверки, поэтому валидируем при reuse, а не доверяем источнику.
        if [[ -n "${EXISTING_PASS:-}" ]] && no_whitespace "${EXISTING_PASS}" && no_colon "${EXISTING_PASS}"; then
            LOCAL_PASS="${EXISTING_PASS}"
            log "LOCAL_PASS переиспользован из ${PASS_FILE} (учётные данные клиента не меняются)."
        else
            # Файл есть, но первая строка пуста, содержит whitespace ИЛИ двоеточие (битый/частично
            # записанный/ручной файл). Молчаливый reuse-skip ниже перегенерировал бы пароль и залочил
            # действующих клиентов — поэтому громко предупреждаем (#11), что старый пароль игнорируется.
            warn "Существующий ${PASS_FILE} невалиден (пустая первая строка, whitespace или двоеточие ':') — старый пароль ИГНОРИРУЕТСЯ, будет сгенерирован НОВЫЙ. Действующим клиентам потребуется обновить пароль."
        fi
    fi
fi
if [[ -z "${LOCAL_PASS}" ]]; then
    # openssl rand отдаёт фиксированную длину — нет SIGPIPE/обрыва пайпа под set -o pipefail
    # (в отличие от 'head -c .. /dev/urandom | base64 | head -c ..', который ломается на pipefail).
    LOCAL_PASS="$(openssl rand -hex 18)"
    log "LOCAL_PASS не задан — сгенерирован автоматически через openssl (см. сводку в конце)."
fi

# Сохраняем пароль релея в отдельный файл с маской 600 — источник истины для re-run (#9).
mkdir -p "${CFG_DIR}"
umask 077
printf '%s\n' "${LOCAL_PASS}" > "${PASS_FILE}"
umask 022
chown root:root "${PASS_FILE}"
chmod 600 "${PASS_FILE}"

# Определяем архитектуру для выбора .deb-ассета релиза 3proxy.
DEB_ARCH=""
case "$(uname -m)" in
    x86_64)          DEB_ARCH="x86_64" ;;
    aarch64|arm64)   DEB_ARCH="arm64"  ;;
    armv7l|armv6l)   DEB_ARCH="arm"    ;;
    *)               DEB_ARCH=""       ;;  # неизвестная арх. -> пойдём в сборку из git
esac

# ============================================================================
#  2. СЕРВИСНЫЙ ПОЛЬЗОВАТЕЛЬ (непривилегированный демон)
# ============================================================================

if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    log "Создаю системного пользователя ${SERVICE_USER} (без shell, без логина)..."
    useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
else
    log "Системный пользователь ${SERVICE_USER} уже существует — пропускаю."
fi

# ============================================================================
#  3. УСТАНОВКА 3proxy
# ============================================================================
# Стратегия (по убыванию надёжности):
#   (а) ПРИОРИТЕТНО (#9) — собрать из git по ЗАПИНЕННОМУ commit-SHA (PINNED_COMMIT): это
#       единственный путь с проверяемой подлинностью исходника. Если PINNED_COMMIT задан —
#       используем его в первую очередь.
#   (б) официальный .deb релиза THREEPROXY_VERSION под нашу архитектуру — ТОЛЬКО как fallback,
#       когда git-путь недоступен/не запинен. Проверка: ОБЯЗАТЕЛЬНО integrity (валидный .deb,
#       а не HTML-404); и, если задан EXPECTED_DEB_SHA256 — жёсткая сверка SHA256. ВАЖНО:
#       апстрим НЕ публикует контрольных сумм/подписей, поэтому без EXPECTED_DEB_SHA256 это
#       НЕ гарантия подлинности — при пустом хэше ставим только с ГРОМКИМ предупреждением (#9).
#   (в) ПОСЛЕДНИЙ РУБЕЖ ДОСТУПНОСТИ (#availability) — если PINNED_COMMIT пуст И .deb-путь
#       недоступен (offline/odd-arch/404/переименован asset), собираем из ЗАПИНЕННОГО ТЕГА
#       3proxy-${THREEPROXY_VERSION} с ГРОМКИМ предупреждением (тег mutable, подлинность НЕ
#       проверена). На плавающий master НЕ откатываемся НИКОГДА.
#
# ВНИМАНИЕ: 3proxy НЕТ в стандартных репозиториях Ubuntu 24.04/Debian, поэтому apt-путь
# из дистрибутива не используется — ставим только из официального релиза апстрима либо из исходников.

# Уже установлен бинарь? (deb кладёт /usr/bin/3proxy; сборка — /usr/local/bin/3proxy)
THREEPROXY_BIN=""
detect_binary() {
    local c
    for c in /usr/local/bin/3proxy /usr/bin/3proxy /bin/3proxy; do
        if [[ -x "$c" ]]; then THREEPROXY_BIN="$c"; return 0; fi
    done
    return 1
}

# Нейтрализуем юнит, который МОЖЕТ приехать и автозапуститься вместе с .deb:
# апстримовый /lib/systemd/system/3proxy.service запускает демон ОТ ROOT и с ЧУЖИМ конфигом.
# Нам нужен только наш hardened ${UNIT_NAME}. Поэтому пакетный юнит останавливаем/выключаем/маскируем.
neutralize_packaged_unit() {
    if systemctl list-unit-files 3proxy.service >/dev/null 2>&1; then
        if systemctl cat 3proxy.service >/dev/null 2>&1; then
            warn "Обнаружен пакетный 3proxy.service (запускался бы от root) — останавливаю и маскирую, оставляю только ${UNIT_NAME}."
            systemctl stop 3proxy.service 2>/dev/null || true
            systemctl disable 3proxy.service 2>/dev/null || true
            systemctl mask 3proxy.service 2>/dev/null || true
        fi
    fi
}

install_from_deb() {
    [[ -n "${DEB_ARCH}" ]] || return 1
    local asset="3proxy-${THREEPROXY_VERSION}.${DEB_ARCH}.deb"
    local url="${THREEPROXY_REPO}/releases/download/${THREEPROXY_VERSION}/${asset}"
    local path="${WORK_DIR}/${asset}"
    log "Пробую установить из официального .deb: ${asset}"
    if ! curl -fsSL --retry 3 -o "${path}" "${url}"; then
        warn ".deb недоступен по ${url} — перехожу к сборке из исходников."
        return 1
    fi
    # (1) integrity: это реально .deb, а не HTML-страница 404?
    if ! dpkg-deb --info "${path}" >/dev/null 2>&1; then
        warn "Скачанный ${asset} не является корректным .deb (вероятно 404/битый файл) — перехожу к сборке из исходников."
        return 1
    fi
    # (2) опциональная жёсткая сверка SHA256 (если хэш задан вручную).
    if [[ -n "${EXPECTED_DEB_SHA256}" ]]; then
        local got
        got="$(sha256sum "${path}" | awk '{print $1}')"
        if [[ "${got}" != "${EXPECTED_DEB_SHA256}" ]]; then
            err "SHA256 НЕ совпал для ${asset}: ожидалось ${EXPECTED_DEB_SHA256}, получено ${got}. Прерываю установку из .deb."
            return 1
        fi
        log "SHA256 .deb подтверждён вручную заданным значением — установка разрешена."
    else
        # (#9) EXPECTED_DEB_SHA256 пуст — НЕ ставим молча. Громкое многострочное предупреждение,
        # что пакет НЕ аутентифицирован; правильный путь — git-сборка по PINNED_COMMIT.
        warn "############################################################################"
        warn "# ВНИМАНИЕ: УСТАНОВКА НЕАУТЕНТИФИЦИРОВАННОГО .deb"
        warn "#   EXPECTED_DEB_SHA256 пуст — выполнена ТОЛЬКО integrity-проверка"
        warn "#   (что файл действительно .deb, а не HTML-404). Подлинность пакета"
        warn "#   криптографически НЕ подтверждена: апстрим 3proxy не публикует"
        warn "#   подписей/контрольных сумм. Это supply-chain-риск."
        warn "#   РЕКОМЕНДАЦИЯ: задайте PINNED_COMMIT и используйте git-сборку, либо"
        warn "#   впишите проверенный EXPECTED_DEB_SHA256 (64 hex), сверенный вне канала."
        warn "############################################################################"
    fi
    log "Устанавливаю ${asset} через apt (подтянет зависимости, например libpcre2)..."
    # apt install <абсолютный путь>.deb сам разрешает зависимости deb-пакета.
    apt-get install -y "${path}"
    # .deb может притащить и автозапустить собственный root-юнит — нейтрализуем.
    neutralize_packaged_unit
    return 0
}

build_from_git() {
    # Цель ревизии для checkout: либо запиненный commit-SHA (проверяемый), либо — как
    # последний рубеж доступности (#availability) — запиненный ТЕГ. На master НЕ откатываемся.
    local git_ref
    local pinned_by_sha=0
    if [[ -n "${PINNED_COMMIT}" ]]; then
        # (#8) ПРОВЕРЯЕМЫЙ путь: собираем строго с запиненного commit-SHA.
        git_ref="${PINNED_COMMIT}"
        pinned_by_sha=1
        warn "СБОРКА ИЗ ИСХОДНИКОВ — ставлю компилятор и собираю с запиненного commit ${PINNED_COMMIT}."
    else
        # (#availability) PINNED_COMMIT пуст и .deb-путь не сработал. Чтобы установка вообще
        # прошла на offline/odd-arch хостах, собираем из ЗАПИНЕННОГО ТЕГА. Тег — mutable-указатель,
        # подлинность исходника НЕ проверена -> ГРОМКОЕ многострочное предупреждение. На плавающий
        # master НЕ откатываемся.
        git_ref="3proxy-${THREEPROXY_VERSION}"
        warn "############################################################################"
        warn "# ВНИМАНИЕ: СБОРКА ИЗ MUTABLE-ТЕГА (последний рубеж доступности)"
        warn "#   PINNED_COMMIT не задан, а .deb-путь недоступен (offline / неизвестная"
        warn "#   архитектура / 404 / переименован asset). Чтобы установка не сорвалась"
        warn "#   совсем, собираю из тега '${git_ref}'."
        warn "#   ТЕГ — ПЕРЕМЕЩАЕМЫЙ указатель: подлинность исходника криптографически"
        warn "#   НЕ подтверждена (это supply-chain-риск). Это компромисс ради доступности."
        warn "#   РЕКОМЕНДАЦИЯ: впишите проверенный PINNED_COMMIT (см. TODO у переменной"
        warn "#   PINNED_COMMIT) либо EXPECTED_DEB_SHA256 — тогда установка станет проверяемой."
        warn "#   На плавающий master скрипт НЕ откатывается ни при каких условиях."
        warn "############################################################################"
        warn "СБОРКА ИЗ ИСХОДНИКОВ — ставлю компилятор и собираю из тега ${git_ref}."
    fi
    apt-get install -y build-essential git
    rm -rf "${WORK_DIR}/3proxy-src"
    # Полный клон (не --depth 1 --branch tag): нам нужно сделать checkout произвольной ревизии
    # (commit-SHA или тега), а тег — mutable-указатель, поэтому фиксируемся явным checkout.
    git clone "${THREEPROXY_REPO}" "${WORK_DIR}/3proxy-src"
    # Checkout строго на целевую ревизию. Если её нет — fail-close (на master НЕ откатываемся).
    if ! git -C "${WORK_DIR}/3proxy-src" checkout --quiet "${git_ref}"; then
        err "Не удалось сделать checkout ревизии '${git_ref}' — прерываю (НЕ откатываюсь на master)."
        exit 1
    fi
    local head_sha
    head_sha="$(git -C "${WORK_DIR}/3proxy-src" rev-parse HEAD)"
    if [[ "${pinned_by_sha}" -eq 1 ]]; then
        # Проверяем, что HEAD действительно равен запиненному SHA (а не передвинутому тегу/ветке).
        if [[ "${head_sha}" != "${PINNED_COMMIT}" ]]; then
            err "HEAD после checkout (${head_sha}) НЕ совпал с PINNED_COMMIT (${PINNED_COMMIT}) — прерываю сборку."
            exit 1
        fi
        log "Исходники зафиксированы на commit ${head_sha} (подтверждено)."
    else
        # Сборка из тега: SHA лишь печатаем для аудита — подлинность НЕ гарантируется.
        log "Исходники из тега ${git_ref} -> commit ${head_sha} (НЕ проверено, mutable-тег)."
    fi
    make -C "${WORK_DIR}/3proxy-src" -f Makefile.Linux
    # Кладём собранный бинарь в /usr/local/bin (надёжный, фиксированный путь для юнита).
    local built="${WORK_DIR}/3proxy-src/bin/3proxy"
    if [[ ! -x "${built}" ]]; then
        err "Сборка не дала бинарь ${built} — прерываю."
        exit 1
    fi
    install -m 0755 "${built}" "${BIN_PATH}"
    log "Бинарь 3proxy установлен в ${BIN_PATH} (сборка из исходников)."
}

if detect_binary; then
    log "3proxy уже установлен: ${THREEPROXY_BIN} — пропускаю установку (идемпотентность)."
    # На случай, если ранее был поставлен .deb со своим root-юнитом — всё равно нейтрализуем.
    neutralize_packaged_unit
elif [[ -n "${PINNED_COMMIT}" ]]; then
    # (#9) ПРИОРИТЕТНО — git-сборка по запиненному SHA: единственный путь с проверяемой
    # подлинностью. Когда PINNED_COMMIT задан, не трогаем неаутентифицированный .deb.
    build_from_git
    detect_binary || { err "Не удалось обнаружить бинарь 3proxy после сборки из git."; exit 1; }
    log "3proxy готов (git, запиненный commit): ${THREEPROXY_BIN}"
else
    # PINNED_COMMIT не задан. Сначала пробуем .deb (с громким предупреждением о
    # неаутентифицированности при пустом EXPECTED_DEB_SHA256, см. #9). Если .deb недоступен
    # (offline / неизвестная архитектура / 404 / переименован asset) — уходим в build_from_git,
    # который как ПОСЛЕДНИЙ РУБЕЖ ДОСТУПНОСТИ (#availability) соберёт из запиненного ТЕГА
    # 3proxy-${THREEPROXY_VERSION} с громким предупреждением (тег mutable, не на master).
    if install_from_deb && detect_binary; then
        log "3proxy установлен из официального .deb: ${THREEPROXY_BIN}"
    else
        build_from_git
        detect_binary || { err "Не удалось обнаружить бинарь 3proxy после установки."; exit 1; }
        log "3proxy готов: ${THREEPROXY_BIN}"
    fi
fi

# ============================================================================
#  4. КОНФИГ /etc/3proxy/3proxy.cfg
# ============================================================================
# Директивы проверены по официальному cfg/3proxy.cfg.sample апстрима:
#   nserver / nscache  — DNS-резолвинг и кэш;
#   timeouts           — таймауты соединений (значения из примера апстрима);
#   auth strong        — обязательная аутентификация по логину/паролю;
#   users U:CL:P       — пользователь с CLeartext-паролем;
#   allow U            — разрешить трафик только нашему пользователю;
#   parent W socks5+ IP PORT USER PASS — цепочка на зарубежный SOCKS5 (socks5+ = DNS-резолв на стороне родителя, без утечки);
#   socks -pPORT       — поднять SOCKS-листенер на нужном порту.
# Привилегии демона задаём systemd-юнитом (User=/Group=), поэтому setuid/setgid в конфиге НЕ дублируем.

# Снимок чек-суммы конфига ДО записи — чтобы рестартить демон только при реальном
# изменении (#13). 'sha256sum' отсутствующего файла даёт пустую строку (|| true).
CFG_SHA_BEFORE=""
if [[ -f "${CFG_FILE}" ]]; then
    CFG_SHA_BEFORE="$(sha256sum "${CFG_FILE}" 2>/dev/null | awk '{print $1}' || true)"
fi

log "Пишу конфиг ${CFG_FILE}..."
mkdir -p "${CFG_DIR}" "${LOG_DIR}"
chown "${SERVICE_USER}:${SERVICE_USER}" "${LOG_DIR}"

# --- Формируем строку parent под активный выход ---
# Прежний режим (Dante): socks5+ на зарубежный VPS.
# Режим residential (Способ B): socks5+ или connect+ (для http) на residential-шлюз.
# socks5+/connect+ отдают резолв имён на сторону родителя (выход с его IP, без DNS-утечки).
if [[ "${RESI_MODE}" -eq 1 ]]; then
    if [[ "${RESI_TYPE}" == "http" ]]; then
        PARENT_LINE="parent 1000 connect+ ${RESI_HOST} ${RESI_PORT} ${RESI_USER} ${RESI_PASS}"
    else
        PARENT_LINE="parent 1000 socks5+ ${RESI_HOST} ${RESI_PORT} ${RESI_USER} ${RESI_PASS}"
    fi
    PARENT_COMMENT="# --- Вышестоящий (parent) прокси: residential-шлюз (Способ B) — выход с РЕЗИДЕНТНОГО IP ---
# Хоп через зарубежный Dante НЕ используется. Тип residential: ${RESI_TYPE}."
else
    PARENT_LINE="parent 1000 socks5+ ${FOREIGN_VPS_IP} ${FOREIGN_SOCKS_PORT} ${FOREIGN_USER} ${FOREIGN_PASS}"
    PARENT_COMMENT="# --- Вышестоящий (parent) прокси: весь трафик уходит на зарубежный SOCKS5 (Dante) ---
# socks5+ — отдаём резолв имён на сторону зарубежного VPS (выход с иностранного IP, без DNS-утечки)."
fi

# Конфиг содержит пароли -> создаём с маской 600 ещё ДО записи (умаска временно).
umask 077
cat > "${CFG_FILE}" <<EOF
# /etc/3proxy/3proxy.cfg — сгенерировано setup-ru-relay.sh
# РФ-релей: аутентифицированный SOCKS5 -> вышестоящий зарубежный SOCKS5 (Dante).

# --- DNS: резолвим имена через публичные серверы, кэшируем ответы ---
nserver ${NSERVER_1}
nserver ${NSERVER_2}
nscache 65536

# --- Таймауты (значения из официального примера апстрима) ---
timeouts 1 5 30 60 180 1800 15 60

# --- Логирование (демон работает от ${SERVICE_USER}, каталог принадлежит ему) ---
# (#2) Приватность на подсанкционном РФ-узле: НЕ храним досье "кто к каким адресам ходил".
# Логируем ТОЛЬКО дату/время, тип записи и код ошибки/завершения (%E) — без идентифицирующих
# и destination-полей: убраны client IP (%C), username (%U), целевой host (%h) и
# upstream-адрес/порт (%R:%r). Этого достаточно для диагностики службы, но недостаточно
# для слежки за пользователем.
log ${LOG_DIR}/3proxy.log D
logformat "L%d-%m-%Y %H:%M:%S %p %E"
# rotate 0 — не накапливаем ротированные суточные логи (никакого 7-дневного архива метаданных).
rotate 0

# --- Строгая аутентификация: только по логину/паролю ---
auth strong

# --- Пользователь клиента: CL = cleartext-пароль в конфиге (файл chmod 600) ---
users ${LOCAL_USER}:CL:${LOCAL_PASS}

# --- Разрешаем выход в сеть ТОЛЬКО нашему пользователю ---
allow ${LOCAL_USER}

${PARENT_COMMENT}
${PARENT_LINE}

# --- Локальный SOCKS5-листенер на этом РФ-сервере ---
socks -p${LOCAL_PORT}
EOF
umask 022

# Жёстко фиксируем права и владельца: конфиг с паролями читает только владелец-демон.
chown "${SERVICE_USER}:${SERVICE_USER}" "${CFG_FILE}"
chmod 600 "${CFG_FILE}"
log "Конфиг записан, права 600, владелец ${SERVICE_USER}."

# Изменился ли конфиг по сравнению со снимком ДО записи?
# Через if-then (НЕ '[[ ]] && var=1') — иначе ложное условие вернёт код 1 и под set -e
# оборвёт скрипт.
CFG_SHA_AFTER="$(sha256sum "${CFG_FILE}" 2>/dev/null | awk '{print $1}' || true)"
CONFIG_CHANGED=0
if [[ "${CFG_SHA_AFTER}" != "${CFG_SHA_BEFORE}" ]]; then CONFIG_CHANGED=1; fi

# ============================================================================
#  5. systemd-ЮНИТ
# ============================================================================
# Демон стартует после поднятия сети, работает от непривилегированного пользователя,
# автоматически перезапускается при падении. Имя ${UNIT_NAME} специально отличается от
# пакетного 3proxy.service (который мы маскируем выше), чтобы исключить любые коллизии.

log "Создаю systemd-юнит ${UNIT_FILE}..."

# Снимок чек-суммы юнита ДО записи — рестарт только при изменении (#13).
UNIT_SHA_BEFORE=""
if [[ -f "${UNIT_FILE}" ]]; then
    UNIT_SHA_BEFORE="$(sha256sum "${UNIT_FILE}" 2>/dev/null | awk '{print $1}' || true)"
fi

# Блок capability добавляем ТОЛЬКО если LOCAL_PORT < 1024 (bind на привилегированный порт
# непривилегированным процессом). Для дефолтного 1080 он не нужен.
# Каждая строка блока имеет ВЕДУЩИЙ '\n' (а не хвостовой) — так подстановка ${CAP_BLOCK}
# в heredoc не оставляет лишней пустой строки перед [Install], когда блок пуст (#12).
CAP_BLOCK=""
# (#6) 10# форсирует base-10: без него LOCAL_PORT с ведущим нулём (например '0080')
# арифметика [[ -lt ]] / (( )) трактовала бы как ВОСЬМЕРИЧНОЕ число — рассинхрон с
# base-10-контрактом valid_port (она уже приняла '0080' как 80). Сверяем строго в base-10.
if (( 10#${LOCAL_PORT} < 1024 )); then
    warn "LOCAL_PORT=${LOCAL_PORT} < 1024 — добавляю CAP_NET_BIND_SERVICE в юнит."
    CAP_BLOCK=$'\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE'
fi

cat > "${UNIT_FILE}" <<EOF
[Unit]
Description=3proxy SOCKS5 relay (RU -> foreign Dante)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# Запуск от непривилегированного сервисного аккаунта (без root-привилегий у процесса).
User=${SERVICE_USER}
Group=${SERVICE_USER}
ExecStart=${THREEPROXY_BIN} ${CFG_FILE}
Restart=on-failure
RestartSec=5
# Доп. изоляция процесса (безопасные дефолты systemd).
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
ReadWritePaths=${LOG_DIR}${CAP_BLOCK}

[Install]
WantedBy=multi-user.target
EOF

# Изменился ли юнит? Складываем с флагом конфига -> рестартим только при реальной разнице (#13).
# if-then, а не '[[ ]] && var=1' — см. пояснение выше про set -e.
UNIT_SHA_AFTER="$(sha256sum "${UNIT_FILE}" 2>/dev/null | awk '{print $1}' || true)"
if [[ "${UNIT_SHA_AFTER}" != "${UNIT_SHA_BEFORE}" ]]; then CONFIG_CHANGED=1; fi

log "Перечитываю unit-файлы и включаю автозапуск..."
systemctl daemon-reload
systemctl enable "${UNIT_NAME}"

# Рестарт только при изменении конфига/юнита ИЛИ если служба сейчас не запущена (#13):
#   безусловный restart на каждом re-run рвал бы живые клиентские сессии без причины.
#   '|| true' у is-active — это запрос состояния, не ошибка (НЕ должен валить set -e).
if [[ "${CONFIG_CHANGED}" -eq 1 ]]; then
    log "Конфиг/юнит изменились — перезапускаю ${UNIT_NAME}."
    systemctl restart "${UNIT_NAME}"
elif ! systemctl is-active --quiet "${UNIT_NAME}"; then
    log "${UNIT_NAME} не запущена — стартую."
    systemctl start "${UNIT_NAME}"
else
    log "Конфиг/юнит без изменений и служба активна — рестарт не нужен (живые сессии не рвём)."
fi

# ============================================================================
#  6. ФАЕРВОЛ ufw  (КРИТИЧНО: SSH открываем ДО enable, иначе залочим доступ!)
# ============================================================================
# (#14) Анти-локаут-оркестрация больше НЕ скопирована сюда инлайном — она вынесена
# в единую ufw_orchestrate (_lib.sh) и используется всеми service-скриптами:
#   - ufw уже активен (ПОВТОРНЫЙ запуск): SSH-правила НЕ трогаются и enable НЕ делается
#     (иначе откатили бы сужение бастиона / переоткрыли бы SSH всему миру — finding #4);
#     вызывается только наша add_service_rules (идемпотентно добавляет порт релея).
#   - ufw неактивен (ПЕРВЫЙ запуск): разрешаются ВСЕ SSH-порты (detect_ssh_ports) и
#     считаются успешные; если ни один не применился — return 1 (мы ОБЯЗАНЫ прекратить и
#     НЕ включать фаервол: default-deny без SSH = локаут) -> '|| exit 1'. Иначе вызывается
#     add_service_rules и 'ufw --force enable'.
# Сервис-правила релея (порт LOCAL_PORT/tcp: fail-closed из ALLOW_FROM_CIDR либо ufw limit
# при пустом CIDR) определены выше в add_service_rules. ufw_orchestrate ставит глобал
# UFW_FINAL_STATE (active|unknown) — используем его в итоговом баннере ниже.

log "Настраиваю ufw (анти-локаут + idempotent re-run через ufw_orchestrate)..."
# (#7) НЕ пишем 'ufw_orchestrate add_service_rules || exit 1': LHS оператора '||' выполняется в
# контексте, где set -e ПОДАВЛЕН на протяжении ВСЕГО вызова (включая тело ufw_orchestrate и
# вложенный коллбэк add_service_rules). Из-за этого ЛЮБОЙ ненулевой код внутри них (не только
# финальный return 1 «ни одно SSH-правило не применилось») перестал бы прерывать выполнение, а
# сбойную команду мы бы молча проскочили. Разрываем '||': запускаем оркестрацию как ОТДЕЛЬНУЮ
# команду (set -e снова активен внутри), затем явно проверяем её код возврата.
ufw_orchestrate add_service_rules
__rc=$?
(( __rc == 0 )) || exit 1

# (#1) Если ALLOW_FROM_CIDR пуст — порт открыт всему интернету. Помимо 'ufw limit' ставим
# fail2ban как второй слой против брутфорса пароля (вне зависимости от ветви ufw выше).
if [[ -z "${ALLOW_FROM_CIDR}" ]]; then
    setup_fail2ban
fi

# ============================================================================
#  7. ПРОВЕРКА ЦЕПОЧКИ
# ============================================================================
# Делаем запрос наружу ЧЕРЕЗ локальный SOCKS5 с авторизацией. Если возвращается
# ИНОСТРАННЫЙ IP — значит parent (зарубежный Dante) работает и трафик выходит за рубежом.

log "Жду 2с старта демона и проверяю цепочку через локальный SOCKS5..."
sleep 2

if ! systemctl is-active --quiet "${UNIT_NAME}"; then
    err "Служба ${UNIT_NAME} не активна. Логи: journalctl -u ${UNIT_NAME} -n 50 --no-pager"
    systemctl status "${UNIT_NAME}" --no-pager || true
    exit 1
fi

CHECK_URL="https://api.ipify.org"
log "curl --socks5 ${LOCAL_USER}:***@127.0.0.1:${LOCAL_PORT} ${CHECK_URL}"
EXIT_IP="$(curl -fsS --max-time 25 \
    --socks5 "${LOCAL_USER}:${LOCAL_PASS}@127.0.0.1:${LOCAL_PORT}" \
    "${CHECK_URL}" || true)"

if [[ -n "${EXIT_IP}" ]]; then
    log "Внешний IP через цепочку: ${EXIT_IP}"
    if [[ "${RESI_MODE}" -eq 1 ]]; then
        # В residential-режиме выходной IP — это резидентный адрес, выданный провайдером
        # (часто ротируется), сверять его с фиксированным значением нечем. Достаточно, что
        # запрос наружу прошёл через цепочку и вернулся непустой IP.
        log "OK: запрос прошёл через residential-выход ${RESI_HOST}:${RESI_PORT} (тип ${RESI_TYPE}) — цепочка работает; ${EXIT_IP} должен быть РЕЗИДЕНТНЫМ IP."
    elif [[ "${EXIT_IP}" == "${FOREIGN_VPS_IP}" ]]; then
        log "OK: выходной IP совпал с зарубежным VPS — parent-цепочка работает."
    else
        warn "Выходной IP (${EXIT_IP}) не равен FOREIGN_VPS_IP (${FOREIGN_VPS_IP})."
        warn "Это нормально, если у зарубежного VPS отдельный исходящий IP/NAT. Главное — IP иностранный."
    fi
else
    # Сам релей ЖИВ (юнит активен — проверено выше). Пустой ответ здесь — это, как правило,
    # КРАТКОВРЕМЕННАЯ недоступность upstream (residential-шлюз/зарубежный VPS/сеть), а не поломка
    # релея. Поэтому НЕ валим скрипт exit 1 под set -e (иначе идемпотентный re-run «падает» на
    # ровном месте), а громко ПРЕДУПРЕЖДАЕМ и доводим до конца — служба и сводка полезны (#13).
    warn "Не удалось получить внешний IP через релей при проверке (служба ${UNIT_NAME} при этом АКТИВНА — вероятно кратковременная недоступность upstream). Проверьте:"
    if [[ "${RESI_MODE}" -eq 1 ]]; then
        warn "  - доступность residential-шлюза ${RESI_HOST}:${RESI_PORT} (тип ${RESI_TYPE}) с этого сервера;"
        warn "  - корректность RESI_USER/RESI_PASS;"
    else
        warn "  - доступность ${FOREIGN_VPS_IP}:${FOREIGN_SOCKS_PORT} с этого сервера;"
        warn "  - корректность FOREIGN_USER/FOREIGN_PASS;"
    fi
    warn "  - логи: journalctl -u ${UNIT_NAME} -n 50 --no-pager и ${LOG_DIR}/3proxy.log"
    warn "Повторите проверку вручную:"
    warn "  curl -fsS --socks5 ${LOCAL_USER}:***@127.0.0.1:${LOCAL_PORT} ${CHECK_URL}"
fi

# ============================================================================
#  8. ИТОГОВАЯ СВОДКА
# ============================================================================
SERVER_PUB_IP="$(curl -fsS --max-time 10 https://api.ipify.org || echo 'неизвестен')"

# --- Готовим строки сводки под активный выход (residential vs зарубежный Dante) ---
if [[ "${RESI_MODE}" -eq 1 ]]; then
    EXIT_SUMMARY="Выход: RESIDENTIAL ${RESI_HOST}:${RESI_PORT} (резидентный IP, тип ${RESI_TYPE})"
    PARENT_SUMMARY="Вышестоящий (parent) residential-шлюз (Способ B):
    ${RESI_HOST}:${RESI_PORT}  (тип ${RESI_TYPE}, логин ${RESI_USER}) — выход с РЕЗИДЕНТНОГО IP"
    CHAIN_SUMMARY="[ПК/телефон] -> [РФ-сервер :${LOCAL_PORT}] -> [residential ${RESI_HOST}:${RESI_PORT}] -> Claude/интернет"
else
    EXIT_SUMMARY="Выход: зарубежный Dante ${FOREIGN_VPS_IP}:${FOREIGN_SOCKS_PORT} (датацентровый IP)"
    PARENT_SUMMARY="Вышестоящий (parent) зарубежный SOCKS5 (Dante):
    ${FOREIGN_VPS_IP}:${FOREIGN_SOCKS_PORT}  (логин ${FOREIGN_USER})"
    CHAIN_SUMMARY="[ПК/телефон] -> [РФ-сервер :${LOCAL_PORT}] -> [VPS ${FOREIGN_VPS_IP}:${FOREIGN_SOCKS_PORT}] -> Claude/интернет"
fi

# --- Состояние фаервола из ufw_orchestrate (#14): active => включён; unknown => честное
#     предупреждение, что enable мог не пройти (OpenVZ/без nf_tables) и порт релея может быть
#     открыт без фильтрации ufw. UFW_FINAL_STATE выставила ufw_orchestrate выше. ---
if [[ "${UFW_FINAL_STATE:-unknown}" == "active" ]]; then
    UFW_STATE_SUMMARY="Фаервол ufw: АКТИВЕН (SSH и порт релея ${LOCAL_PORT}/tcp разрешены, остальное deny)"
else
    UFW_STATE_SUMMARY="Фаервол ufw: СОСТОЯНИЕ НЕИЗВЕСТНО — 'ufw --force enable' мог НЕ пройти (OpenVZ/без nf_tables). Проверьте вручную: ufw status"
fi

cat <<EOF

============================================================
  РФ-РЕЛЕЙ ГОТОВ
============================================================
  АКТИВНЫЙ ВЫХОД (проверен chain-тестом выше):
    ${EXIT_SUMMARY}
    ${UFW_STATE_SUMMARY}

  Подключение клиента (Proxifier / телефон):
    Тип:     SOCKS5
    Хост:    ${SERVER_PUB_IP}   (публичный IP этого РФ-сервера)
    Порт:    ${LOCAL_PORT}
    Логин:   ${LOCAL_USER}
    Пароль:  ${LOCAL_PASS}

  ${PARENT_SUMMARY}

  Полная цепочка:
    ${CHAIN_SUMMARY}

  Доступ к порту ${LOCAL_PORT}/tcp:
    ${ALLOW_FROM_CIDR:+только из ${ALLOW_FROM_CIDR} (ufw allow from, fail-closed)}${ALLOW_FROM_CIDR:-ОТКРЫТ ВСЕМУ ИНТЕРНЕТУ — реальная защита: длинный пароль (openssl) + ufw limit (rate-limit). fail2ban УСТАНОВЛЕН, но jail [3proxy-relay] ВЫКЛЮЧЕН (privacy-логи #2 без client IP — банить некого); включается вручную после настройки источника логов с IP}

  Управление:
    systemctl status ${UNIT_NAME}
    journalctl -u ${UNIT_NAME} -f
    конфиг: ${CFG_FILE}  (chmod 600)
    пароль релея: ${PASS_FILE}  (chmod 600, источник истины для re-run)
============================================================
EOF

log "Готово."
