# shellcheck shell=bash
###############################################################################
# _lib.sh — общие функции для скриптов SOCKS5-VPS toolkit.
#
# НАЗНАЧЕНИЕ:
#   Единый источник правды для логики, которая раньше копировалась в каждый
#   setup-*.sh и со временем РАСХОДИЛАСЬ (разные версии valid_ipv4_or_cidr,
#   detect_ssh_ports, детекта интерфейса, ufw-гейта). Теперь все скрипты
#   подключают этот файл, и правка делается в ОДНОМ месте.
#
# ПОДКЛЮЧЕНИЕ (в начале каждого setup-*.sh, ПОСЛЕ `set -euo pipefail`):
#   _SLV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)"
#   if [[ -z "${_SLV_DIR}" || ! -r "${_SLV_DIR}/_lib.sh" ]]; then
#     echo "ОШИБКА: рядом не найден _lib.sh — скопируйте его в каталог скрипта" >&2
#     exit 1
#   fi
#   # shellcheck source=/dev/null
#   source "${_SLV_DIR}/_lib.sh"
#
# ВАЖНО:
#   * Этот файл ТОЛЬКО определяет функции и НЕ выполняет действий при source.
#   * Он НЕ задаёт `set -euo pipefail` — это делает вызывающий скрипт.
#   * Скрипты теперь НЕ самодостаточны: при копировании на сервер кладите
#     _lib.sh В ТОТ ЖЕ каталог и запускайте как файл (sudo bash setup-*.sh),
#     а НЕ через stdin/pipe (там путь к _lib.sh не определить).
###############################################################################

# --- Логирование (единый стиль во всех скриптах) -----------------------------
log()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; }

# --- Валидаторы ---------------------------------------------------------------
# Возвращают код (0/1); вызывающий сам решает, делать ли exit. Вызывайте в
# контексте `if`/`||`, чтобы под set -e ненулевой код не оборвал скрипт.
#
# 10# форсирует base-10: иначе число с ведущим нулём и цифрой 8/9 (08, 09347,
# октет 203.0.113.08) bash трактует как восьмеричное и (( )) падает/врёт.

# valid_port <n> — целое 1..65535.
valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }

# valid_ipv4_or_cidr <addr> — IPv4 с опциональным /CIDR; октеты <=255, префикс <=32.
valid_ipv4_or_cidr() {
  [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]] || return 1
  local ip="${1%%/*}" pref="" o
  if [[ "$1" == */* ]]; then
    pref="${1#*/}"
    (( 10#$pref >= 0 && 10#$pref <= 32 )) || return 1
  fi
  local IFS='.'
  # shellcheck disable=SC2086
  for o in $ip; do (( 10#$o >= 0 && 10#$o <= 255 )) || return 1; done
  return 0
}

# valid_ipv4 <addr> — ровно один хост IPv4 (CIDR запрещён).
valid_ipv4() { [[ "$1" != */* ]] && valid_ipv4_or_cidr "$1"; }

# no_whitespace <str> / no_colon <str> — для кредов/значений в конфигах.
no_whitespace() { [[ "$1" != *[[:space:]]* ]]; }
no_colon()      { [[ "$1" != *:* ]]; }

# --- Детект внешнего сетевого интерфейса -------------------------------------
# Robust: ищет поле ПОСЛЕ ключевого слова 'dev' (а не жёсткий $5 — у маршрута
# без 'via'-шлюза поля сдвигаются и $5 вернул бы мусор вроде 'dhcp').
detect_ext_iface() {
  ip -o -4 route show to default 2>/dev/null \
    | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'
}

# --- Детект SSH-портов (анти-локаут) -----------------------------------------
# Под set -euo pipefail безопасна: grep'ы закрыты '|| true', глобы '2>/dev/null',
# пайплайн заканчивается на sort. ss-арм анкорится ТОЛЬКО к кавыченным
# "sshd"/"ssh"/ssh.socket (НЕ к голому 'systemd' — иначе ловит чужие сокеты).
# Свойство socket-активации — ListenStream (НЕ Listen). Безусловный echo 22 —
# страховка, чтобы список никогда не был пуст.
detect_ssh_ports() {
  {
    ss -H -tlnp 2>/dev/null | awk '/"sshd"/ || /"ssh"/ || /ssh\.socket/ { n=split($4,a,":"); p=a[n]; if (p ~ /^[0-9]+$/) print p }' || true
    systemctl show ssh.socket  -p ListenStream 2>/dev/null | tr ' ' '\n' | grep -oE '[0-9]+$' || true
    systemctl show sshd.socket -p ListenStream 2>/dev/null | tr ' ' '\n' | grep -oE '[0-9]+$' || true
    awk 'tolower($1)=="port" && $2 ~ /^[0-9]+$/ {print $2}' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true
    echo 22
  } | awk '$1>=1 && $1<=65535' | sort -un
  # Фильтр диапазона 1..65535 ПЕРЕД sort: источники выше пропускают только
  # ^[0-9]+$ без верхней границы, поэтому мусорный порт >65535 (или 0) дошёл бы
  # до 'ufw allow <port>' и свалил бы его. Значения уже числовые → awk-сравнение
  # безопасно. Так список SSH-портов гарантированно пригоден для ufw.
}

# --- ufw активен? ------------------------------------------------------------
# LC_ALL=C (англоязычный вывод вне зависимости от локали — пользователи в РФ),
# захват в переменную (НЕ пайп в grep -q → нет SIGPIPE под pipefail),
# fail-CLOSED: если статус не получить — считаем активным, чтобы НЕ переоткрыть
# SSH на уже забастионенном хосте.
# Код возврата: 0 = активен (или неизвестно), 1 = точно inactive.
ufw_is_active() {
  local s
  if s="$(LC_ALL=C ufw status 2>/dev/null)"; then
    case "$s" in
      *"Status: inactive"*) return 1 ;;
      *"Status: active"*)   return 0 ;;
      *)                    return 0 ;;
    esac
  fi
  return 0
}

# --- ufw-мутация, не валящая скрипт ------------------------------------------
# Транзиентный сбой (xtables-lock contention, OpenVZ без nf_tables) под set -e
# иначе оборвал бы скрипт в полуконфиге. Здесь — предупреждение, продолжаем.
ufw_safe() { ufw "$@" || warn "ufw $* вернул ненулевой код (продолжаю)"; }

# --- Очистка прежних правил для порта (rewrite, не duplicate) -----------------
# ufw_clear_port <port> <proto>
#   Удаляет ВСЕ прежние allow/limit-правила для <port>/<proto>, чтобы при
#   повторном запуске правило ПЕРЕЗАПИСЫВАЛОСЬ, а не ПЛОДИЛОСЬ дубликатами
#   (HIGH #1/#2). Вызывать ПЕРЕД добавлением актуального правила.
#
# АНТИ-ЛОКАУТ (by design): SSH-порты НИКОГДА не чистим. Если <port> совпадает с
#   любым SSH-портом из detect_ssh_ports — warn + return 0, не трогаем ни одной
#   строки (удаление SSH-allow на хосте, куда вы подключены по SSH => локаут).
#
# Реализация безопасна под set -euo pipefail:
#   * LC_ALL=C — англоязычный 'Status: active'/нумерация вне зависимости от локали;
#   * 'ufw status numbered' захватываем В ПЕРЕМЕННУЮ (НЕ пайп-в-grep → нет SIGPIPE);
#   * номера строк, содержащих "<port>/<proto>", собираем и удаляем в порядке
#     УБЫВАНИЯ (иначе после первого delete нумерация сдвигается и мы снесём не то);
#   * каждый 'ufw --force delete' закрыт '|| true' (fail-soft);
#   * на НЕактивном ufw 'status numbered' пуст → цикл не выполнится, no-op.
ufw_clear_port() {
  local port="$1" proto="$2"

  # SSH-порты исключаем безусловно — анти-локаут.
  local p
  for p in $(detect_ssh_ports); do
    if [[ "$port" == "$p" ]]; then
      warn "Порт ${port}/${proto} совпадает с SSH-портом — НЕ чищу правила (анти-локаут)."
      return 0
    fi
  done

  local status
  status="$(LC_ALL=C ufw status numbered 2>/dev/null)" || return 0

  # Номера правил, чья строка содержит "<port>/<proto>", в порядке убывания.
  local -a nums=()
  mapfile -t nums < <(
    printf '%s\n' "$status" \
      | awk -v needle="${port}/${proto}" 'index($0, needle) {
          if (match($0, /\[[ ]*[0-9]+\]/)) {
            n = substr($0, RSTART, RLENGTH); gsub(/[^0-9]/, "", n); print n
          }
        }' \
      | sort -rn
  )

  local n
  for n in "${nums[@]}"; do
    ufw --force delete "$n" || true
  done
}

# --- Анти-локаут оркестрация (единая для service-скриптов) -------------------
# Раньше этот блок (гейт UFW_ACTIVE + first-run allow SSH + enable + re-run add)
# был СКОПИРОВАН в vps/relay/wireguard/mtproxy и расходился. Теперь — здесь.
# bastion НЕ использует эту функцию: он ЗАПИРАЕТ SSH (удаляет широкие правила),
# а не открывает сервис-порт — у него своя логика.
#
# ВЫЗОВ:  ufw_orchestrate <имя_функции_добавляющей_сервис-правила> || exit 1
#   Вызывающий определяет функцию, которая ИДЕМПОТЕНТНО добавляет ЕГО сервис-
#   правила через ufw_safe, например:
#       add_service_rules() { ufw_safe limit "${LOCAL_PORT}/tcp"; }
#   и передаёт её ИМЯ. Сама функция SSH-правила/enable НЕ трогает.
#
# ПОВЕДЕНИЕ:
#   * ufw уже активен (ПОВТОРНЫЙ запуск) => SSH-правила НЕ трогаем и enable НЕ
#     делаем (иначе откатили бы сужение бастиона / переоткрыли бы SSH); только
#     идемпотентно добавляем сервис-правила. UFW_FINAL_STATE=active, return 0.
#   * ufw неактивен (ПЕРВЫЙ запуск) => разрешаем ВСЕ найденные SSH-порты и
#     СЧИТАЕМ успешные. Если успешных 0 — err + return 1 (вызывающий ОБЯЗАН
#     прекратить и НЕ включать фаервол: default-deny без SSH = локаут). Иначе
#     добавляем сервис-правила и 'ufw --force enable'. enable прошёл =>
#     UFW_FINAL_STATE=active; не прошёл (OpenVZ без nf_tables) => warn +
#     UFW_FINAL_STATE=unknown (фаервол МОЖЕТ быть не активен — честно в баннер).
#
# ГЛОБАЛ: UFW_FINAL_STATE (active|unknown) — для итогового баннера вызывающего.
# ВОЗВРАТ: 0 — ок; 1 — первый запуск, но ни одно SSH-правило не применилось.
ufw_orchestrate() {
  local add_service_rules_fn="$1"
  UFW_FINAL_STATE="unknown"

  if ufw_is_active; then
    # ufw_is_active fail-CLOSED: возвращает 0 и при НЕдоступном статусе (баннер
    # бы соврал "active"). Поэтому здесь НЕ ставим active на любой 0 — захватываем
    # реальный статус и ставим active ТОЛЬКО при явном 'Status: active', иначе
    # unknown (честный баннер).
    local s
    if s="$(LC_ALL=C ufw status 2>/dev/null)" && [[ "$s" == *"Status: active"* ]]; then
      UFW_FINAL_STATE="active"
    else
      UFW_FINAL_STATE="unknown"
    fi
    log "ufw уже активен (повторный запуск): SSH-правила не трогаю, фаервол не пере-включаю."
    "${add_service_rules_fn}"
    return 0
  fi

  # ---- Первый запуск (ufw неактивен) ----
  local -a ssh_ports=()
  mapfile -t ssh_ports < <(detect_ssh_ports)
  log "Первый запуск ufw. Разрешаю SSH-порты: ${ssh_ports[*]:-<пусто>}"

  local p ssh_ok=0
  local -a ssh_failed=()
  for p in "${ssh_ports[@]}"; do
    # НЕ ufw_safe: нужен код возврата, чтобы посчитать успешные SSH-allow.
    if ufw allow "${p}/tcp"; then
      ssh_ok=1
    else
      warn "ufw allow ${p}/tcp не прошёл (транзиентно?)"
      ssh_failed+=("${p}")
    fi
  done

  if (( ssh_ok == 0 )); then
    err "НИ ОДНО SSH-правило не применилось — НЕ включаю ufw (default-deny без SSH = ЛОКАУТ)."
    err "Проверьте ufw/nf_tables (на OpenVZ ufw может не работать) и запустите скрипт повторно."
    return 1
  fi

  # Частичный отказ: какие-то SSH-порты прошли, какие-то нет. Гейт ssh_ok==0
  # это не ловит (хотя бы один успех есть), но если вы подключены именно по
  # ПРОВАЛИВШЕМУСЯ порту — после enable вас отрежет. Громко предупреждаем.
  if (( ${#ssh_failed[@]} > 0 )); then
    warn "SSH-allow для портов ${ssh_failed[*]} НЕ прошёл."
    warn "Если вы подключены по одному из них — НЕ отключайтесь, исправьте и перезапустите скрипт."
  fi

  # Сервис-порт(ы) — специфика вызывающего.
  "${add_service_rules_fn}"

  if ufw --force enable; then
    UFW_FINAL_STATE="active"
    log "ufw включён (default-deny incoming; SSH и сервис-порт разрешены)."
  else
    UFW_FINAL_STATE="unknown"
    warn "ufw --force enable вернул ошибку (OpenVZ/без nf_tables?) — фаервол МОЖЕТ быть НЕ активен."
    warn "Проверьте вручную: ufw status"
  fi
  return 0
}
