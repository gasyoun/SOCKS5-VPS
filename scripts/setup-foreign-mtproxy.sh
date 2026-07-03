#!/usr/bin/env bash
###############################################################################
# setup-foreign-mtproxy.sh
#
# НАЗНАЧЕНИЕ:
#   Запускается на ЗАРУБЕЖНОМ VPS (Ubuntu 24.04 / Debian 12-13) ОТ ROOT.
#   Поднимает ЛИЧНЫЙ MTProto-прокси для Telegram на базе mtg v2
#   (github.com/9seconds/mtg) с режимом Fake TLS (домен-маскировка):
#
#     [телефон/Telegram Desktop в РФ] --(маскируется под HTTPS)--> [ЭТОТ VPS] --> Telegram
#
#   Преимущества перед публичными MTProto-прокси:
#     * не попадает в публичные списки — РКН не косит его подсетями;
#     * скорость только ваша (никто посторонний не подключён);
#     * Fake TLS: трафик выглядит как обычный HTTPS-handshake к реальному
#       крупному домену (SNI), что резко затрудняет блокировку по DPI.
#
# БЕЗОПАСНОСТЬ / НАДЁЖНОСТЬ:
#   * Секрет Fake TLS генерируется ОДИН РАЗ и сохраняется персистентно
#     (/etc/mtg/secret). При повторном запуске НЕ перегенерируется — иначе
#     ранее розданная пользователю ссылка перестанет работать.
#   * Бинарь mtg качается с ПОСЛЕДНЕГО релиза GitHub (api.github.com), URL/версия
#     НЕ выдуманы. SHA256 СВЕРЯЕТСЯ и проверка ЖЁСТКАЯ (fail-CLOSED): если
#     checksums-файл недоступен/повреждён/нет строки нашего ассета/сумма не сошлась —
#     установка ПРЕРЫВАЕТСЯ (exit 1), а НЕ продолжается с предупреждением.
#     ВАЖНО про доверие: release-checksums лежат в ТОМ ЖЕ релизе, что и бинарь, и
#     подписи у них нет — они дают только ТРАНСПОРТНУЮ ЦЕЛОСТНОСТЬ (защита от битой
#     докачки / MITM в обход TLS), но НЕ АУТЕНТИЧНОСТЬ источника (тот, кто подменил
#     релиз, подменит и checksums). Для настоящего out-of-band пиннинга задайте
#     EXPECTED_MTG_SHA256 — тогда сверяется ИМЕННО эта сумма (приоритетнее
#     release-checksums), полученная вами по доверенному каналу.
#   * Выбирается БАЗОВЫЙ ассет linux-<arch>.tar.gz, а НЕ микроархитектурные
#     варианты (-v3 для amd64 требует AVX2, -v9.0 для arm64), которые падают
#     с SIGILL на старых/облачных CPU.
#   * Служба работает под отдельным системным пользователем (nologin),
#     БЕЗ root; право слушать 443 даётся точечно через CAP_NET_BIND_SERVICE.
#   * systemd-хардненинг: NoNewPrivileges, ProtectSystem=strict, ProtectHome,
#     PrivateTmp и пр.
#   * ufw сначала разрешает OpenSSH и РЕАЛЬНЫЙ текущий SSH-порт (в т.ч. при
#     socket-активации ssh.socket на Ubuntu 22.10+/24.04) и ТОЛЬКО ПОТОМ
#     включается — чтобы не отрезать себе доступ.
#
# ИДЕМПОТЕНТНОСТЬ:
#   Повторный запуск не падает и не ломает ранее выданную ссылку:
#   секрет сохраняется, бинарь mtg переустанавливается аккуратно (atomic mv),
#   пользователь создаётся при отсутствии, конфиг перезаписывается,
#   правила ufw добавляются без дублей.
###############################################################################

set -euo pipefail
umask 077   # все создаваемые файлы — только для владельца (root)

# --- Подключаем общую библиотеку из каталога этого скрипта -------------------
# Общие функции (log/warn/err, валидаторы, detect_ext_iface, detect_ssh_ports,
# ufw_is_active, ufw_safe, ufw_orchestrate) живут в _lib.sh — единый источник
# правды, не копии.
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

# Порт, на котором MTProto-прокси принимает входящие подключения.
# По умолчанию 443 — это порт HTTPS, поэтому Fake TLS максимально сливается
# с обычным веб-трафиком и хуже всего блокируется по DPI/портам.
# ВАЖНО: порт 443 должен быть СВОБОДЕН на этом VPS (не должно быть nginx/
#        apache/иного веб-сервера, слушающего 443). Если 443 занят —
#        задайте другой, например MTPROXY_PORT=8443.
MTPROXY_PORT="${MTPROXY_PORT:-443}"

# Домен, под который маскируется TLS-рукопожатие (SNI в Fake TLS).
# Выбираем КРУПНЫЙ, реально существующий домен, который РКН не станет блокировать
# целиком (слишком много легитимного трафика), и который поддерживает TLS 1.3.
# www.cloudflare.com подходит: огромная инфраструктура, повсеместный TLS 1.3,
# блокировать его целиком практически невозможно.
# ТРЕБОВАНИЯ к домену:
#   * должен РЕАЛЬНО существовать и отвечать по HTTPS;
#   * должен поддерживать TLS 1.3 (mtg использует его в handshake);
#   * желательно «нейтральный» и неблокируемый в РФ.
# Альтернативы: www.microsoft.com, www.bing.com, dl.google.com.
FAKE_TLS_DOMAIN="${FAKE_TLS_DOMAIN:-www.cloudflare.com}"

# Системный пользователь, под которым работает служба mtg (nologin-аккаунт).
MTG_USER="${MTG_USER:-mtg}"

# Каталог и файлы конфигурации/состояния.
MTG_DIR="/etc/mtg"            # каталог конфигурации и персистентного секрета
MTG_CONFIG="${MTG_DIR}/config.toml"   # конфиг mtg (TOML)
MTG_SECRET_FILE="${MTG_DIR}/secret"   # персистентный Fake-TLS секрет (хранится, не перегенерируется)
MTG_DOMAIN_FILE="${MTG_DIR}/domain"   # домен, под который БЫЛ сгенерирован секрет (для контроля рассинхрона)
MTG_BIN="/usr/local/bin/mtg"          # путь к бинарю mtg

# Интервал перезапуска службы при сбое (systemd RestartSec).
RESTART_SEC="${RESTART_SEC:-5}"

# Опциональный OUT-OF-BAND пин SHA256 бинаря mtg (64 hex-символа, без имени файла).
# Если ЗАДАН — сверяется ИМЕННО эта сумма, и она ПРИОРИТЕТНЕЕ release-checksums.
# Это единственный способ проверить АУТЕНТИЧНОСТЬ (release-checksums лежат в том же
# релизе и дают лишь транспортную целостность, см. шапку). Получите сумму по
# доверенному каналу и передайте, например:
#   EXPECTED_MTG_SHA256=abc...123 bash setup-foreign-mtproxy.sh
# Пусто (по умолчанию) — пин не используется, проверка идёт по release-checksums.
EXPECTED_MTG_SHA256="${EXPECTED_MTG_SHA256:-}"

###############################################################################
# СЛУЖЕБНЫЕ ПРОВЕРКИ
###############################################################################

if [[ "${EUID}" -ne 0 ]]; then
  echo "ОШИБКА: запустите скрипт от root (sudo bash $0)." >&2
  exit 1
fi

# Валидаторы (valid_port, valid_ipv4_or_cidr, no_whitespace) берутся из _lib.sh.

# Валидация порта (1..65535), чтобы не сгенерировать битый конфиг/ufw-правило.
if ! valid_port "${MTPROXY_PORT}"; then
  echo "ОШИБКА: некорректный MTPROXY_PORT='${MTPROXY_PORT}' (нужно 1..65535)." >&2
  exit 1
fi

# Валидация домена: непустой, синтаксис hostname (буквы/цифры/дефисы/точки,
# хотя бы одна точка), длина <= 253. Внутрь Fake-TLS секрета домен кодируется,
# поэтому мусор тут = неработающая маскировка.
if [[ -z "${FAKE_TLS_DOMAIN}" ]]; then
  echo "ОШИБКА: FAKE_TLS_DOMAIN пуст." >&2
  exit 1
fi
if (( ${#FAKE_TLS_DOMAIN} > 253 )) \
   || ! [[ "${FAKE_TLS_DOMAIN}" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$ ]]; then
  echo "ОШИБКА: некорректный FAKE_TLS_DOMAIN='${FAKE_TLS_DOMAIN}' (ожидается домен вида www.example.com)." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

###############################################################################
# 1. УСТАНОВКА ЗАВИСИМОСТЕЙ (curl, ufw, ca-certificates, iproute2; jq по возможности)
###############################################################################
echo "==> [1/8] Установка базовых пакетов (curl, ufw, ca-certificates, iproute2, tar, coreutils)..."

apt-get update -y

# coreutils даёт sha256sum (проверка контрольной суммы бинаря).
# jq не обязателен — скрипт умеет парсить GitHub API и без него (grep/sed),
# но если поставится, используем его как более надёжный путь.
PKGS=(curl ca-certificates ufw iproute2 tar coreutils)
apt-get install -y "${PKGS[@]}"
# jq — best-effort: не валим установку, если его нет в репах/не ставится.
apt-get install -y jq >/dev/null 2>&1 || true

###############################################################################
# 2. ОПРЕДЕЛЕНИЕ АРХИТЕКТУРЫ
###############################################################################
echo "==> [2/8] Определение архитектуры процессора..."

# mtg публикует ассеты вида mtg-<ver>-linux-amd64.tar.gz и ...-linux-arm64.tar.gz.
# Внимание: есть также микроархитектурные варианты -linux-amd64-v3.tar.gz (AVX2)
# и -linux-arm64-v9.0.tar.gz — мы их НЕ берём (могут падать с SIGILL на старых/
# облачных CPU). Берём базовый файл (см. шаг 3, точное сопоставление по имени).
RAW_ARCH="$(uname -m)"
case "${RAW_ARCH}" in
  x86_64|amd64)        MTG_ARCH="amd64" ;;
  aarch64|arm64)       MTG_ARCH="arm64" ;;
  *)
    echo "ОШИБКА: неподдерживаемая架 архитектура '${RAW_ARCH}'." >&2
    echo "        mtg v2 собирается под linux-amd64 и linux-arm64." >&2
    exit 1
    ;;
esac
echo "    Архитектура: ${RAW_ARCH} -> linux-${MTG_ARCH}"

###############################################################################
# 3. УСТАНОВКА / ОБНОВЛЕНИЕ mtg (ПОСЛЕДНИЙ РЕЛИЗ С GitHub, БЕЗ ВЫДУМАННЫХ URL)
###############################################################################
echo "==> [3/8] Установка/обновление mtg v2..."

# Детект уже установленного рабочего бинаря (как у sibling ru-relay detect_binary):
# рабочий mtg = файл существует, исполняем и отвечает на '--version'. Если он уже
# стоит и обновление не запрошено (MTG_FORCE_UPDATE!=1) — НЕ дёргаем GitHub API.
# Зачем: шаг 3 безусловно тянул releases/latest и падал (exit 1) при пустом ответе,
# поэтому ЛЮБОЙ повторный запуск ломался при rate-limit GitHub (403 частый с одного
# VPS-IP) или блоке DNS — хотя переустанавливать рабочий бинарь не требовалось.
# Принудительное обновление: MTG_FORCE_UPDATE=1 bash setup-foreign-mtproxy.sh
MTG_FORCE_UPDATE="${MTG_FORCE_UPDATE:-0}"

mtg_binary_ok() { # рабочий ли уже установленный бинарь mtg?
  [[ -x "${MTG_BIN}" ]] && "${MTG_BIN}" --version >/dev/null 2>&1
}

if mtg_binary_ok && [[ "${MTG_FORCE_UPDATE}" != "1" ]]; then
  # Short-circuit: бинарь уже рабочий — пропускаем загрузку с GitHub целиком,
  # чтобы re-run не падал при rate-limit/блоке DNS. Для обновления — MTG_FORCE_UPDATE=1.
  echo "    mtg уже установлен и работает: $("${MTG_BIN}" --version 2>/dev/null | head -n1)"
  echo "    Пропускаю загрузку с GitHub (re-run безопасен; для обновления — MTG_FORCE_UPDATE=1)."
else

echo "    Получение последнего релиза mtg v2 с GitHub API..."

GH_API="https://api.github.com/repos/9seconds/mtg/releases/latest"

# Тянем JSON последнего релиза. Никаких заранее «зашитых» версий/URL —
# берём только то, что реально отдаёт GitHub API.
RELEASE_JSON="$(curl -fsSL --retry 3 --retry-delay 2 --max-time 30 \
  -H 'Accept: application/vnd.github+json' \
  -H 'User-Agent: setup-foreign-mtproxy' \
  "${GH_API}" 2>/dev/null || true)"

if [[ -z "${RELEASE_JSON}" ]]; then
  echo "ОШИБКА: не удалось получить данные с GitHub API (${GH_API})." >&2
  echo "        Проверьте интернет/DNS на VPS (возможен rate-limit api.github.com)." >&2
  echo "        Fallback-URL НЕ выдумываем — иначе можно скачать неверный/устаревший бинарь." >&2
  exit 1
fi

# Версия релиза (tag_name, например v2.2.8). Нужна для имени checksums-файла.
ASSET_VER=""
if command -v jq >/dev/null 2>&1; then
  ASSET_VER="$(printf '%s' "${RELEASE_JSON}" | jq -r '.tag_name // empty' 2>/dev/null || true)"
fi
if [[ -z "${ASSET_VER}" ]]; then
  ASSET_VER="$(printf '%s' "${RELEASE_JSON}" \
    | grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"[^"]+"' \
    | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/' \
    | head -n1 || true)"
fi
if [[ -z "${ASSET_VER}" ]]; then
  echo "ОШИБКА: не удалось определить версию релиза (tag_name) из ответа GitHub API." >&2
  exit 1
fi

# Версия БЕЗ ведущего 'v' — именно в таком виде она встречается в имени ассета
# (релиз v2.2.8 -> файл mtg-2.2.8-linux-amd64.tar.gz).
VER_NUM="${ASSET_VER#v}"

# ТОЧНОЕ имя нужного ассета. Сопоставляем по ПОЛНОМУ имени файла, а не подстроке,
# чтобы НЕ зацепить микроархитектурные варианты (-v3 / -v9.0):
EXPECT_ASSET="mtg-${VER_NUM}-linux-${MTG_ARCH}.tar.gz"
EXPECT_SUMS="mtg-${VER_NUM}-checksums.txt"

# Выдёргиваем URL ассета СТРОГО по совпадению имени файла в browser_download_url.
ASSET_URL=""
SUMS_URL=""

extract_url_by_basename() { # extract_url_by_basename <basename>
  # Печатает первый browser_download_url, чей последний сегмент пути == <basename>.
  local want="${1}"
  if command -v jq >/dev/null 2>&1; then
    printf '%s' "${RELEASE_JSON}" \
      | jq -r --arg n "${want}" \
          '.assets[]? | select((.name // "") == $n) | .browser_download_url' \
          2>/dev/null | head -n1
    return 0
  fi
  # Fallback без jq: все browser_download_url, оставляем тот, чей basename совпал.
  printf '%s' "${RELEASE_JSON}" \
    | grep -oE '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]+"' \
    | sed -E 's/.*"(https[^"]+)".*/\1/' \
    | while IFS= read -r u; do
        [[ "${u##*/}" == "${want}" ]] && { printf '%s\n' "${u}"; break; }
      done
}

ASSET_URL="$(extract_url_by_basename "${EXPECT_ASSET}" || true)"
SUMS_URL="$(extract_url_by_basename "${EXPECT_SUMS}" || true)"

if [[ -z "${ASSET_URL}" ]]; then
  echo "ОШИБКА: в релизе ${ASSET_VER} не найден ассет '${EXPECT_ASSET}'." >&2
  echo "        Возможно, изменилась схема именования ассетов. Проверьте:" >&2
  echo "        https://github.com/9seconds/mtg/releases/latest" >&2
  exit 1
fi

echo "    Релиз mtg: ${ASSET_VER}"
echo "    Ассет    : ${EXPECT_ASSET}"
echo "    URL      : ${ASSET_URL}"

# Скачиваем во временный каталог, проверяем checksum, распаковываем, ставим бинарь атомарно.
TMP_DL="$(mktemp -d)"
# shellcheck disable=SC2064
trap "rm -rf '${TMP_DL}'" EXIT

echo "    Скачивание ассета..."
curl -fsSL --retry 3 --retry-delay 2 --max-time 120 "${ASSET_URL}" -o "${TMP_DL}/${EXPECT_ASSET}"

# --- Проверка SHA256: жёсткая (fail-CLOSED) ---
# Приоритет (1) out-of-band пин EXPECTED_MTG_SHA256 (аутентичность), иначе
# (2) официальный release-checksums (только транспортная целостность, см. шапку).
# В ОБОИХ случаях любой сбой/несовпадение = exit 1 (никакого warn-and-continue).
if [[ -n "${EXPECTED_MTG_SHA256}" ]]; then
  # (1) OUT-OF-BAND ПИН: сверяем именно заданную сумму, release-checksums игнорируем.
  echo "    Проверка SHA256 по out-of-band пину EXPECTED_MTG_SHA256..."
  # Нормализуем к нижнему регистру и валидируем формат (ровно 64 hex-символа).
  PIN_LC="$(printf '%s' "${EXPECTED_MTG_SHA256}" | tr 'A-Z' 'a-z' | tr -d '[:space:]')"
  if ! [[ "${PIN_LC}" =~ ^[0-9a-f]{64}$ ]]; then
    echo "ОШИБКА: EXPECTED_MTG_SHA256 имеет неверный формат (нужно 64 hex-символа)." >&2
    exit 1
  fi
  ACTUAL_LC="$(sha256sum "${TMP_DL}/${EXPECT_ASSET}" | awk '{print $1}' | tr 'A-Z' 'a-z')"
  if [[ "${ACTUAL_LC}" == "${PIN_LC}" ]]; then
    echo "    Контрольная сумма SHA256 совпала с out-of-band пином (аутентичность подтверждена)."
  else
    echo "ОШИБКА: SHA256 скачанного '${EXPECT_ASSET}' НЕ совпал с EXPECTED_MTG_SHA256." >&2
    echo "        ожидалось: ${PIN_LC}" >&2
    echo "        получено : ${ACTUAL_LC}" >&2
    echo "        Файл повреждён или подменён — установка прервана." >&2
    exit 1
  fi
else
  # (2) RELEASE-CHECKSUMS: только транспортная целостность. Самоссылочно (лежит в
  # том же релизе) => НЕ доказывает аутентичность; для неё задайте EXPECTED_MTG_SHA256.
  # Тем не менее проверка ЖЁСТКАЯ — отсутствие/сбой/несовпадение роняют установку.
  if [[ -z "${SUMS_URL}" ]]; then
    echo "ОШИБКА: в релизе ${ASSET_VER} нет checksums-файла '${EXPECT_SUMS}'." >&2
    echo "        Проверить целостность бинаря невозможно — установка прервана (fail-closed)." >&2
    echo "        Обход: задайте EXPECTED_MTG_SHA256 с суммой из доверенного источника." >&2
    exit 1
  fi
  echo "    Скачивание и проверка контрольной суммы (${EXPECT_SUMS})..."
  if ! curl -fsSL --retry 3 --retry-delay 2 --max-time 30 "${SUMS_URL}" -o "${TMP_DL}/sums.txt"; then
    echo "ОШИБКА: не удалось скачать ${EXPECT_SUMS} — проверка целостности невозможна." >&2
    echo "        Установка прервана (fail-closed). Обход: задайте EXPECTED_MTG_SHA256." >&2
    exit 1
  fi
  # Формат файла — GNU coreutils: "<sha256>  <имя_файла>".
  # Берём ТОЛЬКО строку нашего ассета и сверяем в каталоге загрузки.
  if ! grep -E "[[:space:]]${EXPECT_ASSET}\$" "${TMP_DL}/sums.txt" > "${TMP_DL}/sums.one" \
     || [[ ! -s "${TMP_DL}/sums.one" ]]; then
    echo "ОШИБКА: в ${EXPECT_SUMS} нет строки для '${EXPECT_ASSET}'." >&2
    echo "        Проверить целостность невозможно — установка прервана (fail-closed)." >&2
    exit 1
  fi
  if ( cd "${TMP_DL}" && sha256sum -c --strict "sums.one" >/dev/null 2>&1 ); then
    echo "    Контрольная сумма SHA256 совпала с release-checksums (только целостность, не аутентичность)."
  else
    echo "ОШИБКА: SHA256 скачанного '${EXPECT_ASSET}' НЕ совпал с checksums релиза." >&2
    echo "        Файл повреждён или подменён — установка прервана (fail-closed)." >&2
    exit 1
  fi
fi

echo "    Распаковка..."
tar -xzf "${TMP_DL}/${EXPECT_ASSET}" -C "${TMP_DL}"

# Бинарь лежит внутри подкаталога mtg-<ver>-linux-<arch>/mtg — найдём его.
FOUND_BIN="$(find "${TMP_DL}" -type f -name mtg -perm -u+x 2>/dev/null | head -n1 || true)"
if [[ -z "${FOUND_BIN}" ]]; then
  # Подстраховка: ищем любой файл с именем mtg (вдруг бит исполнения не выставлен).
  FOUND_BIN="$(find "${TMP_DL}" -type f -name mtg 2>/dev/null | head -n1 || true)"
fi
if [[ -z "${FOUND_BIN}" ]]; then
  echo "ОШИБКА: после распаковки не найден бинарь 'mtg'." >&2
  exit 1
fi

# Атомарная установка: копируем во временный файл рядом и mv поверх —
# чтобы при обновлении не словить 'text file busy' и не оставить полубинарь.
install -d -m 0755 "$(dirname "${MTG_BIN}")"
cp -f "${FOUND_BIN}" "${MTG_BIN}.new"
chmod 0755 "${MTG_BIN}.new"
mv -f "${MTG_BIN}.new" "${MTG_BIN}"

# Проверяем работоспособность бинаря (kong: поддерживается --version / -v).
if ! "${MTG_BIN}" --version >/dev/null 2>&1; then
  echo "ОШИБКА: '${MTG_BIN} --version' не отработал — бинарь нерабочий или несовместим с CPU (SIGILL?)." >&2
  exit 1
fi
echo "    Установлен mtg: $("${MTG_BIN}" --version 2>/dev/null | head -n1)"

fi  # конец ветки установки/обновления mtg (short-circuit при уже рабочем бинаре)

###############################################################################
# 4. СИСТЕМНЫЙ ПОЛЬЗОВАТЕЛЬ СЛУЖБЫ
###############################################################################
echo "==> [4/8] Системный пользователь '${MTG_USER}' (nologin)..."

if id -u "${MTG_USER}" >/dev/null 2>&1; then
  echo "    Пользователь '${MTG_USER}' уже существует — пропускаю создание."
else
  # Системный аккаунт без домашнего каталога и без возможности логина.
  useradd --system --no-create-home --shell /usr/sbin/nologin "${MTG_USER}"
  echo "    Пользователь '${MTG_USER}' создан (системный, nologin)."
fi

###############################################################################
# 5. ПЕРСИСТЕНТНЫЙ FAKE-TLS СЕКРЕТ (ГЕНЕРИРУЕМ ОДИН РАЗ!)
###############################################################################
echo "==> [5/8] Fake-TLS секрет (генерируется один раз, далее переиспользуется)..."

install -d -m 0750 "${MTG_DIR}"

# РЕАЛЬНО действующий домен (SNI, закодированный в живом секрете). По умолчанию —
# запрошенный FAKE_TLS_DOMAIN, но при переиспользовании старого секрета он
# ПЕРЕОПРЕДЕЛЯЕТСЯ сохранённым OLD_DOMAIN. Именно EFFECTIVE_DOMAIN, а не
# FAKE_TLS_DOMAIN, должен попадать в документацию/комментарии (#13): иначе
# на re-run со сменой FAKE_TLS_DOMAIN комментарий конфига противоречил бы
# фактическому SNI секрета (секрет-то остаётся старый).
EFFECTIVE_DOMAIN="${FAKE_TLS_DOMAIN}"

if [[ -s "${MTG_SECRET_FILE}" ]]; then
  # Секрет уже есть — НЕ перегенерируем, иначе сломается ранее выданная ссылка.
  MTG_SECRET="$(tr -d '[:space:]' < "${MTG_SECRET_FILE}")"
  if [[ -z "${MTG_SECRET}" ]]; then
    echo "ОШИБКА: ${MTG_SECRET_FILE} существует, но пуст после очистки пробелов." >&2
    echo "        Удалите файл вручную, если хотите перегенерировать секрет (это сломает старую ссылку)." >&2
    exit 1
  fi
  echo "    Найден существующий секрет — переиспользую (ссылка не сломается)."

  # Контроль рассинхрона: если FAKE_TLS_DOMAIN изменился относительно того,
  # под который был сгенерирован секрет, предупреждаем (домен закодирован в секрете,
  # переменная окружения тут уже НЕ влияет — действует домен из старого секрета).
  if [[ -s "${MTG_DOMAIN_FILE}" ]]; then
    OLD_DOMAIN="$(tr -d '[:space:]' < "${MTG_DOMAIN_FILE}")"
    if [[ -n "${OLD_DOMAIN}" ]]; then
      # Документировать/комментировать нужно ФАКТИЧЕСКИЙ SNI секрета, а не запрос (#13).
      EFFECTIVE_DOMAIN="${OLD_DOMAIN}"
      if [[ "${OLD_DOMAIN}" != "${FAKE_TLS_DOMAIN}" ]]; then
        echo "    ВНИМАНИЕ: запрошен домен '${FAKE_TLS_DOMAIN}', но действующий секрет сгенерирован под '${OLD_DOMAIN}'." >&2
        echo "             Секрет НЕ меняется. Чтобы применить новый домен, удалите ${MTG_SECRET_FILE}" >&2
        echo "             и ${MTG_DOMAIN_FILE}, перезапустите скрипт и РАЗДАЙТЕ НОВУЮ ссылку." >&2
      fi
    fi
  fi
else
  # Генерируем новый Fake-TLS секрет. В hex-формате он начинается с 'ee'
  # (признак Fake TLS) и содержит закодированный домен маскировки.
  MTG_SECRET="$("${MTG_BIN}" generate-secret --hex "${FAKE_TLS_DOMAIN}" 2>/dev/null | tr -d '[:space:]')"
  if [[ -z "${MTG_SECRET}" ]]; then
    echo "ОШИБКА: не удалось сгенерировать секрет (mtg generate-secret --hex ${FAKE_TLS_DOMAIN})." >&2
    exit 1
  fi
  printf '%s\n' "${MTG_SECRET}" > "${MTG_SECRET_FILE}"
  chmod 0600 "${MTG_SECRET_FILE}"
  printf '%s\n' "${FAKE_TLS_DOMAIN}" > "${MTG_DOMAIN_FILE}"
  chmod 0600 "${MTG_DOMAIN_FILE}"
  EFFECTIVE_DOMAIN="${FAKE_TLS_DOMAIN}"   # новый секрет — действующий домен = запрошенный
  echo "    Сгенерирован новый секрет и сохранён в ${MTG_SECRET_FILE}."
fi

# Контроль формата: Fake-TLS секрет в hex должен начинаться с 'ee'.
if [[ "${MTG_SECRET}" != ee* ]]; then
  echo "    ВНИМАНИЕ: секрет не начинается с 'ee' — возможно, это не Fake-TLS секрет." >&2
fi

# Права на каталог/секрет: владелец службы должен читать секрет.
# Каталог 0750, файлы 0600, владелец mtg.
chown -R "${MTG_USER}:${MTG_USER}" "${MTG_DIR}"
chmod 0750 "${MTG_DIR}"
chmod 0600 "${MTG_SECRET_FILE}"
[[ -f "${MTG_DOMAIN_FILE}" ]] && chmod 0600 "${MTG_DOMAIN_FILE}"

###############################################################################
# 6. КОНФИГ mtg (TOML)
###############################################################################
echo "==> [6/8] Запись конфига ${MTG_CONFIG}..."

# Минимальный рабочий конфиг mtg v2: секрет + адрес прослушивания.
# bind-to 0.0.0.0:<порт> — слушаем на всех интерфейсах (IPv4).
cat > "${MTG_CONFIG}" <<EOF
# ${MTG_CONFIG} — сгенерировано setup-foreign-mtproxy.sh
# Личный MTProto-прокси (mtg v2) с Fake TLS под домен ${EFFECTIVE_DOMAIN}.
# (домен берётся из ДЕЙСТВУЮЩЕГО секрета — реальный SNI; не из запрошенного
#  FAKE_TLS_DOMAIN, который при re-run со сменой домена секрет НЕ меняет — #13).

# Секрет Fake TLS (hex, начинается с 'ee'). Хранится также в ${MTG_SECRET_FILE}.
secret = "${MTG_SECRET}"

# Адрес и порт прослушивания входящих подключений Telegram-клиентов.
bind-to = "0.0.0.0:${MTPROXY_PORT}"
EOF

chown "${MTG_USER}:${MTG_USER}" "${MTG_CONFIG}"
chmod 0600 "${MTG_CONFIG}"
echo "    Конфиг записан (${MTG_USER}:${MTG_USER}, 600)."

###############################################################################
# 7. SYSTEMD-ЮНИТ + ЗАПУСК (СЛУШАЕМ 443 БЕЗ ROOT ЧЕРЕЗ CAP_NET_BIND_SERVICE)
###############################################################################
echo "==> [7/8] systemd-юнит /etc/systemd/system/mtg.service, запуск службы..."

# CAP_NET_BIND_SERVICE нужен ТОЛЬКО для портов < 1024 (например 443).
# Для портов >= 1024 он безвреден (просто не используется), поэтому держим его
# всегда — так юнит корректен при любом MTPROXY_PORT.
# CapabilityBoundingSet СОДЕРЖИТ CAP_NET_BIND_SERVICE (не вырезает её),
# иначе Ambient-капабилити не сработала бы.
#
# По хардненингу:
#   * ProtectSystem=strict делает почти всю ФС read-only — mtg это устраивает,
#     состояние на диск он не пишет (всё в памяти).
#   * mtg только ЧИТАЕТ свой конфиг/секрет из ${MTG_DIR} (это и так read-only
#     под strict; ReadWritePaths НЕ задаём специально).
#   * ProtectHome=yes, PrivateTmp=yes, NoNewPrivileges=yes не мешают:
#     mtg не лезет в /home и не требует setuid.
cat > /etc/systemd/system/mtg.service <<EOF
[Unit]
Description=mtg v2 MTProto proxy (Fake TLS) for Telegram
Documentation=https://github.com/9seconds/mtg
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${MTG_USER}
ExecStart=${MTG_BIN} run ${MTG_CONFIG}
Restart=on-failure
RestartSec=${RESTART_SEC}

# Право биндить привилегированный порт (443) без root.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# --- Хардненинг ---
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectControlGroups=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
# mtg работает по сети поверх TCP (IPv4/IPv6). AF_UNIX/AF_NETLINK нужны Go-резолверу
# имён (systemd-resolved через AF_UNIX, getaddrinfo/RFC-3484 через AF_NETLINK) —
# без них на хостах с systemd-resolved (дефолт Ubuntu 24.04) mtg может молча не
# разрешать адреса Telegram, хотя сокет на порту слушается и is-active проходит.
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
# Каталог конфига нужен ТОЛЬКО на чтение. Под ProtectSystem=strict он и так
# read-only; перечисляем явно как документирующую страховку (не вредит).
ReadOnlyPaths=${MTG_DIR}

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 /etc/systemd/system/mtg.service

# Чтобы Wants=network-online.target реально работал, нужен включённый
# *-wait-online сервис. Включаем оба best-effort (какой есть в системе).
systemctl enable systemd-networkd-wait-online.service >/dev/null 2>&1 || true
systemctl enable NetworkManager-wait-online.service    >/dev/null 2>&1 || true

systemctl daemon-reload
systemctl enable mtg >/dev/null 2>&1 || true
systemctl restart mtg

# Проверим, что служба реально поднялась (а не упала сразу), с коротким ожиданием.
ok=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if systemctl is-active --quiet mtg; then ok=1; break; fi
  sleep 1
done
if (( ok == 0 )); then
  echo "ОШИБКА: сервис mtg не активен. Логи: journalctl -u mtg -n 50 --no-pager" >&2
  journalctl -u mtg -n 30 --no-pager >&2 || true
  exit 1
fi
echo "    Служба mtg активна и в автозагрузке (работает от пользователя ${MTG_USER})."

###############################################################################
# 8. ФАЕРВОЛ (ufw): СНАЧАЛА SSH, ПОТОМ ВКЛЮЧЕНИЕ, ЗАТЕМ ПОРТ ПРОКСИ
###############################################################################
echo "==> [8/8] Настройка ufw (SSH разрешаем ДО enable, потом порт прокси)..."

# Анти-локаут оркестрация — ЕДИНАЯ для всех service-скриптов — живёт в _lib.sh
# (ufw_orchestrate). Раньше здесь был СКОПИРОВАННЫЙ инлайн-блок (гейт ufw_is_active +
# first-run цикл allow SSH + 'ufw --force enable' + re-run-ветка добавления порта +
# счётчик успешных SSH-allow), который расходился между скриптами. Теперь мы лишь
# определяем ИДЕМПОТЕНТНОЕ добавление СВОИХ сервис-правил и передаём его в оркестратор.
#
# Что делает ufw_orchestrate (см. _lib.sh):
#   * ufw уже активен (ПОВТОРНЫЙ запуск) — SSH-правила НЕ трогает, enable НЕ делает
#     (чтобы не откатить возможное сужение SSH бастионом); только вызывает нашу
#     add_service_rules. UFW_FINAL_STATE=active.
#   * ufw неактивен (ПЕРВЫЙ запуск) — разрешает ВСЕ найденные SSH-порты (detect_ssh_ports)
#     и считает успешные. Если успешных 0 — return 1 (мы ОБЯЗАНЫ прекратить и НЕ включать
#     фаервол: default-deny без SSH = локаут). Иначе вызывает add_service_rules и
#     'ufw --force enable'. enable ок => UFW_FINAL_STATE=active; иначе (OpenVZ/без
#     nf_tables) => warn + UFW_FINAL_STATE=unknown (фаервол МОЖЕТ быть не активен).

# Сервис-правила ИМЕННО этого скрипта: открываем порт MTProto-прокси всему интернету —
# это намеренно: подключиться сможет только тот, у кого есть наш Fake-TLS секрет (ссылка).
# Функция идемпотентна (ufw allow дублей не создаёт) и НЕ трогает SSH-порты/enable.
add_service_rules() {
  # Сначала снимаем возможные прежние правила на этом порту (consistency, HIGH #2):
  # ufw_clear_port убирает дубли/устаревшие записи перед добавлением, чтобы при
  # re-run со сменой порта/протокола не копились висячие правила. Это REWRITE
  # (очистка + добавление), а не дублирование уже существующего allow.
  ufw_clear_port "${MTPROXY_PORT}" tcp
  ufw_safe allow "${MTPROXY_PORT}/tcp"
  echo "    Порт прокси ${MTPROXY_PORT}/tcp открыт."
}

# Единый вызов оркестратора. UFW_FINAL_STATE (active|unknown) выставляется внутри.
# return 1 = первый запуск, но НИ ОДНО SSH-правило не применилось — прекращаем
# (НЕ включаем фаервол, иначе отрежем себе SSH-доступ).
# Код возврата ловим в отдельную переменную ДО любой другой команды: под
# set -euo pipefail цепочка '... || exit 1' тоже работает, но явный __rc делает
# намерение очевидным и не зависит от того, что оркестратор — последняя команда (#7).
ufw_orchestrate add_service_rules; __rc=$?; (( __rc == 0 )) || exit 1

###############################################################################
# ИТОГ: ПУБЛИЧНЫЙ IP, ПОРТ, ДОМЕН И ГОТОВЫЕ ССЫЛКИ ДЛЯ TELEGRAM
###############################################################################

# Определим публичный IP. Сначала пробуем внешние сервисы (надёжно для NAT/cloud),
# затем как fallback — IP с интерфейса маршрута по умолчанию.
PUBLIC_IP=""
for url in https://api.ipify.org https://ifconfig.me https://icanhazip.com; do
  PUBLIC_IP="$(curl -fsS --max-time 5 "${url}" 2>/dev/null | tr -d '[:space:]' || true)"
  # Валидируем строго через valid_ipv4 из _lib.sh (проверяет октеты <=255 и
  # отсутствие CIDR-суффикса), а не слабым локальным regex '^[0-9]+(\.[0-9]+){3}$',
  # который пропускал '999.1.2.3' и т.п. (#8).
  valid_ipv4 "${PUBLIC_IP}" && break
  PUBLIC_IP=""
done
if [[ -z "${PUBLIC_IP}" ]]; then
  # '|| true' обязателен: detect_ext_iface может вернуть ненулевой код (нет
  # default-route и т.п.), и под set -euo pipefail голое присваивание оборвало бы
  # скрипт ДО дружелюбного fallback на '<IP_ЭТОГО_VPS>' (#9).
  EXT_IF="$(detect_ext_iface || true)"   # имя внешнего интерфейса (из _lib.sh, robust dev-keyword)
  if [[ -n "${EXT_IF}" ]]; then
    PUBLIC_IP="$(ip -o -4 addr show dev "${EXT_IF}" scope global 2>/dev/null \
      | awk '{print $4}' | cut -d/ -f1 | head -n1 || true)"
  fi
fi
PUBLIC_IP="${PUBLIC_IP:-<IP_ЭТОГО_VPS>}"

# Готовые ссылки. mtg умеет показать их сам командой 'mtg access <config>' —
# попробуем вытащить их оттуда. Если что-то пойдёт не так — соберём ссылки
# вручную из IP/порта/секрета (гарантированный fallback).
ACCESS_JSON="$("${MTG_BIN}" access "${MTG_CONFIG}" 2>/dev/null || true)"

TG_URL=""
TME_URL=""
if [[ -n "${ACCESS_JSON}" ]]; then
  if command -v jq >/dev/null 2>&1; then
    # Структура вывода mtg access — JSON; ищем любые поля *_url рекурсивно (best-effort).
    TG_URL="$(printf '%s' "${ACCESS_JSON}" | jq -r '..|.tg_url? // empty' 2>/dev/null | head -n1 || true)"
    TME_URL="$(printf '%s' "${ACCESS_JSON}" | jq -r '..|.tme_url? // empty' 2>/dev/null | head -n1 || true)"
  fi
  if [[ -z "${TG_URL}" ]]; then
    TG_URL="$(printf '%s' "${ACCESS_JSON}" | grep -oE 'tg://proxy\?[^"]+' | head -n1 || true)"
  fi
  if [[ -z "${TME_URL}" ]]; then
    TME_URL="$(printf '%s' "${ACCESS_JSON}" | grep -oE 'https://t\.me/proxy\?[^"]+' | head -n1 || true)"
  fi
fi

# Ручная сборка как гарантированный fallback.
if [[ -z "${TG_URL}" ]]; then
  TG_URL="tg://proxy?server=${PUBLIC_IP}&port=${MTPROXY_PORT}&secret=${MTG_SECRET}"
fi
if [[ -z "${TME_URL}" ]]; then
  TME_URL="https://t.me/proxy?server=${PUBLIC_IP}&port=${MTPROXY_PORT}&secret=${MTG_SECRET}"
fi

# Честная строка о состоянии периметра (#12): success-баннер НЕ должен
# подразумевать поднятый фаервол, если 'ufw --force enable' упал (типично на OpenVZ).
# ufw_orchestrate выставляет UFW_FINAL_STATE строго в active|unknown:
#   active  — ufw поднят (или уже был активен при re-run);
#   unknown — 'ufw --force enable' не отработал (фаервол МОЖЕТ быть не активен).
case "${UFW_FINAL_STATE}" in
  active)  UFW_BANNER="ufw активен (периметр поднят)." ;;
  *)       UFW_BANNER="ВНИМАНИЕ: фаервол МОГ не включиться ('ufw --force enable' упал — типично на OpenVZ/без nf_tables). Проверьте вручную ('ufw status') и при необходимости настройте фильтрацию средствами провайдера/панели VPS." ;;
esac

echo
echo "============================================================"
echo " ЛИЧНЫЙ MTProto-ПРОКСИ (mtg v2, Fake TLS) НАСТРОЕН И ЗАПУЩЕН"
echo "============================================================"
echo " Публичный IP   : ${PUBLIC_IP}"
echo " Порт           : ${MTPROXY_PORT}"
echo " Fake TLS домен : ${EFFECTIVE_DOMAIN}"
echo " Фаервол (ufw)  : ${UFW_BANNER}"

# #15: секрет и t.me/tg-ссылки — чувствительные данные. При неинтерактивном
# выводе (ssh+tee, CI, перенаправление в файл/пайп) НЕ печатаем их в stdout,
# чтобы не утекли в логи. Полный вывод — ТОЛЬКО на реальный терминал ([[ -t 1 ]]).
if [[ -t 1 ]]; then
  echo " Секрет         : ${MTG_SECRET}"
  echo "                  (сохранён в ${MTG_SECRET_FILE}; при повторном запуске НЕ меняется)"
  echo "------------------------------------------------------------"
  echo " ССЫЛКИ ДЛЯ ПОДКЛЮЧЕНИЯ TELEGRAM:"
  echo
  echo "   ${TG_URL}"
  echo
  echo "   ${TME_URL}"
  echo "------------------------------------------------------------"
  echo " КАК ПОДКЛЮЧИТЬСЯ:"
  echo "   1) Откройте любую из ссылок выше НА ТЕЛЕФОНЕ (в браузере/заметке)"
  echo "      или в Telegram Desktop — Telegram сам предложит добавить прокси."
  echo "   2) Нажмите «Подключиться» (Connect / Enable proxy) в появившемся окне."
  echo "   3) Готово: в шапке появится значок прокси, трафик пойдёт через VPS."
else
  # Неинтерактив: НЕ светим секрет/ссылки в лог. Говорим, ГДЕ взять их вручную.
  echo " Секрет/ссылки  : скрыты (неинтерактивный вывод — не пишем в лог/CI)."
  echo "                  Секрет сохранён в ${MTG_SECRET_FILE} (root-only, 0600)."
  echo "                  Показать ссылки на терминале: ${MTG_BIN} access ${MTG_CONFIG}"
fi
echo "------------------------------------------------------------"
echo " ПРОВЕРКА/ОБСЛУЖИВАНИЕ:"
echo "   systemctl status mtg                  # статус службы"
echo "   journalctl -u mtg -n 50 --no-pager    # последние логи"
echo "   ${MTG_BIN} access ${MTG_CONFIG}   # снова показать ссылки"
echo
echo " ВАЖНО: ссылку/секрет НЕ публикуйте в открытых чатах/списках —"
echo "        прокси личный, и в этом весь смысл (вас не косят подсетями)."
echo "============================================================"
