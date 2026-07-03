<#
.SYNOPSIS
    make-proxifier-profile.ps1 — генератор импортируемого профиля Proxifier (.ppx).

.DESCRIPTION
    Запускается НА WINDOWS (ПК, с которого ходим к Claude/интернету).

    Цель: автоматически собрать готовый к импорту профиль Proxifier (.ppx — это XML),
    чтобы не настраивать прокси-цепочку руками по разделу 10 инструкции.

    Что описывает сгенерированный профиль:
      * ОДИН вышестоящий SOCKS5-прокси (ProxyList):
          Address  = -ProxyHost  (IP РФ-сервера-релея ИЛИ напрямую зарубежного VPS)
          Port     = -ProxyPort  (по умолчанию 1080 — порт 3proxy-релея на РФ-сервере)
          Auth     = enabled, Username = -ProxyUser (relayuser);
                     ПАРОЛЬ В ФАЙЛ НЕ ПИШЕТСЯ (см. ниже «Безопасность»).
      * Включённое разрешение имён НА СТОРОНЕ ПРОКСИ (Resolve hostnames through proxy):
          DNS-запросы уходят через прокси -> нет DNS-утечки реального местоположения.
      * Пустой <ChainList/> — обязательный служебный элемент реального формата .ppx
        (присутствует во всех экспортированных профилях Proxifier 3/4; без него ряд
        версий отказывает в импорте). Цепочку прокси мы здесь не описываем — пересылка
        на зарубежный VPS настроена параметром `parent` в самом 3proxy на РФ-сервере.
      * Правила (RuleList), порядок важен — Proxifier применяет первое подходящее:
          1) "AI"      — приложения из -Apps идут ЧЕРЕЗ наш SOCKS5-прокси (Action = Proxy);
          2) "Default" — весь остальной трафик идёт НАПРЯМУЮ (Action = Direct).

    Цепочка целиком (для контекста):
      [этот Windows + Proxifier] -> [РФ-сервер 3proxy SOCKS5 :1080 relayuser]
        -> [зарубежный VPS Dante SOCKS5 :39847 proxyuser] -> Claude/интернет.
      Proxifier на ПК подключается ТОЛЬКО к первому звену (-ProxyHost:-ProxyPort);
      дальнейшая пересылка на зарубежный VPS настроена параметром `parent` уже в самом
      3proxy на РФ-сервере (см. setup-ru-relay.sh) — здесь её описывать НЕ нужно.

.PARAMETER ProxyHost
    IP (или хост) первого звена цепочки: РФ-сервера-релея, либо напрямую зарубежного VPS.
    Обязательный параметр.

.PARAMETER ProxyPort
    TCP-порт SOCKS5 на -ProxyHost. По умолчанию 1080 (порт 3proxy-релея).

.PARAMETER ProxyUser
    Имя пользователя для аутентификации на SOCKS5. По умолчанию relayuser.

.PARAMETER Apps
    Список приложений, чей трафик заворачивается в прокси. Имена через ';'.
    По умолчанию "Claude.exe;Antigravity.exe;chrome.exe".

.PARAMETER OutFile
    Путь к выходному .ppx. По умолчанию ".\proxy-ai.ppx".
    Идемпотентность: если файл уже существует — он перезаписывается с предупреждением.

.PARAMETER Force
    Перезаписать существующий OutFile без вывода предупреждения (для скриптов/CI).

.NOTES
    БЕЗОПАСНОСТЬ — почему пароль НЕ попадает в файл:
      * Proxifier хранит пароль прокси в СОБСТВЕННОМ зашифрованном хранилище (Basic или
        AES-256, привязка к учётке Windows / master-паролю), а не открытым текстом в .ppx.
        Воспроизводить этот формат снаружи нельзя и не нужно.
      * .ppx — это, по сути, переносимый XML, который легко попадает в общий доступ
        (репозиторий, мессенджер, облако). Пароль в нём = утечка.
      * Документация Proxifier подтверждает: если Username/Password в профиле пусты,
        Proxifier запросит их интерактивно при первом подключении.
      Поэтому профиль содержит лишь Username и флаг «аутентификация включена».
      Пароль вы введёте ОДИН РАЗ в GUI Proxifier при первом подключении/импорте —
      дальше Proxifier запомнит его в своём защищённом хранилище.

    СОВМЕСТИМОСТЬ ФОРМАТА (ВАЖНО — см. residual_risks):
      Структура .ppx (атрибуты, имена тегов, номер версии профиля) ОТЛИЧАЕТСЯ между
      версиями Proxifier. Данный генератор ориентирован на современную ветку
      Proxifier 3/4 (Standard/Portable) для Windows и сверен с реальными экспортами
      (root version=101; порядок Address->Port->Options в <Proxy>; <ChainList/>;
      <Action type="Proxy">100</Action> и <Action type="Direct"/>).
      ОДНАКО точный синтаксис элемента <Authentication> с логином в публичных образцах
      профилей отсутствует — атрибут enabled="true" выбран по аналогии с подтверждёнными
      enabled="true" на Rule/ViaProxy, но НЕ подтверждён на живом GUI. Если ваша версия
      не примет файл («Cannot import / Unsupported profile»), это НЕ баг цепочки —
      настройте прокси ВРУЧНУЮ по разделу 10 инструкции (теми же значениями
      Host/Port/User), а профиль используйте как шпаргалку со значениями.

.EXAMPLE
    .\make-proxifier-profile.ps1 -ProxyHost 198.51.100.7
    # РФ-релей на 198.51.100.7:1080, пользователь relayuser, приложения по умолчанию.

.EXAMPLE
    .\make-proxifier-profile.ps1 -ProxyHost 203.0.113.10 -ProxyPort 39847 `
        -ProxyUser proxyuser -Apps "Claude.exe;chrome.exe" -OutFile C:\tmp\direct.ppx
    # Прямое подключение к зарубежному VPS (минуя РФ-релей) — для отладки.

.EXAMPLE
    .\make-proxifier-profile.ps1 -ProxyHost gate.residential-provider.com -ProxyPort 1080 -ProxyUser mylogin
    # СПОСОБ A (residential): Proxifier ходит ПРЯМО на residential-шлюз провайдера
    # (host:port:login из кабинета, SOCKS5) — выход с РЕЗИДЕНТНОГО IP, без своего VPS.
    # Генератор host-agnostic: подставьте шлюз residential так же, как любой SOCKS5.
    # Когда выбирать A vs B — см. раздел про residential в основном гайде.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "IP/хост первого звена (РФ-релей или зарубежный VPS)")]
    [ValidateNotNullOrEmpty()]
    [string]$ProxyHost,

    [ValidateRange(1, 65535)]
    [int]$ProxyPort = 1080,

    [ValidateNotNullOrEmpty()]
    [string]$ProxyUser = "relayuser",

    [ValidateNotNullOrEmpty()]
    [string]$Apps = "Claude.exe;Antigravity.exe;chrome.exe",

    [ValidateNotNullOrEmpty()]
    [string]$OutFile = ".\proxy-ai.ppx",

    [switch]$Force
)

# Любая ошибка -> останавливаемся (не «падать молча»: ниже свои понятные сообщения).
$ErrorActionPreference = 'Stop'

# ----------------------------------------------------------------------------
#  Служебные функции вывода (единый стиль логов)
# ----------------------------------------------------------------------------
function Write-Info { param([string]$Message) Write-Host "[+] $Message" -ForegroundColor Green }
function Write-Warn { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Err  { param([string]$Message) Write-Host "[x] $Message" -ForegroundColor Red }

# ----------------------------------------------------------------------------
#  0. ПРОВЕРКА ЗАВИСИМОСТЕЙ / ОКРУЖЕНИЯ (не падать молча)
# ----------------------------------------------------------------------------

# .NET XML API (System.Xml) — встроен в любой Windows PowerShell 5.1 и PowerShell 7+,
# но проверим явно, чтобы при экзотическом окружении дать понятную ошибку, а не stack trace.
try {
    [void][System.Xml.XmlDocument]
}
catch {
    Write-Err "Не найден тип System.Xml.XmlDocument — нужен .NET (Windows PowerShell 5.1+ или PowerShell 7+)."
    Write-Err "Запустите скрипт в штатном PowerShell на Windows."
    exit 1
}

# ----------------------------------------------------------------------------
#  1. ВАЛИДАЦИЯ И НОРМАЛИЗАЦИЯ ВХОДНЫХ ДАННЫХ
# ----------------------------------------------------------------------------

# Хост: режем пробелы; защищаемся от случайно вписанной схемы вроде "socks5://".
$ProxyHost = $ProxyHost.Trim()
if ($ProxyHost -match '://') {
    Write-Warn "В -ProxyHost обнаружена схема (например, socks5://) — убираю, нужен только IP/хост."
    $ProxyHost = ($ProxyHost -replace '^[a-zA-Z0-9]+://', '').Trim()
}
# Дополнительно отрезаем завершающий слэш/путь — но ТОЛЬКО для не-IPv6-форм и
# НЕ молча: иначе '2001:db8::1/64' (IPv6 с префиксом) обрезался бы по первому '/'
# без диагностики, в отличие от соседних веток, которые всегда печатают Write-Warn.
# Голый IPv6-литерал (>1 ':' без скобок) НЕ трогаем здесь — это валидный адрес,
# а '/64' в нём (если есть) к Proxifier-профилю не относится и обрабатывается ниже.
$looksLikeBareIpv6 = (($ProxyHost.Split(':').Count - 1) -gt 1) -and ($ProxyHost -notmatch '[\[\]]')
if ($ProxyHost -match '[/]') {
    if ($looksLikeBareIpv6) {
        Write-Warn "В -ProxyHost обнаружен '/' внутри похожего на IPv6 адреса ('$ProxyHost') — путь/префикс НЕ срезаю автоматически, чтобы не повредить адрес. Уберите лишнее вручную, если это не часть IPv6."
    }
    else {
        $stripped = ($ProxyHost -replace '[/].*$', '').Trim()
        Write-Warn "В -ProxyHost обнаружен путь/слэш — отрезаю всё после первого '/' ('$ProxyHost' -> '$stripped'). Нужен только IP/хост."
        $ProxyHost = $stripped
    }
}

# Отрезаем случайно дописанный ':port' — но БЕЗОПАСНО для IPv6.
# Голый IPv6-литерал (2001:db8::1) содержит несколько ':' и НЕ имеет порта;
# наивный '^(.+):\d+$' срезал бы у него последнюю группу (2001:db8::1 -> 2001:db8:),
# записывая в .ppx битый адрес. Поэтому различаем формы:
#   * '[ipv6]:port'  -> явная скобочная форма с портом: берём host из скобок [..];
#   * '[ipv6]'       -> скобки без порта: просто снимаем скобки;
#   * 'host:port'    -> IPv4/hostname c одним ':' и числовым портом: срезаем порт;
#   * 'ipv6'         -> >1 ':' без скобок: это голый IPv6-литерал, НЕ трогаем.
if ($ProxyHost -match '^\[([^\]]+)\]:\d+$') {
    # Скобочная форма с портом: [2001:db8::1]:1080 -> host = 2001:db8::1
    # Захват '([^\]]+)' нежадный по построению (символ ']' исключён из класса),
    # поэтому мусор вида '[2001:db8::1]:80]:90' СЮДА не матчится — лишние ']' не
    # попадут в host, а сам ввод будет отвергнут проверкой остаточных скобок ниже.
    Write-Warn "В -ProxyHost обнаружена форма '[ipv6]:порт' — беру host из скобок, порт задаётся параметром -ProxyPort."
    $ProxyHost = $Matches[1].Trim()
}
elseif ($ProxyHost -match '^\[([^\]]+)\]$') {
    # Скобочная форма без порта: [2001:db8::1] -> 2001:db8::1
    $ProxyHost = $Matches[1].Trim()
}
elseif (($ProxyHost.Split(':').Count - 1) -gt 1) {
    # Больше одного ':' и без скобок -> это голый IPv6-литерал (2001:db8::1).
    # Порт к такой записи без скобок не приписывают — ничего не срезаем.
}
elseif ($ProxyHost -match '^(.+):\d+$') {
    # Ровно одно ':' и числовой хвост -> IPv4 или hostname с портом: host:port -> host.
    Write-Warn "В -ProxyHost обнаружен ':порт' — убираю, порт задаётся параметром -ProxyPort."
    $ProxyHost = $Matches[1].Trim()
}
if ([string]::IsNullOrWhiteSpace($ProxyHost)) {
    Write-Err "Параметр -ProxyHost пуст после нормализации. Укажите IP РФ-релея или зарубежного VPS."
    exit 1
}

# Остаточные скобки '['/']' после нормализации = либо незакрытая скобка, либо мусор
# вроде '[2001:db8::1]:80]:90', который НЕ совпал ни с одной скобочной веткой выше
# (нежадный '[^\]]+' их не проглатывает). Не пишем такой адрес в .ppx — отвергаем явно.
if ($ProxyHost -match '[\[\]]') {
    Write-Err "Параметр -ProxyHost содержит лишние скобки '['/']' после нормализации: '$ProxyHost'."
    Write-Err "Ожидаемые формы: IPv4/hostname, голый IPv6 (2001:db8::1) или '[2001:db8::1]:порт'."
    exit 1
}

# Логин тоже нормализуем (пустой/пробельный -> понятная ошибка, а не битый XML).
$ProxyUser = $ProxyUser.Trim()
if ([string]::IsNullOrWhiteSpace($ProxyUser)) {
    Write-Err "Параметр -ProxyUser пуст. Укажите имя пользователя SOCKS5 (например, relayuser)."
    exit 1
}

# Разбираем список приложений: по ';', пустые элементы и пробелы отбрасываем.
$appList = @(
    $Apps -split ';' |
        ForEach-Object { $_.Trim() } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
)
if ($appList.Count -eq 0) {
    Write-Err "Список -Apps пуст. Укажите хотя бы одно приложение, например: -Apps `"Claude.exe`"."
    exit 1
}
Write-Info ("Приложения для проксирования (" + $appList.Count + "): " + ($appList -join ', '))

# ----------------------------------------------------------------------------
#  2. ИДЕМПОТЕНТНОСТЬ: подготовка выходного пути и предупреждение о перезаписи
# ----------------------------------------------------------------------------

# Приводим к абсолютному пути, не требуя существования файла (его ещё нет).
# GetUnresolvedProviderPathFromPSPath учитывает текущий каталог провайдера PowerShell.
$resolvedOut = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)

# Гарантируем существование родительского каталога (иначе запись упадёт «молча» внутри .NET).
$outDir = [System.IO.Path]::GetDirectoryName($resolvedOut)
if (-not [string]::IsNullOrEmpty($outDir) -and -not (Test-Path -LiteralPath $outDir)) {
    Write-Info "Создаю каталог назначения: $outDir"
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

if (Test-Path -LiteralPath $resolvedOut) {
    if ($Force) {
        Write-Warn "Файл уже существует и будет перезаписан (-Force): $resolvedOut"
    }
    else {
        Write-Warn "Файл уже существует — будет ПЕРЕЗАПИСАН: $resolvedOut"
        Write-Warn "Чтобы подавить это предупреждение, запустите с -Force."
    }
}

# ----------------------------------------------------------------------------
#  3. СБОРКА XML ПРОФИЛЯ Proxifier (.ppx)
# ----------------------------------------------------------------------------
# Строим документ через System.Xml.XmlDocument — это гарантирует корректное
# экранирование спецсимволов (&, <, > и т.п.) в значениях (имена приложений, хост).
#
# Структура (ветка Proxifier 3/4, сверена с реальными экспортами):
#   <ProxifierProfile version="101" platform="Windows" product_id="0" product_minver="400">
#     <Options><Resolve>...</Resolve></Options>
#     <ProxyList>
#       <Proxy id="100" type="SOCKS5">
#         <Address>..</Address><Port>..</Port><Options>48</Options>   <!-- именно такой порядок -->
#         <Authentication enabled="true"><Username>..</Username></Authentication>
#       </Proxy>
#     </ProxyList>
#     <ChainList/>                                       <!-- ОБЯЗАТЕЛЬНЫЙ пустой элемент -->
#     <RuleList>
#       <Rule enabled="true"><Name>AI</Name><Applications>..</Applications><Action type="Proxy">100</Action></Rule>
#       <Rule enabled="true"><Name>Default</Name><Action type="Direct"/></Rule>
#     </RuleList>
#   </ProxifierProfile>

$PROXY_ID = 100   # внутренний id прокси, на него ссылается правило "AI"

$doc = New-Object System.Xml.XmlDocument

# XML-декларация <?xml version="1.0" encoding="UTF-8"?>
$decl = $doc.CreateXmlDeclaration("1.0", "UTF-8", $null)
[void]$doc.AppendChild($decl)

# Небольшие помощники для лаконичной сборки дерева.
function New-El {
    param([string]$Name, [string]$Text = $null)
    $el = $doc.CreateElement($Name)
    if ($PSBoundParameters.ContainsKey('Text') -and $null -ne $Text) {
        $el.InnerText = $Text   # InnerText сам экранирует спецсимволы
    }
    return $el
}
function Set-Attr {
    param([System.Xml.XmlElement]$El, [string]$Name, [string]$Value)
    $El.SetAttribute($Name, $Value)
}

# --- Корень <ProxifierProfile> ---
$root = New-El 'ProxifierProfile'
Set-Attr $root 'version'        '101'
Set-Attr $root 'platform'       'Windows'
Set-Attr $root 'product_id'     '0'
Set-Attr $root 'product_minver' '400'
[void]$doc.AppendChild($root)

# --- <Options> -> <Resolve>: разрешение имён через прокси (нет DNS-утечки) ---
$options = New-El 'Options'

$resolve = New-El 'Resolve'

$autoDetect = New-El 'AutoModeDetection'
Set-Attr $autoDetect 'enabled' 'false'
[void]$resolve.AppendChild($autoDetect)

# ViaProxy enabled=true -> «Resolve hostnames through proxy»: DNS уходит через прокси.
$viaProxy = New-El 'ViaProxy'
Set-Attr $viaProxy 'enabled' 'true'
$tryLocalFirst = New-El 'TryLocalDnsFirst'
Set-Attr $tryLocalFirst 'enabled' 'false'   # НЕ пробовать локальный DNS первым -> без утечки
[void]$viaProxy.AppendChild($tryLocalFirst)
[void]$resolve.AppendChild($viaProxy)

# Исключения резолва оставляем пустыми (служебный тег для совместимости формата).
$exclusion = New-El 'ExclusionList'
[void]$resolve.AppendChild($exclusion)

[void]$options.AppendChild($resolve)
[void]$root.AppendChild($options)

# --- <ProxyList>: единственный SOCKS5-прокси ---
$proxyList = New-El 'ProxyList'

$proxy = New-El 'Proxy'
Set-Attr $proxy 'id'   "$PROXY_ID"
Set-Attr $proxy 'type' 'SOCKS5'

# Порядок Address -> Port -> Options подтверждён реальными экспортами Proxifier.
[void]$proxy.AppendChild((New-El 'Address' $ProxyHost))
[void]$proxy.AppendChild((New-El 'Port'    "$ProxyPort"))
# <Options>48</Options> — у Proxifier это битовая маска опций прокси; для SOCKS5
# значение с установленным битом удалённого DNS. Точная семантика версионно-зависима,
# поэтому ключевую защиту от DNS-утечки дублируем глобально через Resolve/ViaProxy выше.
[void]$proxy.AppendChild((New-El 'Options' '48'))

# Аутентификация: включена, передаём ТОЛЬКО логин. Пароль вводится в GUI один раз.
# ВНИМАНИЕ: точный синтаксис <Authentication> с логином не подтверждён публичными
# образцами .ppx (см. residual_risks). enabled="true" выбран по аналогии с
# подтверждёнными enabled="true" на Rule/ViaProxy.
$auth = New-El 'Authentication'
Set-Attr $auth 'enabled' 'true'
[void]$auth.AppendChild((New-El 'Username' $ProxyUser))
# <Password> намеренно НЕ добавляем (см. блок «Безопасность» в .NOTES) — Proxifier
# запросит пароль интерактивно при первом подключении.
[void]$proxy.AppendChild($auth)

[void]$proxyList.AppendChild($proxy)
[void]$root.AppendChild($proxyList)

# --- <ChainList/>: ОБЯЗАТЕЛЬНЫЙ пустой элемент реального формата .ppx ---
# Присутствует во всех экспортированных профилях Proxifier между <ProxyList> и
# <RuleList>; без него некоторые версии отказывают в импорте. Цепочку не описываем —
# пересылку на зарубежный VPS делает 3proxy (`parent`) на РФ-сервере.
$chainList = New-El 'ChainList'
[void]$root.AppendChild($chainList)

# --- <RuleList>: правило "AI" (через прокси) + "Default" (напрямую) ---
$ruleList = New-El 'RuleList'

# Правило "AI": перечисленные приложения -> Action type="Proxy" с id нашего прокси.
$ruleAi = New-El 'Rule'
Set-Attr $ruleAi 'enabled' 'true'
[void]$ruleAi.AppendChild((New-El 'Name' 'AI'))
# Applications: список имён через ';' (формат, который понимает Proxifier).
[void]$ruleAi.AppendChild((New-El 'Applications' ($appList -join '; ')))
$actionProxy = New-El 'Action' "$PROXY_ID"
Set-Attr $actionProxy 'type' 'Proxy'
[void]$ruleAi.AppendChild($actionProxy)
[void]$ruleList.AppendChild($ruleAi)

# Правило "Default": ВЕСЬ остальной трафик -> напрямую (Direct).
# Должно идти ПОСЛЕ "AI" — Proxifier берёт первое совпавшее правило, а Default ловит всё.
$ruleDefault = New-El 'Rule'
Set-Attr $ruleDefault 'enabled' 'true'
[void]$ruleDefault.AppendChild((New-El 'Name' 'Default'))
$actionDirect = New-El 'Action'
Set-Attr $actionDirect 'type' 'Direct'
[void]$ruleDefault.AppendChild($actionDirect)
[void]$ruleList.AppendChild($ruleDefault)

[void]$root.AppendChild($ruleList)

# ----------------------------------------------------------------------------
#  4. ЗАПИСЬ ФАЙЛА (UTF-8 без BOM, с отступами для читаемости)
# ----------------------------------------------------------------------------
try {
    $settings = New-Object System.Xml.XmlWriterSettings
    $settings.Indent = $true
    $settings.IndentChars = "  "
    # UTF-8 без BOM: Proxifier и большинство XML-парсеров не любят BOM в начале файла.
    $settings.Encoding = New-Object System.Text.UTF8Encoding($false)

    $writer = [System.Xml.XmlWriter]::Create($resolvedOut, $settings)
    try {
        $doc.Save($writer)
    }
    finally {
        $writer.Dispose()   # гарантированно закрываем поток (без утечки дескриптора)
    }
}
catch {
    Write-Err "Не удалось записать профиль в '$resolvedOut': $($_.Exception.Message)"
    exit 1
}

# ----------------------------------------------------------------------------
#  5. ИТОГ И ИНСТРУКЦИЯ ПО ИМПОРТУ
# ----------------------------------------------------------------------------
Write-Info "Профиль Proxifier создан."
Write-Host ""
Write-Host "  Файл профиля : $resolvedOut" -ForegroundColor Cyan
Write-Host "  Прокси       : SOCKS5  $ProxyHost`:$ProxyPort" -ForegroundColor Cyan
Write-Host "  Пользователь : $ProxyUser  (пароль в файл НЕ записан — введёте в GUI)" -ForegroundColor Cyan
Write-Host "  Через прокси : $($appList -join ', ')" -ForegroundColor Cyan
Write-Host "  Прочий трафик: напрямую (Direct)" -ForegroundColor Cyan
Write-Host "  DNS          : через прокси (защита от DNS-утечки)" -ForegroundColor Cyan
Write-Host ""
Write-Host "  КАК ИМПОРТИРОВАТЬ:" -ForegroundColor Cyan
Write-Host "    1) Откройте Proxifier." -ForegroundColor Cyan
Write-Host "    2) Меню: Profile -> Import Profile..." -ForegroundColor Cyan
Write-Host "    3) Выберите файл: $resolvedOut" -ForegroundColor Cyan
Write-Host "    4) После импорта введите ПАРОЛЬ прокси один раз:" -ForegroundColor Cyan
Write-Host "       Profile -> Proxy Servers -> [этот прокси] -> Edit -> поле Password." -ForegroundColor Cyan
Write-Host "       Proxifier сохранит пароль в собственном защищённом хранилище." -ForegroundColor Cyan
Write-Host ""
Write-Warn "Формат .ppx версионно-зависим. Если Proxifier откажется импортировать файл —"
Write-Warn "настройте прокси ВРУЧНУЮ по разделу 10 (теми же Host/Port/User), а профиль"
Write-Warn "используйте как шпаргалку со значениями."
