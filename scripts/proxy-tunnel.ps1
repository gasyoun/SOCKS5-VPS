#Requires -Version 5.1
<#
.SYNOPSIS
    Поднимает и САМ держит живым SSH-туннель SOCKS5 к зарубежному VPS.

.DESCRIPTION
    Это АЛЬТЕРНАТИВА связке через РФ-релей (3proxy) + Dante.
    Здесь клиент идёт НАПРЯМУЮ по SSH на зарубежный VPS и поднимает
    динамический проброс (-D), то есть локальный SOCKS5-прокси.

    Цепочка в этом режиме:
        [Windows ПК] --SSH--> [зарубежный VPS] --> Claude/интернет

    После запуска локальный SOCKS5 будет доступен на 127.0.0.1:<LocalPort>.
    В Proxifier / браузере указывать:
        Host: 127.0.0.1
        Port: <LocalPort> (по умолчанию 1080)
        Type: SOCKS5
        БЕЗ логина и пароля (это локальный сокет, аутентификация уже на стороне SSH).

    Скрипт держит туннель живым: при обрыве соединения он автоматически
    переподключается. Между попытками выдерживается пауза с экспоненциальным
    нарастанием (защита от busy-loop, если VPS/сеть недоступны).
    Ключи ServerAliveInterval/ServerAliveCountMax заставляют ssh быстро
    замечать "мёртвое" соединение, а ExitOnForwardFailure=yes — падать сразу,
    если локальный порт занять не удалось (а не висеть с неработающим прокси).

.PARAMETER VpsIp
    IP или хостнейм зарубежного VPS (обязательный параметр).

.PARAMETER VpsUser
    Пользователь SSH на VPS. По умолчанию "root".

.PARAMETER LocalPort
    Локальный TCP-порт, на котором поднимется SOCKS5 (127.0.0.1:LocalPort).
    По умолчанию 1080.

.PARAMETER SshPort
    Порт SSH на VPS. По умолчанию 22.

.PARAMETER KnownHostsFile
    Путь к ПОСТОЯННОМУ файлу known_hosts, в котором хранится host key VPS.
    По умолчанию — отдельный файл рядом с профилем пользователя
    (%LOCALAPPDATA%\ProxyTunnel\known_hosts), НЕ зависящий от глобального
    ~/.ssh/known_hosts. Постоянное хранилище нужно, чтобы СМЕНА ключа сервера
    (потенциальный MITM) была замечена и отвергнута, а не принята молча.

.PARAMETER PinnedKnownHosts
    Необязательный путь к файлу known_hosts с ЗАРАНЕЕ выверенным host key VPS
    (получите fingerprint через консоль/панель провайдера ДО первого коннекта).
    Если задан — туннель работает в строгом режиме StrictHostKeyChecking=yes
    против ИМЕННО этого файла: любой неизвестный/несовпадающий ключ => отказ,
    никакого TOFU. Это самый безопасный режим (защита от MITM на первом коннекте).

.PARAMETER Install
    Зарегистрировать этот скрипт как Scheduled Task, запускающуюся при
    входе пользователя в систему (logon) и перезапускающуюся при сбое.

.PARAMETER Uninstall
    Удалить ранее созданную Scheduled Task.

.EXAMPLE
    .\proxy-tunnel.ps1 -VpsIp 203.0.113.10
    Поднять туннель в текущей консоли (foreground), держать живым.

.EXAMPLE
    .\proxy-tunnel.ps1 -VpsIp 203.0.113.10 -VpsUser root -LocalPort 1080 -SshPort 22
    То же, с явными параметрами.
    ВНИМАНИЕ: -VpsUser — это SSH-ЛОГИН на VPS (по умолчанию root), а НЕ имя
    SOCKS-аккаунта. Не путать с 'proxyuser': это nologin-учётка прокси без
    SSH-доступа, по ней туннель не поднимется.

.EXAMPLE
    .\proxy-tunnel.ps1 -VpsIp 203.0.113.10 -Install
    Установить как автозапускаемую задачу (стартует при логоне).

.EXAMPLE
    .\proxy-tunnel.ps1 -LocalPort 1080 -Uninstall
    Удалить автозапускаемую задачу (LocalPort должен совпадать с установкой).

.NOTES
    Требуется встроенный клиент OpenSSH (Get-Command ssh).
    Если его нет — установить (от администратора):
        Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
    Рекомендуется заранее настроить вход на VPS по ключу (ssh-copy-id / ~/.ssh),
    иначе при автозапуске ssh будет ждать ввод пароля и туннель не поднимется.
#>

# --- Параметры (всегда сверху) -------------------------------------------------
# Два набора параметров:
#   'Run'       — поднять/установить туннель (требует -VpsIp).
#   'Uninstall' — удалить Scheduled Task (-VpsIp не нужен и не запрашивается).
# Набор по умолчанию — 'Run', поэтому обычный запуск без -Uninstall работает как раньше.
[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
    # VpsIp обязателен ТОЛЬКО в наборе 'Run'. В наборе 'Uninstall' его нет вовсе,
    # поэтому пример удаления (`-LocalPort 1080 -Uninstall`) корректно биндится.
    [Parameter(ParameterSetName = 'Run', Mandatory = $true, HelpMessage = "IP/хостнейм зарубежного VPS")]
    [ValidateNotNullOrEmpty()]
    [string]$VpsIp,

    [Parameter(ParameterSetName = 'Run')]
    [ValidateNotNullOrEmpty()]
    [string]$VpsUser = "root",

    # LocalPort нужен обоим наборам: при удалении он формирует имя задачи,
    # поэтому объявлен в каждом наборе явно (со своим default).
    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Uninstall')]
    [ValidateRange(1, 65535)]
    [int]$LocalPort = 1080,

    [Parameter(ParameterSetName = 'Run')]
    [ValidateRange(1, 65535)]
    [int]$SshPort = 22,

    # Постоянный known_hosts (TOFU-режим accept-new): первый ключ принимаем,
    # дальнейшая СМЕНА ключа => отказ (ловит поздний MITM). Нужен оба набора,
    # чтобы Install мог пробросить путь в Scheduled Task.
    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Uninstall')]
    [ValidateNotNullOrEmpty()]
    [string]$KnownHostsFile = (Join-Path $env:LOCALAPPDATA "ProxyTunnel\known_hosts"),

    # Заранее выверенный pinned known_hosts: если задан — строгий режим
    # StrictHostKeyChecking=yes против него (без TOFU, отказ на любой нестыковке).
    [Parameter(ParameterSetName = 'Run')]
    [ValidateNotNullOrEmpty()]
    [string]$PinnedKnownHosts,

    [Parameter(ParameterSetName = 'Run')]
    [switch]$Install,

    [Parameter(ParameterSetName = 'Uninstall', Mandatory = $true)]
    [switch]$Uninstall
)

# Останавливаемся на любой НЕперехваченной ошибке (аналог set -e для PowerShell).
$ErrorActionPreference = "Stop"

# --- Константы / переменные верхнего уровня ------------------------------------
# Имя Scheduled Task. Включает LocalPort, чтобы можно было держать несколько
# независимых туннелей (на разные порты) без коллизии задач.
$TaskName            = "ProxyTunnel_SOCKS5_$LocalPort"
$ReconnectDelayMin   = 5      # минимальная пауза (сек) между попытками
$ReconnectDelayMax   = 120    # максимальная пауза (сек) при затяжной недоступности
# Абсолютный путь к самому скрипту (нужен для регистрации задачи).
$ScriptPath          = $MyInvocation.MyCommand.Path

# ------------------------------------------------------------------------------
# Вспомогательные функции вывода — единый стиль сообщений, ничего не молчит.
# ------------------------------------------------------------------------------
function Write-Info  { param([string]$Msg) Write-Host "[i] $Msg" -ForegroundColor Cyan }
function Write-Ok    { param([string]$Msg) Write-Host "[+] $Msg" -ForegroundColor Green }
function Write-Warn  { param([string]$Msg) Write-Host "[!] $Msg" -ForegroundColor Yellow }
function Write-Err   { param([string]$Msg) Write-Host "[x] $Msg" -ForegroundColor Red }

# ------------------------------------------------------------------------------
# Поиск пути к клиенту OpenSSH.
# Возвращает полный путь к ssh.exe или $null, если клиент не найден.
# Используем абсолютный путь при запуске, чтобы не зависеть от PATH в контексте
# Scheduled Task (там PATH может отличаться от интерактивного сеанса).
# ------------------------------------------------------------------------------
function Get-SshPath {
    $ssh = Get-Command ssh -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($ssh) { return $ssh.Source }
    # Запасной путь: штатное расположение встроенного клиента Windows.
    $fallback = Join-Path $env:WINDIR "System32\OpenSSH\ssh.exe"
    if (Test-Path -LiteralPath $fallback) { return $fallback }
    return $null
}

# ------------------------------------------------------------------------------
# Определяет, поддерживает ли клиент OpenSSH режим StrictHostKeyChecking=accept-new.
# Опция accept-new появилась в OpenSSH 7.6 (2017). Клиенты СТАРШЕ (< 7.6) её не знают
# и при её передаче падают с exit 255 ("unknown option") => вечный backoff без подсказки.
# Возвращаем $true, если accept-new заведомо поддерживается; иначе $false (=> фолбэк на 'yes').
# `ssh -V` пишет версию в stderr, поэтому перенаправляем stderr->stdout (2>&1).
# При любой неудаче детекта осторожно возвращаем $false: 'yes' строже и совместим везде.
# ------------------------------------------------------------------------------
function Test-SshAcceptNewSupported {
    param([Parameter(Mandatory = $true)][string]$SshPath)
    try {
        # `ssh -V` => строка вида "OpenSSH_for_Windows_9.5p1, LibreSSL 3.8.2".
        # ErrorAction Continue, чтобы вывод в stderr не считался терминирующей ошибкой.
        $verText = (& $SshPath -V 2>&1 | Out-String)
        # ВАЖНО: у Windows-клиента баннер = 'OpenSSH_for_Windows_9.5p1' — сразу после
        # 'OpenSSH_' идёт 'for_Windows_', а НЕ цифра. Жёсткое 'OpenSSH[_/](\d+)' такой
        # баннер НЕ матчит => версия не определяется => фолбэк на 'yes' даже на свежем
        # клиенте => ломается unattended accept-new/TOFU под Scheduled Task на целевой
        # (Windows) платформе. Поэтому ищем первую пару чисел (\d+)\.(\d+) ПОСЛЕ 'OpenSSH'
        # независимо от промежуточного 'for_Windows_' (буквы/пробел/подчёркивание/'v').
        if ($verText -match 'OpenSSH[_a-zA-Z]*[ _v]?(\d+)\.(\d+)') {
            $major = [int]$Matches[1]
            $minor = [int]$Matches[2]
            # accept-new доступен начиная с 7.6.
            return ($major -gt 7) -or ($major -eq 7 -and $minor -ge 6)
        }
        # Не смогли распарсить версию (нестандартная сборка/форк) — играем безопасно.
        return $false
    }
    catch {
        # Не удалось вызвать ssh -V — не рискуем accept-new, фолбэк на строгий 'yes'.
        return $false
    }
}

# ------------------------------------------------------------------------------
# Проверка наличия клиента OpenSSH.
# Без него скрипт бесполезен — даём чёткую инструкцию по установке.
# ------------------------------------------------------------------------------
function Test-SshAvailable {
    $sshPath = Get-SshPath
    if (-not $sshPath) {
        Write-Err "Не найден клиент OpenSSH (команда 'ssh')."
        Write-Warn "Установите встроенный клиент Windows и повторите запуск:"
        Write-Host '    Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0' -ForegroundColor White
        Write-Warn "Команда установки требует прав администратора."
        return $false
    }
    Write-Info ("Найден ssh: {0}" -f $sshPath)
    return $true
}

# ------------------------------------------------------------------------------
# Проверка доступности модуля ScheduledTasks (нужен для -Install/-Uninstall).
# На некоторых урезанных/серверных образах модуля может не быть.
# ------------------------------------------------------------------------------
function Test-ScheduledTasksModule {
    if (Get-Command Register-ScheduledTask -ErrorAction SilentlyContinue) { return $true }
    Write-Err "Модуль ScheduledTasks недоступен — регистрация автозапуска невозможна на этой системе."
    Write-Warn "Запускайте скрипт вручную в foreground, либо настройте автозапуск иным способом (ярлык в Startup)."
    return $false
}

# ------------------------------------------------------------------------------
# Установка Scheduled Task: автозапуск туннеля при логоне пользователя.
# Идемпотентно: если задача с таким именем уже есть — пересоздаём (не плодим дубли).
# ------------------------------------------------------------------------------
function Install-TunnelTask {
    # Скрипт должен иметь сохранённый путь на диске (а не быть вставлен в консоль).
    if ([string]::IsNullOrWhiteSpace($ScriptPath)) {
        Write-Err "Не удалось определить путь к скрипту. Сохраните .ps1 на диск и запустите его как файл."
        exit 1
    }
    if (-not (Test-ScheduledTasksModule)) { exit 1 }

    Write-Info "Регистрирую Scheduled Task '$TaskName' (автозапуск при входе в систему)..."

    # Определяем учётку текущего пользователя.
    # ВАЖНО: на машинах с входом по Microsoft-account / Azure AD домен в
    # $env:USERDOMAIN может быть именем ПК — это нормально для -AtLogOn.
    # Если домен пуст по какой-то причине — берём только имя пользователя.
    if ([string]::IsNullOrWhiteSpace($env:USERDOMAIN)) {
        $userId = $env:USERNAME
    } else {
        $userId = "$env:USERDOMAIN\$env:USERNAME"
    }
    Write-Info "Задача будет запускаться от: $userId"

    # Аргументы запуска самого скрипта внутри задачи.
    # -ExecutionPolicy Bypass — чтобы задача не споткнулась о политику запуска
    #                           (касается ТОЛЬКО запуска этого файла, политику системы не меняет).
    # -WindowStyle Hidden     — туннель работает в фоне, без мигающего окна.
    # Пробрасываем те же сетевые параметры, что задал пользователь.
    # КАЖДОЕ строковое значение берём в кавычки на случай пробелов/спецсимволов.
    $q = { param($s) '"' + ([string]$s).Replace('"','""') + '"' }
    $psArgs = @(
        '-NoProfile'
        '-ExecutionPolicy', 'Bypass'
        '-WindowStyle', 'Hidden'
        '-File', (& $q $ScriptPath)
        '-VpsIp', (& $q $VpsIp)
        '-VpsUser', (& $q $VpsUser)
        '-LocalPort', $LocalPort
        '-SshPort', $SshPort
        # Пробрасываем постоянный known_hosts, чтобы скрытая задача проверяла
        # host key против того же файла, что и ручной запуск (смена ключа => отказ).
        '-KnownHostsFile', (& $q $KnownHostsFile)
    )
    # pinned known_hosts пробрасываем только если он реально задан пользователем,
    # иначе оставляем TOFU-режим (accept-new) по умолчанию.
    if (-not [string]::IsNullOrWhiteSpace($PinnedKnownHosts)) {
        $psArgs += @('-PinnedKnownHosts', (& $q $PinnedKnownHosts))
    }
    $psArgs = $psArgs -join ' '

    # Идемпотентность: удаляем старую задачу с тем же именем, если она была.
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Warn "Задача '$TaskName' уже существует — пересоздаю (без дублей)."
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }

    # Действие: powershell.exe с нашими аргументами.
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $psArgs

    # Триггер: при входе ТЕКУЩЕГО пользователя в систему.
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $userId

    # Запуск от имени текущего пользователя, в интерактивном контексте
    # (нужно для доступа к его ~/.ssh с ключами и known_hosts).
    $principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Limited

    # Настройки надёжности:
    #   RestartCount/RestartInterval — перезапуск задачи при сбое;
    #   ExecutionTimeLimit 0          — без ограничения по времени (туннель живёт долго);
    #   AllowStartIfOnBatteries / DontStop... — не глушить на ноутбуке от батареи;
    #   StartWhenAvailable            — наверстать запуск, если момент логона был пропущен;
    #   MultipleInstances IgnoreNew   — не плодить второй экземпляр поверх работающего.
    $settings = New-ScheduledTaskSettingsSet `
        -RestartCount 999 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -MultipleInstances IgnoreNew

    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Description "SSH SOCKS5-туннель на $VpsUser@$VpsIp -> 127.0.0.1:$LocalPort (держится живым автоматически)." | Out-Null

    Write-Ok "Задача '$TaskName' установлена. Туннель будет подниматься при входе в систему."
    Write-Info "Запустить прямо сейчас, не дожидаясь перелогина:"
    Write-Host "    Start-ScheduledTask -TaskName '$TaskName'" -ForegroundColor White
    Write-Info "SOCKS5 будет на 127.0.0.1:$LocalPort (в Proxifier: 127.0.0.1, порт $LocalPort, SOCKS5, без пароля)."
    Write-Warn "ПЕРЕД автозапуском один раз запустите туннель вручную в консоли, чтобы принять host key и"
    Write-Warn "убедиться, что вход по ключу работает — иначе скрытая задача зависнет в ожидании пароля."
    Write-Warn "БЕЗОПАСНОСТЬ: при первом коннекте сверьте предъявленный fingerprint с тем, что показывает"
    Write-Warn "консоль/панель провайдера VPS, — это защита от MITM при первичном TOFU-приёме ключа."
    if (-not [string]::IsNullOrWhiteSpace($PinnedKnownHosts)) {
        Write-Info ("Строгий режим: host key проверяется против pinned-файла '{0}' (StrictHostKeyChecking=yes)." -f $PinnedKnownHosts)
    } else {
        Write-Info ("Host key хранится в постоянном known_hosts: {0} (TOFU accept-new; смена ключа => отказ)." -f $KnownHostsFile)
    }
}

# ------------------------------------------------------------------------------
# Удаление Scheduled Task. Идемпотентно: нет задачи — просто сообщаем.
# ------------------------------------------------------------------------------
function Uninstall-TunnelTask {
    if (-not (Test-ScheduledTasksModule)) { exit 1 }

    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $existing) {
        Write-Warn "Задача '$TaskName' не найдена — удалять нечего."
        return
    }
    Write-Info "Удаляю Scheduled Task '$TaskName'..."
    # На случай, если задача сейчас выполняется — сначала остановим её
    # (это завершает дерево процессов задачи, включая ssh, запущенный из неё).
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Ok "Задача '$TaskName' удалена."
    Write-Warn "Если туннель был запущен ВРУЧНУЮ (не через задачу), его процесс ssh продолжит работать."
    Write-Warn "Завершите нужный экземпляр вручную (НЕ убивайте все ssh скопом, если их несколько):"
    # Печатаем готовую к копированию команду: внутренние кавычки экранируем
    # обратным апострофом (`"), $_ экранируем тоже, $LocalPort подставляем.
    Write-Host "    Get-CimInstance Win32_Process -Filter `"Name='ssh.exe'`" | Where-Object CommandLine -like '*127.0.0.1:$LocalPort*' | ForEach-Object { Stop-Process -Id `$_.ProcessId }" -ForegroundColor White
}

# ------------------------------------------------------------------------------
# Основной режим: запустить ssh-туннель и держать его живым в цикле.
# ------------------------------------------------------------------------------
function Start-TunnelLoop {
    $sshPath = Get-SshPath
    if (-not $sshPath) {
        Write-Err "Клиент ssh пропал — не могу запустить туннель."
        exit 1
    }

    Write-Ok  "Запуск SSH SOCKS5-туннеля."
    Write-Info "Маршрут:   $VpsUser@$VpsIp (порт SSH $SshPort)"
    Write-Info "Локальный SOCKS5: 127.0.0.1:$LocalPort"
    Write-Info "В Proxifier/браузере: 127.0.0.1 : $LocalPort, тип SOCKS5, БЕЗ логина/пароля."
    Write-Info "Это альтернатива связке РФ-релей (3proxy) + Dante: здесь прямой SSH на VPS."
    Write-Warn "Остановить: Ctrl+C (в foreground) либо завершить процесс ssh / задачу."

    # --- Защита host key (anti-MITM) ------------------------------------------
    # Выбираем РЕЖИМ проверки host key:
    #   * Если задан -PinnedKnownHosts (выверенный заранее через консоль провайдера) —
    #     строгий режим StrictHostKeyChecking=yes против ИМЕННО этого файла: любой
    #     неизвестный/несовпадающий ключ => немедленный отказ, без TOFU. Самый безопасный.
    #   * Иначе — TOFU-режим accept-new: ПЕРВЫЙ ключ принимаем автоматически и
    #     записываем в ПОСТОЯННЫЙ known_hosts, а дальнейшую СМЕНУ ключа отвергаем
    #     (ловит поздний MITM/подмену сервера). Это строго безопаснее, чем прежнее
    #     поведение (StrictHostKeyChecking по умолчанию + общий ~/.ssh/known_hosts),
    #     и не зависит от глобального known_hosts пользователя.
    # known_hosts держим в постоянном файле — иначе смена ключа не ловилась бы.
    if (-not [string]::IsNullOrWhiteSpace($PinnedKnownHosts)) {
        if (-not (Test-Path -LiteralPath $PinnedKnownHosts)) {
            Write-Err ("Pinned known_hosts не найден: {0}" -f $PinnedKnownHosts)
            Write-Warn "Создайте его заранее, сверив fingerprint через консоль/панель провайдера VPS."
            exit 1
        }
        $hostKeyFile  = $PinnedKnownHosts
        $strictMode   = "yes"
        Write-Info ("Проверка host key: СТРОГО против pinned-файла '{0}' (StrictHostKeyChecking=yes)." -f $hostKeyFile)
    } else {
        $hostKeyFile  = $KnownHostsFile
        $strictMode   = "accept-new"
        # Гарантируем существование каталога под постоянный known_hosts.
        # Под $ErrorActionPreference='Stop' падение New-Item (redirected/roaming
        # профиль, deny-ACL) убило бы весь скрипт — а в Scheduled Task ещё и молча.
        # Поэтому оборачиваем в try/catch: не смогли создать каталог — внятно
        # предупреждаем и продолжаем (ssh сам сообщит, если не сможет писать known_hosts).
        $khDir = Split-Path -Parent $hostKeyFile
        if ($khDir -and -not (Test-Path -LiteralPath $khDir)) {
            try {
                New-Item -ItemType Directory -Path $khDir -Force -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Warn ("Не удалось создать каталог для known_hosts '{0}': {1}" -f $khDir, $_.Exception.Message)
                Write-Warn "Продолжаю: ssh попытается записать known_hosts сам. Если каталог недоступен —"
                Write-Warn "укажите доступный путь через -KnownHostsFile или заранее выверенный -PinnedKnownHosts."
            }
        }
        # Версионный гейт: accept-new есть только в OpenSSH >= 7.6. На старом клиенте
        # передача этой опции => exit 255 и вечный backoff без подсказки. Поэтому
        # одноразово проверяем версию и при необходимости фолбэчимся на 'yes'
        # (строгая проверка: неизвестный/несовпадающий ключ => отказ; первый ключ
        # тогда добавляется интерактивным подтверждением при ручном запуске).
        if (-not (Test-SshAcceptNewSupported -SshPath $sshPath)) {
            $strictMode = "yes"
            Write-Warn "Клиент OpenSSH не поддерживает 'accept-new' (нужен >= 7.6) или версия не определена."
            Write-Warn "Фолбэк на StrictHostKeyChecking=yes: первый ключ примите интерактивно при ручном запуске,"
            Write-Warn "иначе скрытая задача зависнет/упадёт. Лучший вариант — заранее задать -PinnedKnownHosts."
        }
        Write-Info ("Проверка host key: TOFU ({0}), постоянный known_hosts '{1}'." -f $strictMode, $hostKeyFile)
        Write-Warn "ПРИ ПЕРВОМ КОННЕКТЕ сверьте предъявленный fingerprint с консолью/панелью провайдера VPS"
        Write-Warn "ДО подтверждения — это единственный момент, когда возможна незаметная подмена (MITM)."
        Write-Warn "Хотите исключить TOFU полностью — задайте -PinnedKnownHosts с выверенным заранее ключом."
    }

    # Аргументы ssh:
    #   -D 127.0.0.1:LocalPort      — динамический проброс = локальный SOCKS5 (ТОЛЬКО на loopback).
    #   -N                          — не выполнять удалённую команду (только проброс).
    #   -p SshPort                  — порт SSH на VPS.
    #   ServerAliveInterval=30      — слать keepalive каждые 30 с.
    #   ServerAliveCountMax=3       — после 3 пропусков (~90 с) считать соединение мёртвым и выйти.
    #   ExitOnForwardFailure=yes    — если не удалось занять локальный порт — выходить (а не висеть).
    #   StrictHostKeyChecking       — 'yes' (pinned) или 'accept-new' (TOFU): в обоих случаях
    #                                 СМЕНА уже известного ключа => отказ (anti-MITM), молчаливого
    #                                 приёма изменившегося ключа не происходит никогда.
    #   UserKnownHostsFile=<persist>— постоянный known_hosts, чтобы смена ключа реально ловилась.
    #   BatchMode НЕ включаем намеренно: при ПЕРВОМ ручном запуске (в TOFU-режиме) это позволит
    #   принять host key и/или ввести пароль. Для автозапуска настройте ключ заранее.
    $sshArgs = @(
        "-D", "127.0.0.1:$LocalPort"
        "-N"
        "-p", "$SshPort"
        "-o", "ServerAliveInterval=30"
        "-o", "ServerAliveCountMax=3"
        "-o", "ExitOnForwardFailure=yes"
        "-o", "StrictHostKeyChecking=$strictMode"
        # ВНИМАНИЕ: значение UserKnownHostsFile в ssh_config бьётся по ПРОБЕЛАМ в
        # список файлов. Дефолтный путь %LOCALAPPDATA%\ProxyTunnel\known_hosts
        # содержит пробел, если имя Windows-аккаунта с пробелом ('John Doe') =>
        # без кавычек хост каждый раз 'unknown' (анти-MITM persistence не работает),
        # а в pinned-режиме файл не читается и коннект отвергается. Квотируем путь
        # внутренними кавычками, чтобы ssh трактовал его как ОДИН файл.
        "-o", ('UserKnownHostsFile="{0}"' -f $hostKeyFile)
        "$VpsUser@$VpsIp"
    )

    $attempt = 0
    $failStreak = 0   # счётчик подряд идущих НЕУДАЧНЫХ попыток (по коду возврата ssh)
    # Порог "долгоживущего" соединения (сек): успешная сессия, прожившая дольше,
    # считается реально работавшей и обнуляет эскалацию backoff. Короче этого —
    # даже при коде 0 это, скорее всего, мгновенный обрыв, streak не сбрасываем.
    $longLivedThreshold = 30
    # Бесконечный цикл переподключения: при любом завершении ssh ждём и стартуем заново.
    while ($true) {
        $attempt++
        Write-Info ("Подключение (попытка #{0})..." -f $attempt)

        $startedAt = Get-Date
        $code = $null
        try {
            # Вызываем ssh ЧЕРЕЗ оператор вызова (&), а НЕ Start-Process:
            #   * ssh наследует реальную консоль (stdin/stdout/stderr), поэтому
            #     запрос host key / пароля при первом ручном запуске работает;
            #   * $LASTEXITCODE надёжно содержит код выхода ssh
            #     (у Start-Process .ExitCode может оказаться $null).
            & $sshPath @sshArgs
            $code = $LASTEXITCODE
        }
        catch {
            # Не падаем молча: показываем причину и всё равно пойдём на переподключение.
            Write-Err ("Не удалось запустить ssh: {0}" -f $_.Exception.Message)
            $code = -1
        }

        $elapsed = (Get-Date) - $startedAt

        # Классификация попытки — по КОДУ ВОЗВРАТА ssh, а не по времени работы.
        #   * НЕнулевой код  => попытка НЕУДАЧНАЯ (отказ ключа/пароля, неверный хост/порт,
        #     занятый локальный порт, разрыв keepalive и т.п.). Именно так "медленный"
        #     отказ ключа (>=5 с, exit 255) теперь корректно наращивает backoff,
        #     а не обнуляет его, как делала прежняя классификация по времени.
        #   * Код 0 (чистое завершение ssh) => успешная попытка, НО эскалацию backoff
        #     сбрасываем только если соединение реально пожило (>= порога). Иначе
        #     мгновенный "успешный" обрыв не должен прятать стойкую проблему.
        $failed = ($code -ne 0)

        if ($failed) {
            $failStreak++
            Write-Warn ("Туннель оборвался (код выхода ssh: {0}; неудач подряд: {1}). Переподключаюсь..." -f $code, $failStreak)
        }
        elseif ($elapsed.TotalSeconds -ge $longLivedThreshold) {
            # Долгоживущее успешное соединение — считаем сеть/ключ здоровыми,
            # обнуляем счётчик, чтобы следующий обрыв стартовал с минимальной паузы.
            $failStreak = 0
            Write-Warn ("Туннель завершился штатно (код 0, прожил {0:n0} с). Переподключаюсь..." -f $elapsed.TotalSeconds)
        }
        else {
            # Код 0, но соединение почти не прожило — НЕ сбрасываем streak.
            $failStreak++
            Write-Warn ("Туннель завершился почти мгновенно (код 0, {0:n0} с; неудач подряд: {1}). Переподключаюсь..." -f $elapsed.TotalSeconds, $failStreak)
        }

        # Защита от busy-loop: паузу наращиваем экспоненциально по числу
        # ПОСЛЕДОВАТЕЛЬНЫХ неудач (до потолка), чтобы не молотить впустую при
        # стойкой проблеме (неверный хост/порт, отказ в ключе/пароле, занят порт).
        if ($failStreak -ge 1) {
            $delay = [Math]::Min($ReconnectDelayMin * [Math]::Pow(2, $failStreak - 1), $ReconnectDelayMax)
            $delay = [int]$delay
        } else {
            $delay = $ReconnectDelayMin
        }

        if ($failStreak -ge 3) {
            Write-Warn ("Похоже на стойкую ошибку (неудач подряд: {0}). " -f $failStreak +
                        "Проверьте VPS/порт/ключ. Следующая попытка через $delay с.")
        }

        Write-Info ("Пауза {0} с перед повторным подключением..." -f $delay)
        Start-Sleep -Seconds $delay
    }
}

# ==============================================================================
#  ТОЧКА ВХОДА
# ==============================================================================

# Защита от взаимоисключающих режимов.
if ($Install -and $Uninstall) {
    Write-Err "Нельзя одновременно указывать -Install и -Uninstall."
    exit 1
}

# Удаление задачи не требует наличия ssh — обрабатываем первым.
if ($Uninstall) {
    Uninstall-TunnelTask
    exit 0
}

# Дальше любой режим (Install или запуск) требует клиента ssh.
if (-not (Test-SshAvailable)) {
    exit 1
}

if ($Install) {
    Install-TunnelTask
    exit 0
}

# Режим по умолчанию: поднять туннель и держать его живым.
Start-TunnelLoop
