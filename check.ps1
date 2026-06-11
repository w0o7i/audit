# === Скрипт автоматического аудита системы под Windows ===
$ErrorActionPreference = "SilentlyContinue"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$SCORE = 0

function Print-Header($text) {
    Write-Host "`n▶ $text" -ForegroundColor Cyan -BackgroundColor Black
}

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "🚨 КРИТИЧЕСКАЯ ОШИБКА: Запустите PowerShell от ИМЕНИ АДМИНИСТРАТОРА!" -ForegroundColor Red
    return
}

# Поиск процесса игры (CS:S, CS2 или старые версии)
$Process = Get-Process | Where-Object { $_.Name -match "cstrike|cs2" } | Select-Object -First 1
if (!$Process) {
    Write-Host "❌ Ошибка: Процесс игры не найден! Убедитесь, что игра запущена." -ForegroundColor Red
    return
}

Clear-Host
Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host "        СИСТЕМНЫЙ АУДИТ И БЕЗОПАСНОСТЬ ПРОЦЕССА          " -ForegroundColor Cyan
Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host "Целевой процесс: $($Process.ProcessName).exe (PID: $($Process.Id))" -ForegroundColor White
Write-Host "Время проверки: $(Get-Date)" -ForegroundColor White

# 1. АНАЛИЗ ДИГИТАЛЬНЫХ ПОДПИСЕЙ И МОДУЛЕЙ (DLL)
Print-Header "АНАЛИЗ ЗАГРУЖЕННЫХ БИБЛИОТЕК (MODULES)"
$SuspiciousModules = @()
$AllowedPaths = "C:\Windows|steamapps|Steam\|bin\win64"

foreach ($mod in $Process.Modules) {
    $path = $mod.FileName
    if ($path -and ($path -notmatch $AllowedPaths)) {
        # Быстрая проверка цифровой подписи для сторонних DLL
        $sig = Get-AuthenticodeSignature $path
        $isSigned = $sig.Status -eq "Valid"
        
        $SuspiciousModules += [PSCustomObject]@{
            ModuleName = $mod.ModuleName
            Path       = $path
            Signed     = $isSigned
            Signer     = $sig.SignerCertificate.Subject
        }
    }
}

if ($SuspiciousModules.Count -gt 0) {
    Write-Host "⚠ НАЙДЕНЫ СТОРОННИЕ БИБЛИОТЕКИ ВНЕ СИСТЕМНЫХ ПУТЕЙ:" -ForegroundColor Yellow
    foreach ($m in $SuspiciousModules) {
        if (!$m.Signed) {
            Write-Host "  ❌ НЕПОДПИСАННАЯ DLL: $($m.ModuleName) -> $($m.Path)" -ForegroundColor Red
            $SCORE += 25
        } else {
            Write-Host "  ℹ️ Модуль вне путей (Подписан): $($m.ModuleName) ($($m.Signer))" -ForegroundColor Yellow
            $SCORE += 5
        }
    }
} else {
    Write-Host "✅ Все загруженные DLL ведут в доверенные системные/Steam директории." -ForegroundColor Green
}

# 2. ДЕТЕКЦИЯ ЭКСТРЕННОЙ ОЧИСТКИ (FORENSICS)
Print-Header "КРИМИНАЛИСТИЧЕСКИЙ АНАЛИЗ СЛЕДОВ ОЧИСТКИ"
$prefetchPath = "$env:SystemRoot\Prefetch"
if (Test-Path $prefetchPath) {
    $prefetchCount = (Get-ChildItem $prefetchPath -Filter "*.pf").Count
    if ($prefetchCount -lt 15) {
        Write-Host "🚨 ТРЕВОГА: Папка Prefetch практически пуста ($prefetchCount файлов)! Следы запущенных программ были намеренно стерты батником перед проверкой." -ForegroundColor Red
        $SCORE += 45
    } else {
        Write-Host "✅ Логи Prefetch стабильны ($prefetchCount записей)." -ForegroundColor Green
    }
}

# 3. ПОИСК СВЕЖИХ ИСПОЛНЯЕМЫХ ФАЙЛОВ ВО ВРЕМЕННЫХ ДИРЕКТОРИЯХ
Print-Header "АНАЛИЗ ВРЕМЕННЫХ ПАПОК (ЗА ПОСЛЕДНИЕ 24 ЧАСА)"
$PathsToCheck = @("$env:USERPROFILE\Downloads", "$env:TEMP", "$env:APPDATA")
$RecentFiles = Get-ChildItem -Path $PathsToCheck -Include *.exe, *.dll, *.sys, *.bat -Recurse -File -ErrorAction SilentlyContinue |
               Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) }

if ($RecentFiles) {
    Write-Host "⚠ ОБНАРУЖЕНЫ СВЕЖИЕ ИСПОЛНЯЕМЫЕ ФАЙЛЫ / СКРИПТЫ:" -ForegroundColor Yellow
    $RecentFiles | Select-Object Name, LastWriteTime, Length, FullName | Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor Yellow
    $SCORE += 15
} else {
    Write-Host "✅ Свежих подозрительных файлов во временных папках не обнаружено." -ForegroundColor Green
}

# 4. СЛЕДЫ В DNS-КЭШЕ (ИСТОРИЯ ЗАПРОСОВ К САЙТАМ ЧИТОВ)
Print-Header "АНАЛИЗ СИСТЕМНОГО DNS-КЭША"
$DnsTriggers = "cheat|hack|loader|inject|midnight|interium|ezfrags|aimjunkies"
$DnsCache = Get-DnsClientCache | Where-Object { $_.EntryName -match $DnsTriggers }

if ($DnsCache) {
    Write-Host "🚨 ОБНАРУЖЕНЫ СЛЕДЫ ЗАПРОСОВ КРЕМИНАЛЬНЫХ ДОМЕНОВ В КЭШЕ:" -ForegroundColor Red
    $DnsCache | Select-Object EntryName, Type, Status | Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor Red
    $SCORE += 35
} else {
    Write-Host "✅ В DNS-кэше нет упоминаний известных cheat-ресурсов." -ForegroundColor Green
}

# 5. СЕТЕВАЯ АКТИВНОСТЬ ПРОЦЕССА ИГРЫ
Print-Header "СЕТЕВАЯ АКТИВНОСТЬ ПРОЦЕССА"
$NetConnections = Get-NetTCPConnection -OwningProcess $Process.Id
if ($NetConnections) {
    $Listening = $NetConnections | Where-Object { $_.State -eq "Listen" }
    if ($Listening) {
        Write-Host "🚨 ВНИМАНИЕ: Процесс игры открыл порт на прослушивание (State: LISTEN)!" -ForegroundColor Red
        $Listening | Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor Red
        $SCORE += 30
    } else {
        Write-Host "✅ Сетевая активность штатная (Только исходящие игровые соединения)." -ForegroundColor Green
    }
} else {
    Write-Host "ℹ️ Активных сетевых сокетов у процесса сейчас не зафиксировано." -ForegroundColor Gray
}

# ИТОРГОВЫЙ ВЕРДИКТ
Print-Header "ИТОГОВЫЙ ВЕРДИКТ СИСТЕМЫ"
Write-Host "Индекс потенциальной угрозы системы: $SCORE" -ForegroundColor White

if ($SCORE -eq 0) {
    Write-Host "✅ СИСТЕМА АБСОЛЮТНО ЧИСТА. Угроз или следов зачистки не обнаружено." -ForegroundColor Green
} elseif ($SCORE -lt 30) {
    Write-Host "⚠ ЕСТЬ СЛЕДЫ ДЛЯ РАЗБИРАТЕЛЬСТВА. Рекомендуется тщательный покадровый анализ демо-записи." -ForegroundColor Yellow
} else {
    Write-Host "❌ ВЫСОКИЙ УРОВЕНЬ УГРОЗЫ! Обнаружены несовместимые с честной игрой модификации памяти, следы очистки логов или обращения к лоадерам." -ForegroundColor Red
}
Write-Host "=========================================================`n" -ForegroundColor Cyan
