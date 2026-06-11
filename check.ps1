# === Скрипт автоматического аудита системы под Windows (v2.0 - Smart Filter) ===
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

# Поиск процесса игры
$Process = Get-Process | Where-Object { $_.Name -match "cstrike|cs2|hl2" } | Select-Object -First 1
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

foreach ($mod in $Process.Modules) {
    $path = $mod.FileName
    if ([string]::IsNullOrWhiteSpace($path)) { continue }

    # Проверка цифровой подписи
    $sig = Get-AuthenticodeSignature $path
    $isSigned = ($sig.Status -eq "Valid")
    $signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "Unknown" }

    # Белый список проверенных вендоров (Microsoft, Valve, драйверы и периферия)
    if ($isSigned -and ($signer -match "Microsoft|Valve|Advanced Micro Devices|NVIDIA|Intel|Logitech|Razer|Corsair|Realtek")) {
        continue # Полностью доверяем, пропускаем
    }

    # Если мы здесь, значит DLL от неизвестного автора или без подписи
    $SuspiciousModules += [PSCustomObject]@{
        ModuleName = $mod.ModuleName
        Path       = $path
        Signed     = $isSigned
        Signer     = $signer
    }
}

if ($SuspiciousModules.Count -gt 0) {
    Write-Host "⚠ НАЙДЕНЫ СТОРОННИЕ ИЛИ НЕПОДПИСАННЫЕ БИБЛИОТЕКИ:" -ForegroundColor Yellow
    foreach ($m in $SuspiciousModules) {
        if (!$m.Signed) {
            Write-Host "  ❌ НЕПОДПИСАННАЯ DLL (Критично!): $($m.ModuleName) -> $($m.Path)" -ForegroundColor Red
            $SCORE += 35
        } else {
            Write-Host "  ℹ️ Сторонний модуль (Подписан): $($m.ModuleName) (Автор: $($m.Signer))" -ForegroundColor Yellow
            $SCORE += 5
        }
    }
} else {
    Write-Host "✅ В память загружены только доверенные системные библиотеки и файлы игры." -ForegroundColor Green
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
        Write-Host "✅ Логи Prefetch стабильны ($prefetchCount записей). Следов экстренной зачистки нет." -ForegroundColor Green
    }
}

# 3. ПОИСК СВЕЖИХ ИСПОЛНЯЕМЫХ ФАЙЛОВ ВО ВРЕМЕННЫХ ДИРЕКТОРИЯХ
Print-Header "АНАЛИЗ ВРЕМЕННЫХ ПАПОК (ЗА ПОСЛЕДНИЕ 24 ЧАСА)"
$PathsToCheck = @("$env:USERPROFILE\Downloads", "$env:TEMP", "$env:APPDATA")
$RecentFiles = Get-ChildItem -Path $PathsToCheck -Include *.exe, *.dll, *.bat -Recurse -File -ErrorAction SilentlyContinue |
               Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) }

if ($RecentFiles) {
    Write-Host "ℹ️ Найдены свежие файлы (Обычные обновления или загрузки, требует визуального контроля):" -ForegroundColor Cyan
    $RecentFiles | Select-Object Name, LastWriteTime | Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor Cyan
    # Баллы за это больше не начисляем, так как Telegram и браузеры обновляются постоянно
} else {
    Write-Host "✅ Свежих исполняемых файлов во временных папках не обнаружено." -ForegroundColor Green
}

# 4. СЛЕДЫ В DNS-КЭШЕ (ИСТОРИЯ ЗАПРОСОВ К САЙТАМ ЧИТОВ)
Print-Header "АНАЛИЗ СИСТЕМНОГО DNS-КЭША"
$DnsTriggers = "cheat|hack|loader|inject|midnight|interium|ezfrags|aimjunkies"
$DnsCache = Get-DnsClientCache | Where-Object { $_.EntryName -match $DnsTriggers }

if ($DnsCache) {
    Write-Host "🚨 ОБНАРУЖЕНЫ СЛЕДЫ ЗАПРОСОВ К ЧИТ-ДОМЕНАМ В КЭШЕ:" -ForegroundColor Red
    $DnsCache | Select-Object EntryName, Type, Status | Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor Red
    $SCORE += 40
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
    Write-Host "✅ СИСТЕМА ЧИСТА. Подозрительных активностей в памяти и логах не найдено." -ForegroundColor Green
} elseif ($SCORE -lt 30) {
    Write-Host "⚠ ЖЕЛТЫЙ УРОВЕНЬ. Есть отклонения (возможно, несистемная DLL). Требуется анализ демо-записи." -ForegroundColor Yellow
} else {
    Write-Host "❌ ВЫСОКИЙ УРОВЕНЬ УГРОЗЫ! Обнаружены маркеры использования стороннего ПО или зачистки ПК." -ForegroundColor Red
}
Write-Host "=========================================================`n" -ForegroundColor Cyan
