# === CSS FORENSIC AUDITOR (TIMED FORENSICS BUILD) ===
$SCORE = 0

function Write-Header($text) { Write-Host "`n▶ $text" -ForegroundColor Cyan }

# 1. ADMIN CHECK
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[-] ERROR: RUN POWERSHELL AS ADMINISTRATOR!" -ForegroundColor Red
    Read-Host "Press Enter to exit..."
    return
}

# 2. NT RESUME PROCESS (Win32 API)
$TypeDefinition = '[DllImport("ntdll.dll")] public static extern int NtResumeProcess(IntPtr handle);'
$NtDll = Add-Type -MemberDefinition $TypeDefinition -Name "NtDllMethods" -PassThru -ErrorAction SilentlyContinue

# Find active process
$Proc = Get-Process | Where-Object { $_.ProcessName -match "hl2|cstrike" } | Select-Object -First 1

if (!$Proc) {
    Write-Host "[-] ERROR: Game process (hl2/cstrike) not found! Run the game first." -ForegroundColor Red
    Read-Host "Press Enter to exit..."
    return
}

# Resume if frozen
try { $null = $NtDll::NtResumeProcess($Proc.Handle) } catch {}

# Paths extraction
$ExactExePath = $Proc.MainModule.FileName
$GamePath = Split-Path $ExactExePath
$BinPath = Join-Path $GamePath "bin"

Clear-Host
Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host "          CSS FORENSIC AUDITOR (TIMED BUILD)             " -ForegroundColor Cyan
Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host "ACTIVE PROCESS: $($Proc.ProcessName) (PID: $($Proc.Id))" -ForegroundColor Green
Write-Host "TARGET CLIENT : $GamePath" -ForegroundColor Yellow
Write-Host "EXE PATH      : $ExactExePath" -ForegroundColor Gray

# 3. EXPANDED CORE HASH DATABASE
$AllowedHashes = @{
    "engine.dll" = @(
        "A7401E5338D64860D421A20A38166D4678880A183889B66348D2A1C3E042784A", 
        "F639D2440DDB5809E114E6BCFEEF7B998E814C1CD852BEDD776D189E00EE700A", 
        "536EAB44AED8EA4F25DA2CBC090570BCEB89AB05A7DC2CD65AF8B97A296E6771"  
    )
    "tier0.dll"  = @(
        "0C1F82E647DE026EE30AA1F2948E5CDBA680FFA62FE1CA17FD6A5F2CF6BA2DF5", 
        "3E8CE15C79A0DCC5FA5E7C9B94F0DEC3835FF31B7C18D823A50FFA0EF00AAEB8"  
    )
    "inputsystem.dll" = @(
        "223F348A1FE255C02879BA8AE1549E5BDD65608894218B2AD6166E99E6A0F14A",
        "9178739DAF6B2B37CE8A305080818B767123BF8A5C64CE3001083AEF48B68EFD"
    )
    "filesystem_stdio.dll" = @(
        "7CE8608C7EC37E5266857E47A1C6D22087A2C5F084ED5F68BBF1C22B36C8B9A8",
        "2B65A4063A633790FEEB8B48A20289A1D3F2503B67FC5369686235C3707C52E3"
    )
    "vstdlib.dll" = @(
        "BBB9A77F6845FC0BD657F9A69C5B97AF946774F5A42F6D52BB9888952C9FD1F9",
        "DF993D8653DF1A21FE3CD69C1EF80E305020FBC13DF8EC91D91A687C79EDCF54"
    )
}

# 4. DLL INTEGRITY AUDIT
Write-Header "CHECKING CRITICAL SYSTEM CORRIDORS..."
foreach ($entry in $AllowedHashes.GetEnumerator()) {
    $FilePath = Join-Path $BinPath $entry.Key
    if (Test-Path $FilePath) {
        $CurrentHash = (Get-FileHash $FilePath -Algorithm SHA256).Hash
        
        if ($entry.Value -notcontains $CurrentHash) {
            if ($entry.Value.Count -eq 1 -and $Proc.ProcessName -notmatch "win64") {
                Write-Host "  [?] SKIP: $($entry.Key) (x32 client detected)" -ForegroundColor Yellow
            } else {
                Write-Host "  [-] MODIFIED: $($entry.Key)" -ForegroundColor Red
                Write-Host "      Unknown Hash: $CurrentHash" -ForegroundColor Gray
                $SCORE += 100
            }
        } else {
            Write-Host "  [+] $($entry.Key) - ORIGINAL OK" -ForegroundColor Green
        }
    } else {
        if ($entry.Key -match "engine|tier0") {
            Write-Host "  [-] CRITICAL: $($entry.Key) missing!" -ForegroundColor Red
            $SCORE += 100
        } else {
            Write-Host "  [!] WARNING: $($entry.Key) not found in bin folder!" -ForegroundColor Yellow
        }
    }
}

# 5. SYSTEM FORENSICS (Продвинутый аудит USB с таймштампами)
Write-Header "USB STORAGE HISTORY (TOP 10 MOST RECENT):"

# Опрашиваем PnP-устройства накопителей через системное API
$USBDevices = Get-PnpDevice | Where-Object { $_.InstanceId -like "USBSTOR*" } | ForEach-Object {
    $Arrival = ($_ | Get-PnpDeviceProperty -KeyName "DEVPKEY_Device_LastArrivalDate" -ErrorAction SilentlyContinue).Data
    [PSCustomObject]@{
        FriendlyName  = $_.FriendlyName
        LastConnected = if ($Arrival) { $Arrival } else { [DateTime]::MinValue }
    }
}

if ($USBDevices) {
    # Сортируем от самых свежих к старым и берем топ-10
    $USBDevices | Sort-Object LastConnected -Descending | Select-Object -First 10 | ForEach-Object {
        $TimeStr = if ($_.LastConnected -eq [DateTime]::MinValue) { "Unknown Timestamp" } else { $_.LastConnected.ToString("yyyy-MM-dd HH:mm:ss") }
        
        # Если флешка была подключена в течение последних 24 часов — подсветим её желтым для внимания
        if ($_.LastConnected -gt (Get-Date).AddDays(-1)) {
            Write-Host "  [USB] $($_.FriendlyName) | Connected: $TimeStr (RECENT!)" -ForegroundColor Yellow
        } else {
            Write-Host "  [USB] $($_.FriendlyName) | Connected: $TimeStr" -ForegroundColor Gray
        }
    }
} else {
    Write-Host "  No USB history records available." -ForegroundColor Gray
}

# 6. RECENT FILES
Write-Header "RECENT FILES (LAST 60 MIN IN TEMP/DOWNLOADS):"
$Recent = Get-ChildItem -Path "$env:TEMP", "$env:USERPROFILE\Downloads" -Include *.exe, *.dll, *.bat, *.sys -Recurse -ErrorAction SilentlyContinue | 
          Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-60) }

if ($Recent) {
    $Recent | Select-Object Name, LastWriteTime | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
} else {
    Write-Host "  No suspicious files found in the last hour." -ForegroundColor Green
}

# FINAL VERDICT
Write-Header "FINAL VERDICT"
if ($SCORE -gt 0) {
    Write-Host "[-] DETECTED: MODIFIED FILES OR MEMORY INJECTION! USE HEX EDITOR." -ForegroundColor Red
} else {
    Write-Host "[+] VERDICT: CLIENT AND SYSTEM ARE CLEAN" -ForegroundColor Green
}

Read-Host "`nAnalysis complete. Press Enter to close..."