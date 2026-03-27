#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Health Check & Update Cache Maintenance Script

.DESCRIPTION
    1. Detects the Windows OS version and build
    2. Validates the OS is not End-of-Life (EOL)
    3. Confirms the system volume has at least 20 GB of free space
    4. Checks whether Windows Update cache folders are older than 30 days;
       if so, deletes them and runs a DISM /RestoreHealth repair

.NOTES
    Must be run as Administrator.
    Tested against: Windows 10 (all supported versions), Windows 11, Windows Server 2019/2022/2025
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
function Write-Header {
    param([string]$Text)
    $line = '─' * 60
    Write-Host "`n$line" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "$line" -ForegroundColor Cyan
}

function Write-Pass   { param([string]$Msg) Write-Host "  [PASS] $Msg" -ForegroundColor Green  }
function Write-Fail   { param([string]$Msg) Write-Host "  [FAIL] $Msg" -ForegroundColor Red    }
function Write-Warn   { param([string]$Msg) Write-Host "  [WARN] $Msg" -ForegroundColor Yellow }
function Write-Info   { param([string]$Msg) Write-Host "  [INFO] $Msg" -ForegroundColor White  }

# ─────────────────────────────────────────────
# EOL Reference Table
# Key   = ProductName substring (lowercase)
# Value = [ordered] hashtable of Build -> EOL date
# ─────────────────────────────────────────────
$EolDates = @{

    # Windows 10 – Home/Pro channel (feature update EOL dates)
    'windows 10' = [ordered]@{
        1507 = [datetime]'2017-05-09'
        1511 = [datetime]'2017-10-10'
        1607 = [datetime]'2018-04-10'
        1703 = [datetime]'2018-10-09'
        1709 = [datetime]'2019-04-09'
        1803 = [datetime]'2019-11-12'
        1809 = [datetime]'2020-05-12'
        1903 = [datetime]'2019-12-08'
        1909 = [datetime]'2022-05-10'
        2004 = [datetime]'2021-12-14'
        2009 = [datetime]'2022-05-10'   # 20H2
        2104 = [datetime]'2022-12-13'   # 21H1
        2110 = [datetime]'2023-06-13'   # 21H2 Home/Pro
        2210 = [datetime]'2024-06-11'   # 22H2
        # 22H2 LTSC / Enterprise extended support ends 2025-10-14
    }

    # Windows 11 – Home/Pro channel
    'windows 11' = [ordered]@{
        2009 = [datetime]'2023-10-10'   # 21H2
        2210 = [datetime]'2024-10-08'   # 22H2
        2310 = [datetime]'2025-11-11'   # 23H2
        # 24H2 – currently supported
    }

    # Windows Server
    'windows server 2008'    = [ordered]@{ 0 = [datetime]'2020-01-14' }
    'windows server 2012'    = [ordered]@{ 0 = [datetime]'2023-10-10' }
    'windows server 2016'    = [ordered]@{ 0 = [datetime]'2027-01-12' }
    'windows server 2019'    = [ordered]@{ 0 = [datetime]'2029-01-09' }
    'windows server 2022'    = [ordered]@{ 0 = [datetime]'2031-10-14' }
    'windows server 2025'    = [ordered]@{ 0 = [datetime]'2034-10-10' }
}

# ─────────────────────────────────────────────
# STEP 1 – Detect OS
# ─────────────────────────────────────────────
Write-Header 'STEP 1 – Detect Windows Version'

$os          = Get-CimInstance -ClassName Win32_OperatingSystem
$productName = $os.Caption                      # e.g. "Microsoft Windows 10 Pro"
$buildNumber = [int]$os.BuildNumber             # e.g. 19045
$version     = $os.Version                      # e.g. "10.0.19045"

# Map build number → Display version string
$BuildToVersion = @{
    # Windows 10
    10240 = '1507'; 10586 = '1511'; 14393 = '1607'; 15063 = '1703'
    16299 = '1709'; 17134 = '1803'; 17763 = '1809'; 18362 = '1903'
    18363 = '1909'; 19041 = '2004'; 19042 = '20H2'; 19043 = '21H1'
    19044 = '21H2'; 19045 = '22H2'
    # Windows 11
    22000 = '21H2'; 22621 = '22H2'; 22631 = '23H2'; 26100 = '24H2'
}

$displayVersion = if ($BuildToVersion.ContainsKey($buildNumber)) {
    $BuildToVersion[$buildNumber]
} else {
    "Build $buildNumber"
}

Write-Info "Product   : $productName"
Write-Info "Version   : $displayVersion  (Build $buildNumber)"
Write-Info "Full ver  : $version"
Write-Info "Arch      : $($os.OSArchitecture)"

# ─────────────────────────────────────────────
# STEP 2 – EOL Check
# ─────────────────────────────────────────────
Write-Header 'STEP 2 – End-of-Life Check'

$today        = [datetime]::Today
$productLower = $productName.ToLower()
$eolDate      = $null
$matchedKey   = $null

foreach ($key in $EolDates.Keys) {
    if ($productLower -like "*$key*") {
        $matchedKey = $key
        break
    }
}

if ($null -eq $matchedKey) {
    Write-Warn "No EOL record found for '$productName'. Manual verification recommended."
} else {
    $versionMap = $EolDates[$matchedKey]

    # Server products use a single entry (key 0); client products use build-mapped keys
    if ($versionMap.Contains(0)) {
        $eolDate = $versionMap[0]
    } else {
        # Find the version entry that matches the current display version (numeric part)
        foreach ($ver in $versionMap.Keys) {
            if ($displayVersion -like "*$ver*") {
                $eolDate = $versionMap[$ver]
                break
            }
        }
    }

    if ($null -eq $eolDate) {
        Write-Warn "Could not map version '$displayVersion' to an EOL date. Verify manually."
    } elseif ($today -gt $eolDate) {
        Write-Fail "This Windows version reached End-of-Life on $($eolDate.ToString('yyyy-MM-dd'))."
        Write-Fail "The system is NO LONGER RECEIVING SECURITY UPDATES. Upgrade immediately."
    } else {
        $daysLeft = ($eolDate - $today).Days
        if ($daysLeft -le 90) {
            Write-Warn "EOL date: $($eolDate.ToString('yyyy-MM-dd'))  ($daysLeft days remaining). Plan your upgrade soon."
        } else {
            Write-Pass "Supported until $($eolDate.ToString('yyyy-MM-dd'))  ($daysLeft days remaining)."
        }
    }
}

# ─────────────────────────────────────────────
# STEP 3 – Disk Space Check (≥ 20 GB free)
# ─────────────────────────────────────────────
Write-Header 'STEP 3 – System Volume Free Space (≥ 20 GB Required)'

$MinFreeGB     = 20
$systemDrive   = $env:SystemDrive          # e.g. C:
$disk          = Get-PSDrive -Name ($systemDrive.TrimEnd(':'))
$freeGB        = [math]::Round($disk.Free / 1GB, 2)
$totalGB       = [math]::Round(($disk.Used + $disk.Free) / 1GB, 2)
$usedGB        = [math]::Round($disk.Used / 1GB, 2)

Write-Info "Drive     : $systemDrive"
Write-Info "Total     : $totalGB GB"
Write-Info "Used      : $usedGB GB"
Write-Info "Free      : $freeGB GB"

if ($freeGB -lt $MinFreeGB) {
    Write-Fail "Free space ($freeGB GB) is below the $MinFreeGB GB minimum."
    Write-Fail "Free up space before proceeding; the DISM repair step will be SKIPPED."
    $diskOk = $false
} else {
    Write-Pass "$freeGB GB free — meets the $MinFreeGB GB requirement."
    $diskOk = $true
}

# ─────────────────────────────────────────────
# STEP 4 – Windows Update Cache Age Check
# ─────────────────────────────────────────────
Write-Header 'STEP 4 – Windows Update Cache Check (30-Day Threshold)'

# Primary cache folders used by Windows Update / CBS
$CacheFolders = @(
    "$env:SystemRoot\SoftwareDistribution\Download",
    "$env:SystemRoot\SoftwareDistribution\DataStore",
    "$env:SystemRoot\Logs\CBS"
)

$MaxAgeDays   = 30
$cutoff       = (Get-Date).AddDays(-$MaxAgeDays)
$needsCleanup = $false

foreach ($folder in $CacheFolders) {
    if (-not (Test-Path $folder)) {
        Write-Info "Folder not found (skipping): $folder"
        continue
    }

    $dirInfo  = Get-Item $folder
    $ageLabel = "created $($dirInfo.CreationTime.ToString('yyyy-MM-dd'))"

    if ($dirInfo.CreationTime -lt $cutoff) {
        Write-Warn "$folder  ← $ageLabel  [OLDER than $MaxAgeDays days]"
        $needsCleanup = $true
    } else {
        Write-Pass "$folder  ← $ageLabel"
    }
}

# ─────────────────────────────────────────────
# STEP 5 – Cache Cleanup + DISM Repair
# ─────────────────────────────────────────────
if ($needsCleanup) {
    Write-Header 'STEP 5 – Deleting Stale Cache & Running DISM Repair'

    if (-not $diskOk) {
        Write-Warn 'Skipping DISM repair: insufficient disk space (see Step 3).'
    } else {
        # Stop Windows Update service before touching its folders
        Write-Info 'Stopping Windows Update service (wuauserv)...'
        Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
        Stop-Service -Name bits     -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3

        foreach ($folder in $CacheFolders) {
            if (Test-Path $folder) {
                try {
                    Write-Info "Removing: $folder"
                    Remove-Item -Path $folder -Recurse -Force
                    Write-Pass "Deleted: $folder"
                } catch {
                    Write-Warn "Could not fully remove '$folder': $_"
                }
            }
        }

        # Restart Windows Update so it can recreate the folders
        Write-Info 'Restarting Windows Update service...'
        Start-Service -Name wuauserv -ErrorAction SilentlyContinue
        Start-Service -Name bits     -ErrorAction SilentlyContinue

        # Run DISM component store repair
        Write-Info 'Running DISM /Online /Cleanup-Image /RestoreHealth ...'
        Write-Info '(This may take 10–30 minutes depending on system state)'

        $dismLog  = "$env:SystemRoot\Logs\DISM\dism_healthcheck_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        $dismArgs = "/Online /Cleanup-Image /RestoreHealth /LogPath:`"$dismLog`""

        $proc = Start-Process -FilePath 'dism.exe' `
                              -ArgumentList $dismArgs `
                              -Wait -PassThru -NoNewWindow

        if ($proc.ExitCode -eq 0) {
            Write-Pass "DISM repair completed successfully. Log: $dismLog"
        } else {
            Write-Fail "DISM exited with code $($proc.ExitCode). Review log: $dismLog"
        }
    }
} else {
    Write-Header 'STEP 5 – Cache Cleanup & DISM Repair'
    Write-Pass "All cache folders are within $MaxAgeDays days. No cleanup or DISM repair needed."
}

# ─────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────
Write-Header 'SUMMARY'
Write-Info "OS          : $productName  ($displayVersion)"
Write-Info "Free Space  : $freeGB GB on $systemDrive"
Write-Info "Cache Clean : $(if ($needsCleanup) { 'Cleanup performed' } else { 'No action required' })"
Write-Info "DISM        : $(if ($needsCleanup -and $diskOk) { 'Repair executed' } elseif ($needsCleanup -and -not $diskOk) { 'Skipped – low disk' } else { 'Not required' })"
Write-Host ''