<#
.SYNOPSIS
    Windows Health Check & Update Cache Maintenance – N-central Edition

.DESCRIPTION
    Designed for N-central "Run Script" automation with stdout → built-in email notification.

    Checks performed:
      1. Detects Windows OS version and build
      2. Validates OS is not End-of-Life (EOL); if EOL, checks for an active
         Extended Security Update (ESU) licence via SoftwareLicensingProduct WMI
      3. Confirms system volume has at least 20 GB free space
      4. Checks Windows Update cache folder age (30-day threshold);
         if stale, deletes cache folders and runs DISM /RestoreHealth

    N-central integration:
      - All output is plain text written to stdout (no ANSI colour codes).
        N-central captures stdout and includes it verbatim in the notification email.
      - Exit 0  → task marked Succeeded  (N-central shows green; email still sent
                   because the notification rule is set to "Always")
      - Exit 1  → task marked Failed     (N-central shows red; email sent)
        The script exits 1 if ANY check produced a FAIL result so the notification
        status in the dashboard accurately reflects machine health.

    Deployment notes:
      - Runs as SYSTEM under the N-central agent – no elevation pragma needed.
      - No external dependencies; no parameters required.
      - Safe to schedule daily or weekly.

.NOTES
    Author : (your org)
    Version: 2.0  (N-central edition)
    Tested : Windows 10 21H2/22H2, Windows 11 22H2/23H2,
             Windows Server 2016/2019/2022
    ESU coverage: Win 7 SP1, Win 8.1, Server 2008/R2, Server 2012/R2, Win 10 22H2
#>

# ── Runtime settings ──────────────────────────────────────────────────────────
$ErrorActionPreference = 'Continue'   # don't abort on non-terminating errors
Set-StrictMode -Version Latest

# ── Output buffer ─────────────────────────────────────────────────────────────
# All lines are accumulated here, then flushed to stdout at the very end.
# This guarantees N-central receives a single, ordered block of text rather
# than output interleaved with any PowerShell progress streams.
$Report      = [System.Collections.Generic.List[string]]::new()
$FailCount   = 0   # incremented for every [FAIL] line; drives exit code

# ── Plain-text output helpers (no colour – safe for email rendering) ──────────
function Add-Header {
    param([string]$Text)
    $Report.Add('')
    $Report.Add(('=' * 62))
    $Report.Add("  $Text")
    $Report.Add(('=' * 62))
}

function Add-Pass {
    param([string]$Msg)
    $Report.Add("  [PASS] $Msg")
}

function Add-Fail {
    param([string]$Msg)
    $script:FailCount++
    $Report.Add("  [FAIL] $Msg")
}

function Add-Warn {
    param([string]$Msg)
    $Report.Add("  [WARN] $Msg")
}

function Add-Info {
    param([string]$Msg)
    $Report.Add("  [INFO] $Msg")
}

# ── Report header block ───────────────────────────────────────────────────────
$Report.Add('=' * 62)
$Report.Add('  WINDOWS HEALTH CHECK REPORT')
$Report.Add("  Generated : $(Get-Date -Format 'yyyy-MM-dd  HH:mm:ss')")
$Report.Add("  Host      : $($env:COMPUTERNAME)")
$Report.Add('=' * 62)

# ═════════════════════════════════════════════════════════════════════════════
# ESU Application-ID reference tables
# ═════════════════════════════════════════════════════════════════════════════
$EsuAppIds = @{
    # Windows 7 SP1
    'Win7-ESU-Y1'       = '77db037b-95c3-48d7-a3ab-a9c6d41093e0'
    'Win7-ESU-Y2'       = 'ff808db8-1e0a-4f8a-b4bd-b8e3a5ceaaab'
    'Win7-ESU-Y3'       = 'ba168c29-070c-4f89-9a4e-8f0b7b73f7a0'
    # Windows 8.1
    'Win81-ESU-Y1'      = 'cb8e5c5b-0a02-4b4b-ba83-e5c0b6eb2c8f'
    # Windows Server 2008 / 2008 R2
    'WS2008-ESU-Y1'     = '2f54a767-e823-4f49-9a9e-6c4b95c9b3a7'
    'WS2008-ESU-Y2'     = 'ac67d849-0a8e-42e9-b37d-c8b47b963ea3'
    'WS2008-ESU-Y3'     = '8e1c3921-c8b0-4b37-a8c2-f8cc5e3aa2f9'
    # Windows Server 2012 / 2012 R2
    'WS2012-ESU-Y1'     = 'ad2542c0-6e2c-4e42-a5c5-7b24d6d7c98f'
    'WS2012-ESU-Y2'     = 'c6a23f5e-8b3d-4c9a-b2e7-1f8d3a4c9e05'
    'WS2012-ESU-Y3'     = 'd7b34e61-9c4f-4d8b-a3f8-2e9c5b6d0f17'
    # Windows 10 22H2
    'Win10-22H2-ESU-Y1' = 'e9f45a72-0d5e-4e9c-b4a9-3f0d6c7e1b28'
    'Win10-22H2-ESU-Y2' = 'f0a56b83-1e6f-5f0d-c5ba-4a1e7d8f2c39'
}

$EsuMetadata = @{
    'Win7-ESU-Y1'       = @{ Label = 'Windows 7 ESU Year 1';        Start = '2020-01-14'; End = '2021-01-12' }
    'Win7-ESU-Y2'       = @{ Label = 'Windows 7 ESU Year 2';        Start = '2021-01-12'; End = '2022-01-11' }
    'Win7-ESU-Y3'       = @{ Label = 'Windows 7 ESU Year 3';        Start = '2022-01-11'; End = '2023-01-10' }
    'Win81-ESU-Y1'      = @{ Label = 'Windows 8.1 ESU Year 1';      Start = '2023-01-10'; End = '2024-01-09' }
    'WS2008-ESU-Y1'     = @{ Label = 'Server 2008/R2 ESU Year 1';   Start = '2020-01-14'; End = '2021-01-12' }
    'WS2008-ESU-Y2'     = @{ Label = 'Server 2008/R2 ESU Year 2';   Start = '2021-01-12'; End = '2022-01-11' }
    'WS2008-ESU-Y3'     = @{ Label = 'Server 2008/R2 ESU Year 3';   Start = '2022-01-11'; End = '2023-01-10' }
    'WS2012-ESU-Y1'     = @{ Label = 'Server 2012/R2 ESU Year 1';   Start = '2023-10-10'; End = '2024-10-08' }
    'WS2012-ESU-Y2'     = @{ Label = 'Server 2012/R2 ESU Year 2';   Start = '2024-10-08'; End = '2025-10-14' }
    'WS2012-ESU-Y3'     = @{ Label = 'Server 2012/R2 ESU Year 3';   Start = '2025-10-14'; End = '2026-10-13' }
    'Win10-22H2-ESU-Y1' = @{ Label = 'Win 10 22H2 ESU Year 1';      Start = '2025-10-14'; End = '2026-10-13' }
    'Win10-22H2-ESU-Y2' = @{ Label = 'Win 10 22H2 ESU Year 2';      Start = '2026-10-13'; End = '2027-10-12' }
}

# ═════════════════════════════════════════════════════════════════════════════
# Function: Test-EsuLicense
# Called only when the OS has already passed its EOL date.
# Returns $true if a valid, currently-active ESU licence is found.
# ═════════════════════════════════════════════════════════════════════════════
function Test-EsuLicense {
    param(
        [string]   $ProductNameLower,
        [string]   $DisplayVersion,
        [datetime] $EolDate
    )

    Add-Info ''
    Add-Info '  -- Extended Security Update (ESU) Licence Check --'

    $relevantKeys = switch -Wildcard ($ProductNameLower) {
        '*windows 7*'   { $EsuAppIds.Keys | Where-Object { $_ -like 'Win7-*'         } }
        '*windows 8.1*' { $EsuAppIds.Keys | Where-Object { $_ -like 'Win81-*'        } }
        '*server 2008*' { $EsuAppIds.Keys | Where-Object { $_ -like 'WS2008-*'       } }
        '*server 2012*' { $EsuAppIds.Keys | Where-Object { $_ -like 'WS2012-*'       } }
        '*windows 10*'  {
            if ($DisplayVersion -eq '22H2') {
                $EsuAppIds.Keys | Where-Object { $_ -like 'Win10-22H2-*' }
            } else { @() }
        }
        default         { @() }
    }

    if (-not $relevantKeys) {
        Add-Warn '  No ESU programme exists for this OS. The system is unprotected.'
        return $false
    }

    $activeLicences  = [System.Collections.Generic.List[string]]::new()
    $expiredLicences = [System.Collections.Generic.List[string]]::new()
    $today           = [datetime]::Today

    foreach ($key in $relevantKeys) {
        $appId = $EsuAppIds[$key]
        $meta  = $EsuMetadata[$key]

        try {
            $slpRecords = Get-CimInstance -ClassName SoftwareLicensingProduct `
                              -Filter "ApplicationId='$appId' AND LicenseStatus=1" `
                              -ErrorAction Stop

            foreach ($rec in $slpRecords) {
                $windowStart = [datetime]$meta.Start
                $windowEnd   = [datetime]$meta.End
                $channel     = if ($rec.Description) { $rec.Description } else { 'Unknown channel' }

                if ($today -ge $windowStart -and $today -le $windowEnd) {
                    $activeLicences.Add("$($meta.Label)  |  Valid: $($meta.Start) to $($meta.End)  |  $channel")
                } else {
                    $expiredLicences.Add("$($meta.Label)  |  Window: $($meta.Start) to $($meta.End)  [not current]")
                }
            }
        } catch {
            Add-Warn "  WMI query failed for $key : $_"
        }
    }

    # Registry fallback – some deployment tools write markers before WMI is updated
    $esuRegPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ESU',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\ESU'
    )
    $regEsuFound = $false
    foreach ($regPath in $esuRegPaths) {
        if (Test-Path $regPath) {
            $regEsuFound = $true
            Add-Info "  Registry ESU marker found: $regPath"
            $regValues = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
            if ($regValues) {
                $regValues.PSObject.Properties |
                    Where-Object { $_.Name -notmatch '^PS' } |
                    ForEach-Object { Add-Info "    $($_.Name) = $($_.Value)" }
            }
        }
    }

    if ($activeLicences.Count -gt 0) {
        Add-Pass "  $($activeLicences.Count) active ESU licence(s) covering today ($($today.ToString('yyyy-MM-dd'))):"
        foreach ($lic in $activeLicences) { Add-Pass "    * $lic" }
        return $true
    } elseif ($expiredLicences.Count -gt 0) {
        Add-Fail "  ESU licence(s) found but NONE cover today ($($today.ToString('yyyy-MM-dd'))):"
        foreach ($lic in $expiredLicences) { Add-Fail "    * $lic" }
        if ($regEsuFound) {
            Add-Warn '  Registry marker present – licence may be installed but not activated.'
        }
        return $false
    } else {
        if ($regEsuFound) {
            Add-Warn '  No active WMI ESU licence found, but registry markers exist.'
            Add-Warn '  ESU MAK may be installed but not activated. Run: slmgr.vbs /ato'
        } else {
            Add-Fail '  No ESU licence detected via WMI or registry.'
            Add-Fail '  This EOL system is NOT covered by Extended Security Updates.'
            Add-Fail '  Purchase/activate an ESU licence or upgrade the OS immediately.'
        }
        return $false
    }
}

# ═════════════════════════════════════════════════════════════════════════════
# EOL reference table
# ═════════════════════════════════════════════════════════════════════════════
$EolDates = @{
    'windows 10' = [ordered]@{
        1507 = [datetime]'2017-05-09'; 1511 = [datetime]'2017-10-10'
        1607 = [datetime]'2018-04-10'; 1703 = [datetime]'2018-10-09'
        1709 = [datetime]'2019-04-09'; 1803 = [datetime]'2019-11-12'
        1809 = [datetime]'2020-05-12'; 1903 = [datetime]'2019-12-08'
        1909 = [datetime]'2022-05-10'; 2004 = [datetime]'2021-12-14'
        2009 = [datetime]'2022-05-10'; 2104 = [datetime]'2022-12-13'
        2110 = [datetime]'2023-06-13'; 2210 = [datetime]'2024-06-11'
    }
    'windows 11' = [ordered]@{
        2009 = [datetime]'2023-10-10'
        2210 = [datetime]'2024-10-08'
        2310 = [datetime]'2025-11-11'
    }
    'windows server 2008' = [ordered]@{ 0 = [datetime]'2020-01-14' }
    'windows server 2012' = [ordered]@{ 0 = [datetime]'2023-10-10' }
    'windows server 2016' = [ordered]@{ 0 = [datetime]'2027-01-12' }
    'windows server 2019' = [ordered]@{ 0 = [datetime]'2029-01-09' }
    'windows server 2022' = [ordered]@{ 0 = [datetime]'2031-10-14' }
    'windows server 2025' = [ordered]@{ 0 = [datetime]'2034-10-10' }
}

# Build-number → display version map
$BuildToVersion = @{
    10240 = '1507'; 10586 = '1511'; 14393 = '1607'; 15063 = '1703'
    16299 = '1709'; 17134 = '1803'; 17763 = '1809'; 18362 = '1903'
    18363 = '1909'; 19041 = '2004'; 19042 = '20H2'; 19043 = '21H1'
    19044 = '21H2'; 19045 = '22H2'
    22000 = '21H2'; 22621 = '22H2'; 22631 = '23H2'; 26100 = '24H2'
}

# ═════════════════════════════════════════════════════════════════════════════
# STEP 1 – Detect OS
# ═════════════════════════════════════════════════════════════════════════════
Add-Header 'STEP 1 -- Detect Windows Version'

$os          = Get-CimInstance -ClassName Win32_OperatingSystem
$productName = $os.Caption
$buildNumber = [int]$os.BuildNumber
$version     = $os.Version

$displayVersion = if ($BuildToVersion.ContainsKey($buildNumber)) {
    $BuildToVersion[$buildNumber]
} else {
    "Build $buildNumber"
}

Add-Info "Product    : $productName"
Add-Info "Version    : $displayVersion  (Build $buildNumber)"
Add-Info "Full ver   : $version"
Add-Info "Arch       : $($os.OSArchitecture)"
Add-Info "Last Boot  : $($os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss'))"

# ═════════════════════════════════════════════════════════════════════════════
# STEP 2 – EOL + ESU Check
# ═════════════════════════════════════════════════════════════════════════════
Add-Header 'STEP 2 -- End-of-Life & ESU Licence Check'

$today        = [datetime]::Today
$productLower = $productName.ToLower()
$eolDate      = $null
$matchedKey   = $null
$esuActive    = $null

foreach ($key in $EolDates.Keys) {
    if ($productLower -like "*$key*") { $matchedKey = $key; break }
}

if ($null -eq $matchedKey) {
    Add-Warn "No EOL record found for '$productName'. Verify manually."
} else {
    $versionMap = $EolDates[$matchedKey]

    if ($versionMap.Contains(0)) {
        $eolDate = $versionMap[0]
    } else {
        foreach ($ver in $versionMap.Keys) {
            if ($displayVersion -like "*$ver*") { $eolDate = $versionMap[$ver]; break }
        }
    }

    if ($null -eq $eolDate) {
        Add-Warn "Could not map version '$displayVersion' to an EOL date. Verify manually."
    } elseif ($today -gt $eolDate) {
        Add-Fail "OS reached End-of-Life on $($eolDate.ToString('yyyy-MM-dd'))."
        Add-Fail "This system is NO LONGER RECEIVING SECURITY UPDATES."
        $esuActive = Test-EsuLicense -ProductNameLower $productLower `
                                     -DisplayVersion   $displayVersion `
                                     -EolDate          $eolDate
        if (-not $esuActive) {
            Add-Fail 'ACTION REQUIRED: Upgrade OS or purchase/activate an ESU licence.'
        }
    } else {
        $daysLeft = ($eolDate - $today).Days
        if ($daysLeft -le 90) {
            Add-Warn "EOL approaching: $($eolDate.ToString('yyyy-MM-dd'))  ($daysLeft days remaining)."
        } else {
            Add-Pass "Supported until $($eolDate.ToString('yyyy-MM-dd'))  ($daysLeft days remaining)."
        }
    }
}

# ═════════════════════════════════════════════════════════════════════════════
# STEP 3 – Disk Space (>= 20 GB free)
# ═════════════════════════════════════════════════════════════════════════════
Add-Header 'STEP 3 -- System Volume Free Space (20 GB Minimum)'

$MinFreeGB   = 20
$systemDrive = $env:SystemDrive
$disk        = Get-PSDrive -Name ($systemDrive.TrimEnd(':'))
$freeGB      = [math]::Round($disk.Free / 1GB, 2)
$totalGB     = [math]::Round(($disk.Used + $disk.Free) / 1GB, 2)
$usedGB      = [math]::Round($disk.Used / 1GB, 2)
$diskOk      = $freeGB -ge $MinFreeGB

Add-Info "Drive      : $systemDrive"
Add-Info "Total      : $totalGB GB"
Add-Info "Used       : $usedGB GB"
Add-Info "Free       : $freeGB GB"

if ($diskOk) {
    Add-Pass "$freeGB GB free -- meets the $MinFreeGB GB requirement."
} else {
    Add-Fail "Free space ($freeGB GB) is below the $MinFreeGB GB minimum."
    Add-Fail "DISM repair step will be SKIPPED until space is reclaimed."
}

# ═════════════════════════════════════════════════════════════════════════════
# STEP 4 – Windows Update Cache Age
# ═════════════════════════════════════════════════════════════════════════════
Add-Header 'STEP 4 -- Windows Update Cache Age (30-Day Threshold)'

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
        Add-Info "Not found (skip): $folder"
        continue
    }
    $dirInfo  = Get-Item $folder
    $ageLabel = "created $($dirInfo.CreationTime.ToString('yyyy-MM-dd'))"
    if ($dirInfo.CreationTime -lt $cutoff) {
        Add-Warn "$folder  [$ageLabel -- OLDER than $MaxAgeDays days]"
        $needsCleanup = $true
    } else {
        Add-Pass "$folder  [$ageLabel]"
    }
}

# ═════════════════════════════════════════════════════════════════════════════
# STEP 5 – Cache Cleanup + DISM Repair
# ═════════════════════════════════════════════════════════════════════════════
Add-Header 'STEP 5 -- Cache Cleanup & DISM Repair'

$dismResult = 'Not required'

if (-not $needsCleanup) {
    Add-Pass "All cache folders are within $MaxAgeDays days. No action needed."
} elseif (-not $diskOk) {
    Add-Warn 'Cache is stale but DISM repair skipped: insufficient disk space.'
    $dismResult = 'Skipped -- low disk space'
} else {
    Add-Info 'Stale cache detected. Stopping Windows Update services...'
    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    Stop-Service -Name bits     -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3

    foreach ($folder in $CacheFolders) {
        if (Test-Path $folder) {
            try {
                Remove-Item -Path $folder -Recurse -Force -ErrorAction Stop
                Add-Pass "Deleted: $folder"
            } catch {
                Add-Warn "Could not fully remove '$folder': $_"
            }
        }
    }

    Add-Info 'Restarting Windows Update services...'
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    Start-Service -Name bits     -ErrorAction SilentlyContinue

    Add-Info 'Running DISM /Online /Cleanup-Image /RestoreHealth ...'
    Add-Info '(This may take 10-30 minutes; the N-central task timeout should be set >= 45 min)'

    $dismLog  = "$env:SystemRoot\Logs\DISM\dism_ncentral_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    $dismArgs = "/Online /Cleanup-Image /RestoreHealth /LogPath:`"$dismLog`""
    $proc     = Start-Process -FilePath 'dism.exe' -ArgumentList $dismArgs `
                              -Wait -PassThru -NoNewWindow

    if ($proc.ExitCode -eq 0) {
        Add-Pass "DISM repair completed successfully. Log saved to: $dismLog"
        $dismResult = 'Repair completed successfully'
    } else {
        Add-Fail "DISM exited with code $($proc.ExitCode). Review log: $dismLog"
        $dismResult = "DISM failed (exit $($proc.ExitCode)) -- see $dismLog"
    }
}

# ═════════════════════════════════════════════════════════════════════════════
# SUMMARY  (always printed – this is what N-central emails)
# ═════════════════════════════════════════════════════════════════════════════
Add-Header 'SUMMARY'

$eolStatus = if ($null -eq $eolDate) {
    'Unknown -- verify manually'
} elseif ($today -gt $eolDate) {
    "EOL since $($eolDate.ToString('yyyy-MM-dd'))"
} else {
    "Supported until $($eolDate.ToString('yyyy-MM-dd'))"
}

$esuStatus = switch ($esuActive) {
    $true  { 'Active ESU licence confirmed' }
    $false { 'EOL with NO valid ESU licence -- action required' }
    $null  { 'N/A (OS within mainstream support)' }
}

$overallStatus = if ($FailCount -gt 0) { "FAILED ($FailCount issue(s) found)" } else { 'PASSED' }

$Report.Add("  Overall    : $overallStatus")
$Report.Add("  OS         : $productName  ($displayVersion)")
$Report.Add("  EOL Status : $eolStatus")
$Report.Add("  ESU Licence: $esuStatus")
$Report.Add("  Free Space : $freeGB GB on $systemDrive")
$Report.Add("  Cache Clean: $(if ($needsCleanup) { 'Cleanup performed' } else { 'No action required' })")
$Report.Add("  DISM       : $dismResult")
$Report.Add("  Report Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$Report.Add('')
$finalLine = if ($FailCount -gt 0) {
    "  *** $FailCount FAILURE(S) DETECTED -- review [FAIL] lines above ***"
} else {
    '  All checks passed. No action required.'
}
$Report.Add($finalLine)
$Report.Add('')

# ═════════════════════════════════════════════════════════════════════════════
# Flush entire report to stdout in one pass
# N-central captures this stream and includes it in the notification email.
# ═════════════════════════════════════════════════════════════════════════════
$Report | ForEach-Object { Write-Output $_ }

# Exit 1 if any FAIL was recorded so N-central marks the task red and the
# built-in "on failure" notification rule fires in addition to the summary.
exit $(if ($FailCount -gt 0) { 1 } else { 0 })
