<#
.SYNOPSIS
    Phase 1 read-only prerequisite audit for the Microsoft Secure Boot 2023
    certificate update (Windows UEFI CA 2023 / KEK CA 2023).

.DESCRIPTION
    Checks every condition required for the in-OS Secure Boot certificate
    update to apply successfully. Makes NO changes and triggers NO reboot.
    All output uses Write-Host for N-central AMP capture.

    Exit logic: prints a clear PASS/FAIL summary. If any prerequisite is
    not met, the missing items are listed explicitly under "MISSING".

.NOTES
    Read-only. Does not set MicrosoftUpdateManagedOptIn, does not run the
    Secure-Boot-Update task, does not reboot.

.NCENTRAL_OUTPUT_MAPPING
    This script is designed for an AMP "script/command" custom service in
    N-central that scrapes stdout (Write-Host) for fixed token lines.

    Three machine-parseable lines are emitted near the end of output, each
    prefixed "NCENTRAL:" so they are easy to target with a regex/contains
    capture rule. Build the custom service to scrape these:

      Token line                         Suggested custom service property
      ---------------------------------  ----------------------------------
      NCENTRAL:PREREQ_STATUS=<value>     String  - PASS | FAIL
      NCENTRAL:MISSING_COUNT=<n>         Numeric - count of failed prereqs
      NCENTRAL:CERT2023_PRESENT=<value>  String  - True | False (DB already updated)

    Recommended custom service scan/threshold logic:
      - PrereqStatus  : Normal when = PASS,        Failed when = FAIL
      - MissingCount  : Normal when = 0,           Warning/Failed when > 0
      - Cert2023Present: Normal when = True (post-update verification);
                         informational pre-update (do NOT alert on False
                         until after opt-in + reboot cycle has run).

    AMP "Parse" / capture regex examples (PCRE-style, capture group 1):
      PrereqStatus    ->  NCENTRAL:PREREQ_STATUS=(\w+)
      MissingCount    ->  NCENTRAL:MISSING_COUNT=(\d+)
      Cert2023Present ->  NCENTRAL:CERT2023_PRESENT=(\w+)

    Because every other line is human-readable PASS/FAIL detail, the same
    AMP output can also be surfaced verbatim in the task result for ad-hoc
    review without breaking the scraped properties.

    The ScriptVersion value is also emitted as NCENTRAL:SCRIPT_VERSION=<ver>
    so you can confirm which build of the audit ran across the fleet
    (use a String custom service property and alert on version drift).
#>

$ScriptVersion = '1.0.0'

# ---------------------------------------------------------------------------
$results  = New-Object System.Collections.Generic.List[object]
$missing  = New-Object System.Collections.Generic.List[string]

function Add-Check {
    param(
        [string]$Name,
        [bool]$Pass,
        [string]$Detail,
        [string]$MissingMsg
    )
    $results.Add([pscustomobject]@{ Name = $Name; Pass = $Pass; Detail = $Detail })
    if (-not $Pass -and $MissingMsg) { $missing.Add($MissingMsg) }
}

Write-Host "==============================================================="
Write-Host " Secure Boot 2023 Certificate Update - Prerequisite Audit"
Write-Host " Script version : $ScriptVersion"
Write-Host " Computer       : $env:COMPUTERNAME"
Write-Host " Timestamp      : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "==============================================================="
Write-Host ""

# ---------------------------------------------------------------------------
# 1. Administrative context
# ---------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Add-Check -Name 'Running as Administrator' -Pass $isAdmin `
    -Detail $(if ($isAdmin) { 'Elevated' } else { 'NOT elevated' }) `
    -MissingMsg 'Script is not running with administrative privileges.'

# ---------------------------------------------------------------------------
# 2. OS edition / version
# ---------------------------------------------------------------------------
$os        = Get-CimInstance Win32_OperatingSystem
$caption   = $os.Caption
$buildNum  = [int]$os.BuildNumber
# Update plumbing requires a serviced, supported build. Server 2016 (14393)+.
$osPass    = $buildNum -ge 14393
Add-Check -Name 'Supported OS build' -Pass $osPass `
    -Detail "$caption (build $buildNum)" `
    -MissingMsg "OS build $buildNum may be unsupported for the cert update tooling."

# ---------------------------------------------------------------------------
# 3. Firmware mode must be UEFI (not legacy/BIOS)
# ---------------------------------------------------------------------------
$firmwareUefi = $false
$fwDetail     = 'Unknown'
try {
    # PEFirmwareType: 1 = BIOS/Legacy, 2 = UEFI
    $fw = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop)
    $pe = $env:firmware_type
    if (-not $pe) {
        $peVal = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control' `
            -Name 'PEFirmwareType' -ErrorAction SilentlyContinue).PEFirmwareType
    } else { $peVal = $pe }
    # Most reliable: Confirm-SecureBootUEFI presence implies UEFI
    $firmwareUefi = $true
    $null = Confirm-SecureBootUEFI -ErrorAction Stop
    $fwDetail = 'UEFI'
} catch {
    if ($_.Exception.Message -match 'not supported|Cmdlet not supported') {
        $firmwareUefi = $false
        $fwDetail     = 'Legacy BIOS (Secure Boot not available)'
    } else {
        # Cmdlet exists but Secure Boot disabled -> still UEFI
        $firmwareUefi = $true
        $fwDetail     = 'UEFI'
    }
}
Add-Check -Name 'Firmware is UEFI' -Pass $firmwareUefi `
    -Detail $fwDetail `
    -MissingMsg 'System is booting in legacy BIOS mode; cert update does not apply.'

# ---------------------------------------------------------------------------
# 4. Secure Boot enabled
# ---------------------------------------------------------------------------
$sbEnabled = $false
$sbDetail  = 'Unknown'
try {
    $sbEnabled = Confirm-SecureBootUEFI -ErrorAction Stop
    $sbDetail  = if ($sbEnabled) { 'Enabled' } else { 'Disabled (UEFI present)' }
} catch {
    $sbDetail = 'Not available (legacy BIOS)'
}
Add-Check -Name 'Secure Boot enabled' -Pass $sbEnabled `
    -Detail $sbDetail `
    -MissingMsg 'Secure Boot is not enabled; enable it in firmware before opt-in.'

# ---------------------------------------------------------------------------
# 5. Current DB / KEK certificate state (informational + 2023 presence)
# ---------------------------------------------------------------------------
$has2023Db  = $false
$has2023Kek = $false
$dbDetail   = 'Unable to read'
try {
    $dbBytes = (Get-SecureBootUEFI db -ErrorAction Stop).bytes
    $dbText  = [System.Text.Encoding]::ASCII.GetString($dbBytes)
    $has2023Db = $dbText -match 'Windows UEFI CA 2023'
    $dbDetail  = if ($has2023Db) { "'Windows UEFI CA 2023' already present in DB" }
                 else            { "'Windows UEFI CA 2023' NOT yet in DB (update pending)" }
} catch {
    $dbDetail = "Could not read DB variable: $($_.Exception.Message)"
}
try {
    $kekBytes = (Get-SecureBootUEFI KEK -ErrorAction Stop).bytes
    $kekText  = [System.Text.Encoding]::ASCII.GetString($kekBytes)
    $has2023Kek = $kekText -match 'Microsoft Corporation KEK 2K CA 2023'
} catch { }
# This is a STATE check, not a prereq failure - record as informational pass.
Add-Check -Name 'Current 2023 cert state (info)' -Pass $true `
    -Detail "DB 2023: $has2023Db | KEK 2023: $has2023Kek | $dbDetail"

# ---------------------------------------------------------------------------
# 6. Capability / availability flags reported by servicing stack
# ---------------------------------------------------------------------------
$sbKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot'
$capable = (Get-ItemProperty -Path $sbKey -Name 'WindowsUEFICA2023Capable' `
            -ErrorAction SilentlyContinue).WindowsUEFICA2023Capable
$capablePass = ($null -ne $capable -and $capable -ge 1)
$capableDetail = if ($null -eq $capable) { 'WindowsUEFICA2023Capable not present (servicing has not staged update)' }
                 else { "WindowsUEFICA2023Capable = $capable" }
Add-Check -Name 'Servicing reports 2023 capability' -Pass $capablePass `
    -Detail $capableDetail `
    -MissingMsg 'WindowsUEFICA2023Capable flag absent/0 - latest cumulative update likely not installed.'

# ---------------------------------------------------------------------------
# 7. Opt-in key state (informational - script does NOT set it)
# ---------------------------------------------------------------------------
$optIn = (Get-ItemProperty -Path $sbKey -Name 'MicrosoftUpdateManagedOptIn' `
          -ErrorAction SilentlyContinue).MicrosoftUpdateManagedOptIn
$optInDetail = if ($null -eq $optIn) { 'Not set (deployment not yet opted in)' }
               else { ("MicrosoftUpdateManagedOptIn = 0x{0:X}" -f $optIn) }
Add-Check -Name 'Opt-in key state (info)' -Pass $true -Detail $optInDetail

# ---------------------------------------------------------------------------
# 8. Secure-Boot-Update scheduled task present
# ---------------------------------------------------------------------------
$taskPresent = $false
$taskDetail  = 'Not found'
try {
    $task = Get-ScheduledTask -TaskName 'Secure-Boot-Update' -ErrorAction Stop
    $taskPresent = $true
    $taskDetail  = "Present (State: $($task.State))"
} catch {
    $taskDetail = 'Secure-Boot-Update scheduled task not found'
}
Add-Check -Name 'Secure-Boot-Update task present' -Pass $taskPresent `
    -Detail $taskDetail `
    -MissingMsg 'Secure-Boot-Update scheduled task is missing (servicing stack out of date).'

# ---------------------------------------------------------------------------
# 9. TPM present and ready (best practice for boot integrity)
# ---------------------------------------------------------------------------
$tpmPass   = $false
$tpmDetail = 'Unknown'
try {
    $tpm = Get-Tpm -ErrorAction Stop
    $tpmPass   = $tpm.TpmPresent -and $tpm.TpmReady
    $tpmDetail = "Present: $($tpm.TpmPresent) | Ready: $($tpm.TpmReady)"
} catch {
    $tpmDetail = "Could not query TPM: $($_.Exception.Message)"
}
Add-Check -Name 'TPM present and ready' -Pass $tpmPass `
    -Detail $tpmDetail `
    -MissingMsg 'TPM not present/ready - not strictly required but recommended before proceeding.'

# ---------------------------------------------------------------------------
# 10. Windows Update service reachable / running
# ---------------------------------------------------------------------------
$wuPass   = $false
$wuDetail = 'Unknown'
try {
    $wu = Get-Service -Name wuauserv -ErrorAction Stop
    $wuPass   = $wu.StartType -ne 'Disabled'
    $wuDetail = "Status: $($wu.Status) | StartType: $($wu.StartType)"
} catch {
    $wuDetail = "Could not query wuauserv: $($_.Exception.Message)"
}
Add-Check -Name 'Windows Update service usable' -Pass $wuPass `
    -Detail $wuDetail `
    -MissingMsg 'Windows Update service (wuauserv) is disabled - update cannot be delivered.'

# ---------------------------------------------------------------------------
# 11. Pending reboot state (informational - flag only, no action)
# ---------------------------------------------------------------------------
$pendingReboot = $false
$cbs = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
$wuauReboot = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
$pendingReboot = $cbs -or $wuauReboot
Add-Check -Name 'Pending reboot state (info)' -Pass $true `
    -Detail $(if ($pendingReboot) { 'Reboot is PENDING (resolve before opt-in)' } else { 'No pending reboot' })

# ===========================================================================
# OUTPUT
# ===========================================================================
Write-Host "----- CHECK RESULTS -------------------------------------------"
foreach ($r in $results) {
    $status = if ($r.Pass) { 'PASS' } else { 'FAIL' }
    Write-Host ("[{0}] {1,-35} {2}" -f $status, $r.Name, $r.Detail)
}
Write-Host ""

# Prerequisite gating items only (exclude the informational checks)
$prereqFailures = $results | Where-Object { -not $_.Pass }

if ($missing.Count -eq 0) {
    Write-Host "==============================================================="
    Write-Host " RESULT: ALL PREREQUISITES MET"
    Write-Host " System is ready for the Secure Boot 2023 certificate opt-in."
    Write-Host "==============================================================="
} else {
    Write-Host "==============================================================="
    Write-Host " RESULT: PREREQUISITES NOT MET"
    Write-Host " The following items are MISSING / require attention:"
    Write-Host "---------------------------------------------------------------"
    $i = 1
    foreach ($m in $missing) {
        Write-Host (" {0}. {1}" -f $i, $m)
        $i++
    }
    Write-Host "==============================================================="
    if ($pendingReboot) {
        Write-Host " NOTE: A reboot is currently pending. This script did NOT"
        Write-Host "       reboot. Resolve the pending reboot during your normal"
        Write-Host "       maintenance window before opting in."
    }
}

Write-Host ""
Write-Host "Audit complete (read-only - no changes made, no reboot performed)."
Write-Host "Script version: $ScriptVersion"

# ===========================================================================
# MACHINE-PARSEABLE OUTPUT FOR N-CENTRAL CUSTOM SERVICE SCRAPING
# These fixed-format lines are what the AMP capture rules target. Keep the
# tokens exact - do not localize or reformat. See .NCENTRAL_OUTPUT_MAPPING.
# ===========================================================================
$prereqStatus  = if ($missing.Count -eq 0) { 'PASS' } else { 'FAIL' }
$cert2023State = ($has2023Db -and $has2023Kek)

Write-Host ""
Write-Host "----- NCENTRAL SCRAPE TOKENS ----------------------------------"
Write-Host ("NCENTRAL:PREREQ_STATUS={0}"    -f $prereqStatus)
Write-Host ("NCENTRAL:MISSING_COUNT={0}"    -f $missing.Count)
Write-Host ("NCENTRAL:CERT2023_PRESENT={0}" -f $cert2023State)
Write-Host ("NCENTRAL:SCRIPT_VERSION={0}"   -f $ScriptVersion)
