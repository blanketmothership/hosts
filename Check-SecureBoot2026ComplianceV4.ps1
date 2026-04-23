<#
.SYNOPSIS
    Windows 2026 Secure Boot Certificate & Boot Manager Compliance Check

.DESCRIPTION
    Reports the compliance state of a Windows device with respect to the
    2026 Secure Boot certificate rollover (KB5025885 / "Windows Secure Boot
    Certificate Expiration and CA updates"). The 2011-era certificates
    begin expiring in June 2026, after which unpatched devices may fail
    to receive bootloader / firmware security updates.

    The script verifies:
      - OS / firmware eligibility (UEFI, Secure Boot enabled)
      - Presence of "Microsoft Corporation KEK CA 2023" in KEK
      - Presence of "Windows UEFI CA 2023" in DB
      - Presence of "Microsoft UEFI CA 2023" (third-party) in DB
      - Presence of "Microsoft Option ROM UEFI CA 2023" in DB
      - Boot Manager signed by the 2023 chain (bootmgfw.efi on ESP)
      - AvailableUpdates rollout bitmask (target 0x5944, completion 0x4000)
      - UEFICA2023Status / UEFICA2023Error / UEFICA2023ErrorEvent values
        (new diagnostics written by the Secure-Boot-Update task)
      - Cumulative update currency
      - Relevant diagnostic events from Microsoft-Windows-Kernel-Boot

    Output is written to STDOUT in both a human-readable block and a
    key=value summary line that N-central can parse via custom properties
    or "Last Script Output".

    AvailableUpdates bit map (per current Microsoft guidance):
        0x0004  Apply "Microsoft Corporation KEK CA 2023" to KEK
        0x0040  Deploy "Windows UEFI CA 2023" to DB
        0x0100  Install 2023-signed boot manager on the ESP
        0x0800  Deploy "Microsoft Option ROM UEFI CA 2023" to DB
        0x1000  Deploy "Microsoft UEFI CA 2023" (3P) to DB
        0x4000  Completion modifier (stays set as the "done" marker)
        Target composite:   0x5944 (all of the above combined)
        Success indicator:  AvailableUpdates == 0x4000

.NOTES
    Designed for the N-central "Run a Script" tool (PowerShell engine,
    SYSTEM context).

    Exit codes:
        0  = Compliant         (UEFI + SB on + all 2023 certs + 2023 boot mgr)
        1  = Non-Compliant     (one or more required items missing -- including
                                 legacy BIOS, SB disabled, or missing certs)
        2  = Not Applicable    (platform cannot support Secure Boot at all,
                                 e.g. Confirm-SecureBootUEFI throws
                                 PlatformNotSupportedException)
        3  = Error             (script could not evaluate the system)

    Author  : Generated for commander (cshannon@crsassist.com)
    Version : V4
    File    : Check-SecureBoot2026ComplianceV4.ps1
    Date    : 2026-04-23
    Ref     : https://support.microsoft.com/help/5025885
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    # When set, emits a single-line JSON payload as the final STDOUT line
    # (useful if you want to parse with an N-central AMP script).
    [switch]$EmitJson
)

$ErrorActionPreference = 'Stop'
$ScriptVersion         = 'V4'

# -----------------------------------------------------------------------------
# Result object
# -----------------------------------------------------------------------------
$result = [ordered]@{
    ComputerName         = $env:COMPUTERNAME
    CheckedUtc           = (Get-Date).ToUniversalTime().ToString('s') + 'Z'
    OSCaption            = $null
    OSBuild              = $null
    FirmwareType         = $null
    SecureBootSupported  = $false
    SecureBootEnabled    = $false
    KEK2023Present       = $false
    DbWindowsCA2023      = $false
    DbThirdPartyCA2023   = $false
    DbOptionRomCA2023    = $false
    BootMgrSignedBy2023  = $false
    BootMgrSigner        = $null
    AvailableUpdatesHex  = $null
    AvailableUpdatesBits = @()
    AvailableUpdatesComplete = $false
    UEFICA2023Status     = $null
    UEFICA2023Error      = $null
    UEFICA2023ErrorEvent = $null
    LatestCUInstalled    = $null
    DaysSinceLastCU      = $null
    KernelBootEvents     = @()
    ComplianceStatus     = 'Unknown'
    Reasons              = @()
    Remediation          = @()
}

# -----------------------------------------------------------------------------
# Helper: add reason / remediation
# -----------------------------------------------------------------------------
function Add-Issue {
    param(
        [Parameter(Mandatory)][string]$Reason,
        [Parameter(Mandatory)][string]$Remediation
    )
    $result.Reasons     += $Reason
    $result.Remediation += $Remediation
}

# -----------------------------------------------------------------------------
# 1. OS & firmware
# -----------------------------------------------------------------------------
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $result.OSCaption = $os.Caption
    $result.OSBuild   = "$($os.Version).$($os.BuildNumber)"
} catch {
    $result.ComplianceStatus = 'Error'
    Write-Output "ERROR: Could not query Win32_OperatingSystem: $($_.Exception.Message)"
    exit 3
}

# Firmware type: 1 = BIOS, 2 = UEFI  (Get-ComputerInfo exposes this)
try {
    $firmware = (Get-ComputerInfo -Property BiosFirmwareType -ErrorAction Stop).BiosFirmwareType
    $result.FirmwareType = "$firmware"
} catch {
    # Fallback via registry / env
    $result.FirmwareType = if ($env:firmware_type) { $env:firmware_type } else { 'Unknown' }
}

if ($result.FirmwareType -notmatch 'Uefi') {
    Add-Issue "System is not booting in UEFI mode (FirmwareType=$($result.FirmwareType))." `
              "Secure Boot requires UEFI. Convert the disk to GPT (e.g. 'mbr2gpt.exe /convert /allowFullOS') and switch the firmware from Legacy/CSM to UEFI. All downstream Secure Boot checks will remain 'false' until this is done."
}

# -----------------------------------------------------------------------------
# 2. Secure Boot enabled?
# -----------------------------------------------------------------------------
try {
    $result.SecureBootSupported = $true
    $result.SecureBootEnabled   = [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
} catch [System.PlatformNotSupportedException] {
    # Platform genuinely cannot do Secure Boot -- this is the only case we
    # still call "NotApplicable", but downstream checks still run so the
    # report is as complete as possible.
    $result.SecureBootSupported = $false
    if ($result.ComplianceStatus -eq 'Unknown') { $result.ComplianceStatus = 'NotApplicable' }
    Add-Issue "Platform does not support Secure Boot (PlatformNotSupportedException)." `
              "Hardware or firmware does not expose Secure Boot variables. Typically means Legacy/CSM firmware mode or unsupported hardware. Convert to UEFI/GPT; if already UEFI, check OEM firmware update availability."
} catch {
    $result.SecureBootSupported = $true
    $result.SecureBootEnabled   = $false
    Add-Issue "Secure Boot is disabled in firmware: $($_.Exception.Message)" `
              "Enable Secure Boot in the UEFI/BIOS setup. The 2023 certificate servicing will not run on this device, and any 2023 certs that are present are not being enforced, until Secure Boot is turned on."
}

# -----------------------------------------------------------------------------
# 3. Certificate store inspection (KEK + DB)
#    Get-SecureBootUEFI returns a binary EFI_SIGNATURE_LIST blob. Certificate
#    Subject names appear inside the blob as ASCII, so a string search is a
#    reliable (and Microsoft-documented) way to detect them.
# -----------------------------------------------------------------------------
function Test-SecureBootVarForString {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Match
    )
    try {
        $bytes = (Get-SecureBootUEFI -Name $Name -ErrorAction Stop).bytes
        if (-not $bytes) { return $false }
        $text  = [System.Text.Encoding]::ASCII.GetString($bytes)
        return $text -match [regex]::Escape($Match)
    } catch {
        return $false
    }
}

# Cert checks run unconditionally -- Get-SecureBootUEFI reads the UEFI
# variables regardless of whether Secure Boot enforcement is on, so we can
# still tell you whether the certs have been staged even on a machine
# where Secure Boot is disabled in firmware. Test-SecureBootVarForString
# swallows errors and returns $false when the variable isn't accessible
# (e.g. on legacy BIOS), so these lines are safe everywhere.

# The single-write remediation Microsoft now recommends is:
#   HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\AvailableUpdates = 0x5944
# The Secure-Boot-Update scheduled task processes each bit on subsequent
# reboots / 12-hour cycles. All remediation messages below reference that
# value so the fix is a single registry write regardless of which cert(s)
# are missing.

# KEK -- Microsoft Corporation KEK CA 2023 (sometimes written as "KEK 2K CA 2023")
$result.KEK2023Present = Test-SecureBootVarForString -Name 'KEK' -Match 'Microsoft Corporation KEK (2K )?CA 2023'
if (-not $result.KEK2023Present) {
    Add-Issue "KEK store is missing 'Microsoft Corporation KEK CA 2023'." `
              "Install the current monthly cumulative update, then set HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\AvailableUpdates (DWORD) to 0x5944 and reboot. The Secure-Boot-Update scheduled task will deploy the new KEK automatically (bit 0x0004)."
}

# DB -- Windows UEFI CA 2023 (signs Windows boot components)
$result.DbWindowsCA2023 = Test-SecureBootVarForString -Name 'db' -Match 'Windows UEFI CA 2023'
if (-not $result.DbWindowsCA2023) {
    Add-Issue "DB store is missing 'Windows UEFI CA 2023'." `
              "Set AvailableUpdates (DWORD) to 0x5944 and reboot. Bit 0x0040 deploys this cert to DB."
}

# DB -- Microsoft UEFI CA 2023 (third-party -- Linux shim, non-Windows boot media)
$result.DbThirdPartyCA2023 = Test-SecureBootVarForString -Name 'db' -Match 'Microsoft UEFI CA 2023'
if (-not $result.DbThirdPartyCA2023) {
    Add-Issue "DB store is missing 'Microsoft UEFI CA 2023' (third-party UEFI CA)." `
              "Set AvailableUpdates (DWORD) to 0x5944 and reboot. Bit 0x1000 deploys this cert to DB. Required for Linux shim loaders and non-Windows bootable media."
}

# DB -- Microsoft Option ROM UEFI CA 2023 (signs firmware/option ROMs)
$result.DbOptionRomCA2023 = Test-SecureBootVarForString -Name 'db' -Match 'Microsoft Option ROM UEFI CA 2023'
if (-not $result.DbOptionRomCA2023) {
    Add-Issue "DB store is missing 'Microsoft Option ROM UEFI CA 2023'." `
              "Set AvailableUpdates (DWORD) to 0x5944 and reboot. Bit 0x0800 deploys this cert to DB. Used by OEM firmware and UEFI option ROMs (e.g. NICs, HBAs) signed under the 2023 chain."
}

# -----------------------------------------------------------------------------
# 4. Boot Manager signer -- is bootmgfw.efi on the ESP signed by the 2023 PCA?
#    We mount the EFI System Partition, read the cert on bootmgfw.efi, and
#    inspect the signer subject.
# -----------------------------------------------------------------------------
function Get-EspDriveLetter {
    try {
        $esp = Get-Partition -ErrorAction Stop | Where-Object { $_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' } | Select-Object -First 1
        if (-not $esp) { return $null }

        # Try to find an existing drive letter/access path
        $existing = $esp.AccessPaths | Where-Object { $_ -match '^[A-Za-z]:\\?$' } | Select-Object -First 1
        if ($existing) { return $existing.TrimEnd('\') }

        # Temporarily mount to an unused letter
        $free = 90..65 | ForEach-Object { [char]$_ } |
                Where-Object { -not (Test-Path ("{0}:\" -f $_)) } |
                Select-Object -First 1
        if (-not $free) { return $null }
        $letter = "$free`:"
        Add-PartitionAccessPath -DiskNumber $esp.DiskNumber -PartitionNumber $esp.PartitionNumber -AccessPath "$letter\" -ErrorAction Stop
        return [pscustomobject]@{
            Letter   = $letter
            Disk     = $esp.DiskNumber
            PartNum  = $esp.PartitionNumber
            Temp     = $true
        }
    } catch {
        return $null
    }
}

# Boot Manager check runs unconditionally too. On legacy-BIOS systems there
# will be no ESP with the GPT type GUID, so Get-EspDriveLetter returns $null
# and we simply flag that bootmgfw.efi could not be evaluated. On UEFI
# systems with Secure Boot disabled, the file still exists and we can still
# inspect its signer -- that tells you whether Windows has already swapped
# in the 2023-signed boot manager, independent of enforcement state.
$espInfo = Get-EspDriveLetter
$espLetter = if ($espInfo -is [string]) { $espInfo } elseif ($espInfo) { $espInfo.Letter } else { $null }
try {
    if ($espLetter) {
        $bootMgrPath = Join-Path "$espLetter\" 'EFI\Microsoft\Boot\bootmgfw.efi'
        if (Test-Path -LiteralPath $bootMgrPath) {
            $sig = Get-AuthenticodeSignature -FilePath $bootMgrPath -ErrorAction Stop
            if ($sig -and $sig.SignerCertificate) {
                $subject = $sig.SignerCertificate.Subject
                $result.BootMgrSigner = $subject

                # The 2023-signed boot manager is issued by "Windows UEFI CA 2023"
                if ($sig.SignerCertificate.Issuer -match 'Windows UEFI CA 2023' -or
                    $subject -match 'Windows UEFI CA 2023') {
                    $result.BootMgrSignedBy2023 = $true
                } else {
                    Add-Issue "Boot Manager (bootmgfw.efi) is still signed via the 2011 'Windows Production PCA' chain." `
                              "Set AvailableUpdates (DWORD) to 0x5944 and reboot. Bit 0x0100 installs the 2023-signed boot manager on the ESP. Windows must first have 'Windows UEFI CA 2023' in DB (bit 0x0040) before this step can succeed; the Secure-Boot-Update task handles the ordering."
                }
            }
        } else {
            Add-Issue "bootmgfw.efi not found on the EFI System Partition ($espLetter)." `
                      "Verify the ESP is intact. Run 'bcdboot C:\Windows /s $espLetter /f UEFI' from an elevated prompt if the boot files are missing."
        }
    } else {
        # Legacy BIOS systems or systems whose ESP can't be mounted land here.
        if ($result.FirmwareType -match 'Uefi') {
            Add-Issue "Could not locate or mount the EFI System Partition." `
                      "Manually inspect bootmgfw.efi signer: run 'mountvol X: /S' then 'Get-AuthenticodeSignature X:\EFI\Microsoft\Boot\bootmgfw.efi'."
        } else {
            Add-Issue "No EFI System Partition exists (legacy BIOS boot disk)." `
                      "No bootmgfw.efi to evaluate. Converting to UEFI/GPT (see firmware remediation above) will create the ESP that the 2023-signed boot manager needs to live on."
        }
    }
} catch {
    Add-Issue "Failed to evaluate bootmgfw.efi signer: $($_.Exception.Message)" `
              "Re-run the script elevated / under SYSTEM; N-central scripts run as LocalSystem which normally has ESP access."
} finally {
    if ($espInfo -and -not ($espInfo -is [string]) -and $espInfo.Temp) {
        try {
            Remove-PartitionAccessPath -DiskNumber $espInfo.Disk -PartitionNumber $espInfo.PartNum -AccessPath "$($espInfo.Letter)\" -ErrorAction SilentlyContinue
        } catch { }
    }
}

# -----------------------------------------------------------------------------
# 5. AvailableUpdates registry bitmask + new 2023 CA diagnostics.
#    Bit map reflects current Microsoft guidance (target composite 0x5944,
#    completion marker 0x4000). Each bit is cleared by the Secure-Boot-Update
#    scheduled task as its corresponding phase completes.
# -----------------------------------------------------------------------------
try {
    $sbKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot'
    if (Test-Path $sbKey) {
        $sbProps = Get-ItemProperty -Path $sbKey -ErrorAction SilentlyContinue

        $au = $sbProps.AvailableUpdates
        if ($null -ne $au) {
            $auInt = [int]$au
            $result.AvailableUpdatesHex      = ('0x{0:X}' -f $auInt)
            $result.AvailableUpdatesComplete = ($auInt -eq 0x4000)

            $bitMap = [ordered]@{
                0x0004 = 'Apply "Microsoft Corporation KEK CA 2023" to KEK'
                0x0040 = 'Deploy "Windows UEFI CA 2023" to DB'
                0x0100 = 'Install 2023-signed boot manager on the ESP'
                0x0800 = 'Deploy "Microsoft Option ROM UEFI CA 2023" to DB'
                0x1000 = 'Deploy "Microsoft UEFI CA 2023" (3P) to DB'
                0x4000 = 'Completion modifier (stays set when all else clears)'
            }
            $result.AvailableUpdatesBits = $bitMap.Keys | Where-Object { ($auInt -band $_) -eq $_ } | ForEach-Object {
                ('0x{0:X4} = {1}' -f $_, $bitMap[$_])
            }

            # Pending-work bits (everything except the 0x4000 completion marker)
            $pending = $auInt -band (-bnot 0x4000)
            if ($pending -ne 0) {
                Add-Issue ("AvailableUpdates = 0x{0:X} -- Secure-Boot-Update task still has work to do (pending bits 0x{1:X})." -f $auInt, $pending) `
                          "Leave AvailableUpdates at 0x5944 and reboot. The task runs at startup and every 12 hours as LocalSystem; each bit clears as its phase completes. Final state is 0x4000."
            }
        }

        # New diagnostic values written by the Secure-Boot-Update task
        if ($null -ne $sbProps.UEFICA2023Status)     { $result.UEFICA2023Status     = $sbProps.UEFICA2023Status }
        if ($null -ne $sbProps.UEFICA2023Error)      { $result.UEFICA2023Error      = ('0x{0:X}' -f [int]$sbProps.UEFICA2023Error) }
        if ($null -ne $sbProps.UEFICA2023ErrorEvent) { $result.UEFICA2023ErrorEvent = $sbProps.UEFICA2023ErrorEvent }
        if ($result.UEFICA2023Error -and $result.UEFICA2023Error -ne '0x0') {
            Add-Issue "Secure-Boot-Update task reported UEFICA2023Error=$($result.UEFICA2023Error) (event: $($result.UEFICA2023ErrorEvent))." `
                      "Review the Microsoft-Windows-Kernel-Boot/Operational event log and the Secure Boot troubleshooting guide (KB5025885). Common causes: outdated OEM firmware, third-party boot loader blocking the swap, or insufficient ESP free space."
        }
    }
} catch {
    # Non-fatal
}

# -----------------------------------------------------------------------------
# 6. Cumulative update currency. The 2023 Secure Boot servicing code and the
#    Secure-Boot-Update scheduled task ship inside the monthly CUs; a device
#    that hasn't patched in many weeks is liable to be missing diagnostic
#    improvements (Windows Security app visibility, UEFICA2023* values).
# -----------------------------------------------------------------------------
try {
    $lastCU = Get-HotFix -ErrorAction Stop |
              Where-Object { $_.Description -match 'Security Update|Update' -and $_.InstalledOn } |
              Sort-Object -Property InstalledOn -Descending |
              Select-Object -First 1
    if ($lastCU) {
        $result.LatestCUInstalled = '{0} ({1:yyyy-MM-dd})' -f $lastCU.HotFixID, $lastCU.InstalledOn
        $result.DaysSinceLastCU   = [int]((Get-Date) - $lastCU.InstalledOn).TotalDays
        if ($result.DaysSinceLastCU -gt 60) {
            Add-Issue "Last cumulative update was $($result.DaysSinceLastCU) days ago." `
                      "Install the current monthly Windows cumulative update. The Secure-Boot-Update scheduled task and 2023 certificate payloads ride along in the monthly LCUs -- there is no standalone 'install certs' KB."
        }
    } else {
        Add-Issue "Unable to determine last installed cumulative update." `
                  "Verify Windows Update is functional and install the current monthly CU."
    }
} catch {
    # Non-fatal
}

# -----------------------------------------------------------------------------
# 7. Diagnostic events -- Kernel-Boot logs certificate deployment outcomes
# -----------------------------------------------------------------------------
try {
    $evt = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-Kernel-Boot/Operational'
        StartTime = (Get-Date).AddDays(-45)
        Id        = 153,154,155,156,1035,1036,1037,1796,1797,1798,1799,1800,1801,1802,1803,1804,1805,1806,1807,1808
    } -ErrorAction SilentlyContinue -MaxEvents 25
    if ($evt) {
        $result.KernelBootEvents = $evt | Select-Object TimeCreated, Id, LevelDisplayName,
            @{n='Message';e={ ($_.Message -split "`r?`n")[0] }}
    }
} catch {
    # Non-fatal
}

# -----------------------------------------------------------------------------
# 8. Final compliance decision
# -----------------------------------------------------------------------------
# A device is Compliant only when the firmware is UEFI, Secure Boot is
# enabled, all four 2023 certs (KEK CA 2023, Windows UEFI CA 2023, Microsoft
# UEFI CA 2023 third-party, Microsoft Option ROM UEFI CA 2023) are present,
# AND the 2023-signed boot manager is on the ESP. Anything else is
# NonCompliant (with remediation already attached), except the narrow
# PlatformNotSupportedException case flagged as NotApplicable earlier.
if ($result.ComplianceStatus -ne 'NotApplicable') {
    $fullyCompliant =
        ($result.FirmwareType -match 'Uefi') -and
        $result.SecureBootEnabled           -and
        $result.KEK2023Present              -and
        $result.DbWindowsCA2023             -and
        $result.DbThirdPartyCA2023          -and
        $result.DbOptionRomCA2023           -and
        $result.BootMgrSignedBy2023

    $result.ComplianceStatus = if ($fullyCompliant) { 'Compliant' } else { 'NonCompliant' }
}

# -----------------------------------------------------------------------------
# 9. Output
# -----------------------------------------------------------------------------
$divider = '-' * 72
Write-Output $divider
Write-Output ("Windows 2026 Secure Boot Compliance Report ({0})  |  {1}" -f $ScriptVersion, $result.ComputerName)
Write-Output ("Checked (UTC): {0}" -f $result.CheckedUtc)
Write-Output $divider
Write-Output ("OS                     : {0} (build {1})" -f $result.OSCaption, $result.OSBuild)
Write-Output ("Firmware               : {0}" -f $result.FirmwareType)
Write-Output ("Secure Boot Supported  : {0}" -f $result.SecureBootSupported)
Write-Output ("Secure Boot Enabled    : {0}" -f $result.SecureBootEnabled)
Write-Output $divider
Write-Output ("KEK 'MS Corp KEK CA 2023'      : {0}" -f $result.KEK2023Present)
Write-Output ("DB  'Windows UEFI CA 2023'     : {0}" -f $result.DbWindowsCA2023)
Write-Output ("DB  'Microsoft UEFI CA 2023' (3P): {0}" -f $result.DbThirdPartyCA2023)
Write-Output ("DB  'MS Option ROM UEFI CA 2023': {0}" -f $result.DbOptionRomCA2023)
Write-Output ("Boot Manager 2023-signed       : {0}" -f $result.BootMgrSignedBy2023)
if ($result.BootMgrSigner) {
    Write-Output ("Boot Manager Signer    : {0}" -f $result.BootMgrSigner)
}
Write-Output $divider
Write-Output ("AvailableUpdates       : {0}" -f ($result.AvailableUpdatesHex  | ForEach-Object { if ($_) { $_ } else { '(not set)' } }))
Write-Output ("  Target composite     : 0x5944  (write this once; Windows progresses the phases)")
Write-Output ("  Completion marker    : 0x4000  (value settles here when all phases finish)")
Write-Output ("  Servicing complete?  : {0}" -f $result.AvailableUpdatesComplete)
if ($result.AvailableUpdatesBits.Count) {
    Write-Output  '  Decoded bits currently set:'
    $result.AvailableUpdatesBits | ForEach-Object { Write-Output ("    {0}" -f $_) }
}
if ($result.UEFICA2023Status -or $result.UEFICA2023Error -or $result.UEFICA2023ErrorEvent) {
    Write-Output ("UEFICA2023Status       : {0}" -f $result.UEFICA2023Status)
    Write-Output ("UEFICA2023Error        : {0}" -f $result.UEFICA2023Error)
    Write-Output ("UEFICA2023ErrorEvent   : {0}" -f $result.UEFICA2023ErrorEvent)
}
Write-Output ("Latest CU Installed    : {0}" -f ($result.LatestCUInstalled | ForEach-Object { if ($_) { $_ } else { '(unknown)' } }))
if ($null -ne $result.DaysSinceLastCU) {
    Write-Output ("Days Since Last CU     : {0}" -f $result.DaysSinceLastCU)
}
Write-Output $divider
Write-Output ("COMPLIANCE STATUS      : {0}" -f $result.ComplianceStatus.ToUpper())
Write-Output $divider

if ($result.Reasons.Count -gt 0) {
    Write-Output 'FINDINGS:'
    for ($i = 0; $i -lt $result.Reasons.Count; $i++) {
        Write-Output ("  [{0}] {1}" -f ($i + 1), $result.Reasons[$i])
    }
    Write-Output ''
    Write-Output 'REMEDIATION STEPS:'
    for ($i = 0; $i -lt $result.Remediation.Count; $i++) {
        Write-Output ("  [{0}] {1}" -f ($i + 1), $result.Remediation[$i])
    }
    Write-Output $divider
}

if ($result.KernelBootEvents.Count -gt 0) {
    Write-Output 'RECENT Kernel-Boot EVENTS (last 45 days):'
    $result.KernelBootEvents | ForEach-Object {
        Write-Output ("  {0}  ID {1}  [{2}]  {3}" -f $_.TimeCreated, $_.Id, $_.LevelDisplayName, $_.Message)
    }
    Write-Output $divider
}

# Single-line summary that N-central can grep / store as a custom property
$summary = "SUMMARY|Ver=$ScriptVersion|Host=$($result.ComputerName)|Status=$($result.ComplianceStatus)|" +
           "SecureBoot=$($result.SecureBootEnabled)|KEK2023=$($result.KEK2023Present)|" +
           "DbWin2023=$($result.DbWindowsCA2023)|Db3P2023=$($result.DbThirdPartyCA2023)|" +
           "DbOptionRom2023=$($result.DbOptionRomCA2023)|BootMgr2023=$($result.BootMgrSignedBy2023)|" +
           "AvailableUpdates=$($result.AvailableUpdatesHex)|ServicingComplete=$($result.AvailableUpdatesComplete)|" +
           "IssueCount=$($result.Reasons.Count)"
Write-Output $summary

if ($EmitJson) {
    $result | ConvertTo-Json -Depth 5 -Compress | Write-Output
}

# -----------------------------------------------------------------------------
# 10. Exit code
# -----------------------------------------------------------------------------
switch ($result.ComplianceStatus) {
    'Compliant'      { exit 0 }
    'NonCompliant'   { exit 1 }
    'NotApplicable'  { exit 2 }
    default          { exit 3 }
}
