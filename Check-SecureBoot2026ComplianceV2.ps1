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
      - Presence of the 2023 KEK CA in the Key Exchange Key store
      - Presence of "Windows UEFI CA 2023" in the DB signature store
      - Presence of "Microsoft UEFI CA 2023" (3rd-party) in the DB store
      - Boot Manager signed by the 2023 PCA (bootmgfw.efi on ESP)
      - AvailableUpdates registry rollout bitmask progress
      - KB5025885 servicing / opt-in state
      - Relevant diagnostic events from Microsoft-Windows-Kernel-Boot
      - Cumulative update currency (March 2024 or later required)

    Output is written to STDOUT in both a human-readable block and a
    key=value summary line that N-central can parse via custom properties
    or "Last Script Output".

.NOTES
    Designed for the N-central "Run a Script" tool (PowerShell engine,
    SYSTEM context).

    Exit codes:
        0  = Compliant         (UEFI + SB on + all 2023 certs + 2023 boot mgr)
        1  = Non-Compliant     (one or more required items missing — including
                                 legacy BIOS, SB disabled, or missing certs)
        2  = Not Applicable    (platform cannot support Secure Boot at all,
                                 e.g. Confirm-SecureBootUEFI throws
                                 PlatformNotSupportedException)
        3  = Error             (script could not evaluate the system)

    Author : Generated for commander (cshannon@crsassist.com)
    Date   : 2026-04-23
    Ref    : https://support.microsoft.com/help/5025885
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    # When set, emits a single-line JSON payload as the final STDOUT line
    # (useful if you want to parse with an N-central AMP script).
    [switch]$EmitJson
)

$ErrorActionPreference = 'Stop'

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
    BootMgrSignedBy2023  = $false
    BootMgrSigner        = $null
    AvailableUpdatesHex  = $null
    AvailableUpdatesBits = @()
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

# KEK — Microsoft Corporation KEK 2K CA 2023
$result.KEK2023Present = Test-SecureBootVarForString -Name 'KEK' -Match 'Microsoft Corporation KEK 2K CA 2023'
if (-not $result.KEK2023Present) {
    Add-Issue "KEK store is missing 'Microsoft Corporation KEK 2K CA 2023'." `
              "Ensure the March 2024 or later cumulative update is installed, then opt in per KB5025885 by setting HKLM\SYSTEM\CurrentControlSet\Control\Secureboot\AvailableUpdates (DWORD) to the current KEK-deployment bit and rebooting twice. Check KB5025885 for the current bit value (Microsoft has revised it during the rollout)."
}

# DB — Windows UEFI CA 2023 (used to sign Windows boot components)
$result.DbWindowsCA2023 = Test-SecureBootVarForString -Name 'db' -Match 'Windows UEFI CA 2023'
if (-not $result.DbWindowsCA2023) {
    Add-Issue "DB store is missing 'Windows UEFI CA 2023'." `
              "After the KEK is updated, opt in to the 'Windows UEFI CA 2023' DB deployment step per KB5025885 (AvailableUpdates bit -- see KB for current value) and reboot twice to stage and apply."
}

# DB — Microsoft UEFI CA 2023 (third-party / option-ROMs / Linux shim)
$result.DbThirdPartyCA2023 = Test-SecureBootVarForString -Name 'db' -Match 'Microsoft UEFI CA 2023'
if (-not $result.DbThirdPartyCA2023) {
    Add-Issue "DB store is missing 'Microsoft UEFI CA 2023' (third-party UEFI CA)." `
              "Opt in to the 3rd-party UEFI CA 2023 DB deployment step per KB5025885. This cert is required for Linux shim loaders, many OEM option ROMs, and non-Windows bootable media."
}

# -----------------------------------------------------------------------------
# 4. Boot Manager signer — is bootmgfw.efi on the ESP signed by the 2023 PCA?
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
                              "Once 'Windows UEFI CA 2023' is in DB, opt in to the boot-manager-swap step per KB5025885 (AvailableUpdates bit that stages the 2023-signed bootmgr). Reboot twice to allow Windows to copy the 2023-signed boot manager to the ESP."
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
# 5. AvailableUpdates registry bitmask (KB5025885 rollout progress)
# -----------------------------------------------------------------------------
try {
    $sbKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot'
    if (Test-Path $sbKey) {
        $au = (Get-ItemProperty -Path $sbKey -Name 'AvailableUpdates' -ErrorAction SilentlyContinue).AvailableUpdates
        if ($null -ne $au) {
            $result.AvailableUpdatesHex = ('0x{0:X}' -f [int]$au)

            # Approximate meanings per KB5025885. Microsoft has revised these
            # bit assignments during the rollout -- always treat the KB as the
            # authoritative source. These are shown as hints only.
            $bitMap = [ordered]@{
                0x10   = '(hint) Servicing / DBX update'
                0x40   = '(hint) Deploy KEK CA 2023 to KEK'
                0x100  = '(hint) Deploy "Windows UEFI CA 2023" to DB'
                0x200  = '(hint) Deploy "Microsoft UEFI CA 2023" (3P) to DB'
                0x400  = '(hint) Swap to 2023-signed boot manager'
                0x800  = '(hint) Apply SVN / revocation update'
                0x1000 = '(hint) Apply SKUSiPolicy 2023'
                0x2000 = '(hint) Revoke 2011 PCA signed boot manager (DBX)'
            }
            $result.AvailableUpdatesBits = $bitMap.Keys | Where-Object { ([int]$au -band $_) -eq $_ } | ForEach-Object {
                ('0x{0:X} = {1}' -f $_, $bitMap[$_])
            }
        }
    }
} catch {
    # Non-fatal
}

# -----------------------------------------------------------------------------
# 6. Cumulative update currency — you need the March 2024 CU or newer
#    (KB5035853 / KB5035845) for the 2023 servicing to be present at all.
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
                      "Install the latest Windows cumulative update. The 2023 Secure Boot certificates ship through monthly CUs starting March 2024 (KB5035853 / KB5035845)."
        }
    } else {
        Add-Issue "Unable to determine last installed cumulative update." `
                  "Verify Windows Update is functional and install the current monthly CU."
    }
} catch {
    # Non-fatal
}

# -----------------------------------------------------------------------------
# 7. Diagnostic events — Kernel-Boot logs certificate deployment outcomes
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
# enabled, all three 2023 certs are present, AND the 2023-signed boot
# manager is on the ESP. Anything else is NonCompliant (with remediation
# already attached), except the narrow PlatformNotSupportedException case
# which was flagged as NotApplicable earlier.
if ($result.ComplianceStatus -ne 'NotApplicable') {
    $fullyCompliant =
        ($result.FirmwareType -match 'Uefi') -and
        $result.SecureBootEnabled           -and
        $result.KEK2023Present              -and
        $result.DbWindowsCA2023             -and
        $result.DbThirdPartyCA2023          -and
        $result.BootMgrSignedBy2023

    $result.ComplianceStatus = if ($fullyCompliant) { 'Compliant' } else { 'NonCompliant' }
}

# -----------------------------------------------------------------------------
# 9. Output
# -----------------------------------------------------------------------------
$divider = '-' * 72
Write-Output $divider
Write-Output ("Windows 2026 Secure Boot Compliance Report  |  {0}" -f $result.ComputerName)
Write-Output ("Checked (UTC): {0}" -f $result.CheckedUtc)
Write-Output $divider
Write-Output ("OS                     : {0} (build {1})" -f $result.OSCaption, $result.OSBuild)
Write-Output ("Firmware               : {0}" -f $result.FirmwareType)
Write-Output ("Secure Boot Supported  : {0}" -f $result.SecureBootSupported)
Write-Output ("Secure Boot Enabled    : {0}" -f $result.SecureBootEnabled)
Write-Output $divider
Write-Output ("KEK CA 2023 present    : {0}" -f $result.KEK2023Present)
Write-Output ("DB 'Windows UEFI CA 2023'   : {0}" -f $result.DbWindowsCA2023)
Write-Output ("DB 'Microsoft UEFI CA 2023' : {0}" -f $result.DbThirdPartyCA2023)
Write-Output ("Boot Manager 2023-signed : {0}" -f $result.BootMgrSignedBy2023)
if ($result.BootMgrSigner) {
    Write-Output ("Boot Manager Signer    : {0}" -f $result.BootMgrSigner)
}
Write-Output $divider
Write-Output ("AvailableUpdates       : {0}" -f ($result.AvailableUpdatesHex  | ForEach-Object { if ($_) { $_ } else { '(not set)' } }))
if ($result.AvailableUpdatesBits.Count) {
    Write-Output  '  Decoded bits:'
    $result.AvailableUpdatesBits | ForEach-Object { Write-Output ("    {0}" -f $_) }
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
$summary = "SUMMARY|Host=$($result.ComputerName)|Status=$($result.ComplianceStatus)|" +
           "SecureBoot=$($result.SecureBootEnabled)|KEK2023=$($result.KEK2023Present)|" +
           "DbWin2023=$($result.DbWindowsCA2023)|Db3P2023=$($result.DbThirdPartyCA2023)|" +
           "BootMgr2023=$($result.BootMgrSignedBy2023)|AvailableUpdates=$($result.AvailableUpdatesHex)|" +
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
