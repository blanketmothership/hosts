<#
.SYNOPSIS
    Windows 2026 Secure Boot Certificate Remediation Script

.DESCRIPTION
    Drives a Windows device toward compliance with the 2023 Secure Boot
    certificate rollover (KB5025885). Detects the current state (KEK, DB
    certs, boot manager signer, CU currency, BitLocker posture) and sets
    the HKLM\SYSTEM\CurrentControlSet\Control\Secureboot\AvailableUpdates
    bitmask so that Windows stages the next batch of 2023-era updates on
    subsequent reboots.

    Design goals:
      - SAFE BY DEFAULT. Reports what WOULD be done. Nothing is changed
        until you pass -Apply.
      - IDEMPOTENT. Re-running after reboots advances the state; there's
        no harm in running on an already-compliant device.
      - GATED destructive steps. The 2011 PCA revocation (which can
        brick a device if prior phases aren't in place) is locked behind
        -AllowRevocation.
      - BitLocker-aware. Boot config changes can trigger PCR mismatch
        and a recovery key prompt. Use -SuspendBitLocker to issue a
        Suspend-BitLocker before rebooting.

    Typical flow:
        1) Run the check script first (Check-SecureBoot2026Compliance.ps1).
        2) Run this script with -Apply during a maintenance window.
        3) Reboot the device (two reboots are normally required for
           Windows to stage + apply an AvailableUpdates phase).
        4) Re-run the check script to verify, or re-run this script with
           -Apply to advance to the next phase if one is outstanding.

.PARAMETER Apply
    Actually make the changes. Without this, the script runs in dry-run
    mode and only reports what it would do.

.PARAMETER IncludeThirdParty
    Also deploy the "Microsoft UEFI CA 2023" (third-party) certificate
    to DB. Required for machines that boot Linux shim loaders, non-
    Windows bootable media, or OEM option ROMs signed by 3P CAs. Windows-
    only estates can safely skip this.

.PARAMETER AllowRevocation
    DANGEROUS. Permits the final DBX revocation step that invalidates
    the 2011 "Windows Production PCA". Only set this after every other
    phase is verified compliant AND you have tested pilot devices; once
    revoked, a device that still depends on the 2011 chain will not boot.

.PARAMETER SuspendBitLocker
    Before writing the registry change, issue Suspend-BitLocker against
    the system drive for the number of reboots the phase requires. This
    prevents a TPM PCR mismatch from prompting the user for a recovery
    key during the reboots that follow.

.PARAMETER AutoReboot
    After applying changes, schedule a reboot using shutdown.exe. Without
    this switch, the machine must be rebooted manually for changes to
    take effect.

.PARAMETER RebootDelaySeconds
    Delay before auto-reboot. Default 300 (5 min). Ignored unless
    -AutoReboot is set.

.PARAMETER MinCuDaysOld
    Fail prerequisite check if the last cumulative update is older than
    this many days. Default 60. The March 2024 CU or later is required
    for the 2023 servicing to be present.

.NOTES
    Exit codes:
        0   = Already compliant (or nothing to do).
        10  = Change applied; reboot required.
        11  = Change applied AND reboot was initiated.
        20  = Dry-run complete; would take action (re-run with -Apply).
        30  = Prerequisite failure (CU out of date, SB disabled, etc.).
        40  = Not applicable (legacy BIOS, no SB support).
        1   = Error during execution.

    For use with the N-central "Run a Script" tool (PowerShell engine,
    SYSTEM context). SYSTEM has the rights needed to write the registry,
    suspend BitLocker, and reboot.

    Reference : https://support.microsoft.com/help/5025885
    Author    : Generated for commander (cshannon@crsassist.com)
    Date      : 2026-04-23
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Apply,
    [switch]$IncludeThirdParty,
    [switch]$AllowRevocation,
    [switch]$SuspendBitLocker,
    [switch]$AutoReboot,
    [int]   $RebootDelaySeconds = 300,
    [int]   $MinCuDaysOld       = 60
)

$ErrorActionPreference = 'Stop'

# -----------------------------------------------------------------------------
# Configuration: AvailableUpdates bit values (per KB5025885).
# Microsoft has revised these during the rollout -- verify against the
# current KB before relying on them. They are centralised here so you can
# update them in one place if Microsoft republishes.
# -----------------------------------------------------------------------------
$AU = [ordered]@{
    DeployKEK2023        = 0x40    # Deploy "Microsoft Corporation KEK 2K CA 2023" to KEK
    DeployWindowsCA2023  = 0x100   # Deploy "Windows UEFI CA 2023" to DB
    UpdateBootManager    = 0x200   # Swap ESP boot manager to the 2023-signed version
    DeployThirdPartyCA   = 0x400   # Deploy "Microsoft UEFI CA 2023" (3P) to DB
    ApplySvnUpdate       = 0x800   # Apply boot manager SVN / revocation tokens
    RevokeBootMgr2011    = 0x2000  # DESTRUCTIVE: revoke 2011-signed boot manager in DBX
}

$SbKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot'

# -----------------------------------------------------------------------------
# Output / logging helpers
# -----------------------------------------------------------------------------
$script:Lines = New-Object System.Collections.Generic.List[string]
function Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = ("[{0}] [{1,-5}] {2}" -f (Get-Date -Format 'HH:mm:ss'), $Level, $Msg)
    $script:Lines.Add($line) | Out-Null
    Write-Output $line
}

function Test-SecureBootVarForString {
    param([string]$Name, [string]$Match)
    try {
        $bytes = (Get-SecureBootUEFI -Name $Name -ErrorAction Stop).bytes
        if (-not $bytes) { return $false }
        $text = [System.Text.Encoding]::ASCII.GetString($bytes)
        return $text -match [regex]::Escape($Match)
    } catch { return $false }
}

function Get-EspDriveLetter {
    try {
        $esp = Get-Partition -ErrorAction Stop | Where-Object { $_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' } | Select-Object -First 1
        if (-not $esp) { return $null }

        $existing = $esp.AccessPaths | Where-Object { $_ -match '^[A-Za-z]:\\?$' } | Select-Object -First 1
        if ($existing) { return [pscustomobject]@{ Letter = $existing.TrimEnd('\'); Disk = $esp.DiskNumber; PartNum = $esp.PartitionNumber; Temp = $false } }

        $free = 90..65 | ForEach-Object { [char]$_ } | Where-Object { -not (Test-Path ("{0}:\" -f $_)) } | Select-Object -First 1
        if (-not $free) { return $null }
        $letter = "$free`:"
        Add-PartitionAccessPath -DiskNumber $esp.DiskNumber -PartitionNumber $esp.PartitionNumber -AccessPath "$letter\" -ErrorAction Stop
        return [pscustomobject]@{ Letter = $letter; Disk = $esp.DiskNumber; PartNum = $esp.PartitionNumber; Temp = $true }
    } catch { return $null }
}

# -----------------------------------------------------------------------------
# 1) Prerequisite checks — firmware type, Secure Boot state, CU currency.
# -----------------------------------------------------------------------------
Log "Starting Secure Boot 2026 remediation on $env:COMPUTERNAME (Apply=$Apply)"

# Firmware
$firmwareType = try { (Get-ComputerInfo -Property BiosFirmwareType -ErrorAction Stop).BiosFirmwareType } catch { 'Unknown' }
Log "Firmware type: $firmwareType"
if ($firmwareType -notmatch 'Uefi') {
    Log "Device is not booting in UEFI mode. Secure Boot remediation cannot proceed." 'ERROR'
    Log "Remediation: convert the boot disk to GPT (mbr2gpt.exe /convert /allowFullOS) and switch firmware from Legacy/CSM to UEFI before running this script again." 'ERROR'
    exit 40
}

# Secure Boot enabled?
$sbEnabled = $false
try {
    $sbEnabled = [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
} catch [System.PlatformNotSupportedException] {
    Log "Platform does not support Secure Boot (PlatformNotSupportedException)." 'ERROR'
    Log "Remediation: check OEM firmware update availability. Some very old hardware cannot participate in the 2023 rollout." 'ERROR'
    exit 40
} catch {
    Log "Secure Boot is disabled in firmware." 'WARN'
    Log "The 2023 servicing only runs when Secure Boot is enforced. Enable Secure Boot in the UEFI/BIOS setup (usually: Security -> Secure Boot -> Enabled, with OS Type = Windows UEFI). After enabling, re-run this script." 'WARN'
    # We stop here because writing AvailableUpdates with SB off does nothing
    # useful -- Windows won't consume the flag until SB is on.
    exit 30
}
Log "Secure Boot enabled: $sbEnabled"

# CU currency
$lastCu    = Get-HotFix -ErrorAction SilentlyContinue | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
$daysSince = if ($lastCu) { [int]((Get-Date) - $lastCu.InstalledOn).TotalDays } else { $null }
if ($lastCu) {
    Log ("Last update installed: {0} on {1:yyyy-MM-dd} ({2} days ago)" -f $lastCu.HotFixID, $lastCu.InstalledOn, $daysSince)
} else {
    Log "Unable to determine last installed update." 'WARN'
}
if ($daysSince -and $daysSince -gt $MinCuDaysOld) {
    Log "Last cumulative update is older than $MinCuDaysOld days. The 2023 Secure Boot servicing ships via monthly CUs starting with the March 2024 update (KB5035853 / KB5035845)." 'ERROR'
    Log "Remediation: install the current monthly cumulative update via Windows Update / your patch management tool, then re-run this script." 'ERROR'
    exit 30
}

# -----------------------------------------------------------------------------
# 2) Detect current cert / boot manager state
# -----------------------------------------------------------------------------
$state = [ordered]@{
    KEK2023             = Test-SecureBootVarForString -Name 'KEK' -Match 'Microsoft Corporation KEK 2K CA 2023'
    DbWindows2023       = Test-SecureBootVarForString -Name 'db'  -Match 'Windows UEFI CA 2023'
    DbThirdParty2023    = Test-SecureBootVarForString -Name 'db'  -Match 'Microsoft UEFI CA 2023'
    BootMgrIs2023       = $false
    BootMgrSigner       = $null
    CurrentAvailableHex = $null
}

$espInfo = Get-EspDriveLetter
try {
    if ($espInfo) {
        $bootMgrPath = Join-Path "$($espInfo.Letter)\" 'EFI\Microsoft\Boot\bootmgfw.efi'
        if (Test-Path -LiteralPath $bootMgrPath) {
            $sig = Get-AuthenticodeSignature -FilePath $bootMgrPath -ErrorAction Stop
            if ($sig -and $sig.SignerCertificate) {
                $state.BootMgrSigner = $sig.SignerCertificate.Subject
                if ($sig.SignerCertificate.Issuer -match 'Windows UEFI CA 2023' -or
                    $sig.SignerCertificate.Subject -match 'Windows UEFI CA 2023') {
                    $state.BootMgrIs2023 = $true
                }
            }
        }
    }
} catch {
    Log "Could not inspect bootmgfw.efi signer: $($_.Exception.Message)" 'WARN'
} finally {
    if ($espInfo -and $espInfo.Temp) {
        try { Remove-PartitionAccessPath -DiskNumber $espInfo.Disk -PartitionNumber $espInfo.PartNum -AccessPath "$($espInfo.Letter)\" -ErrorAction SilentlyContinue } catch {}
    }
}

try {
    $cur = (Get-ItemProperty -Path $SbKey -Name 'AvailableUpdates' -ErrorAction SilentlyContinue).AvailableUpdates
    if ($null -ne $cur) { $state.CurrentAvailableHex = '0x{0:X}' -f [int]$cur }
} catch {}

$_auText = if ($state.CurrentAvailableHex) { $state.CurrentAvailableHex } else { '(unset)' }
Log ("State -> KEK2023={0}  DbWin2023={1}  Db3P2023={2}  BootMgr2023={3}  AvailableUpdates={4}" -f `
        $state.KEK2023, $state.DbWindows2023, $state.DbThirdParty2023, $state.BootMgrIs2023, $_auText)

# -----------------------------------------------------------------------------
# 3) Decide which bits need to be set.
#    Strategy: set the minimum combined mask for whatever is still missing.
#    Windows will stage and apply them across two reboots per enabled bit.
# -----------------------------------------------------------------------------
$desiredMask      = 0
$plannedActions   = New-Object System.Collections.Generic.List[string]
$pendingForLater  = New-Object System.Collections.Generic.List[string]

if (-not $state.KEK2023) {
    $desiredMask = $desiredMask -bor $AU.DeployKEK2023
    $plannedActions.Add("Set bit 0x{0:X} to deploy 'Microsoft Corporation KEK 2K CA 2023' to KEK." -f $AU.DeployKEK2023)
}
if (-not $state.DbWindows2023) {
    $desiredMask = $desiredMask -bor $AU.DeployWindowsCA2023
    $plannedActions.Add("Set bit 0x{0:X} to deploy 'Windows UEFI CA 2023' to DB." -f $AU.DeployWindowsCA2023)
}
if (-not $state.BootMgrIs2023) {
    $desiredMask = $desiredMask -bor $AU.UpdateBootManager
    $plannedActions.Add("Set bit 0x{0:X} to swap the ESP boot manager to the 2023-signed version." -f $AU.UpdateBootManager)
}
if ($IncludeThirdParty -and -not $state.DbThirdParty2023) {
    $desiredMask = $desiredMask -bor $AU.DeployThirdPartyCA
    $plannedActions.Add("Set bit 0x{0:X} to deploy 'Microsoft UEFI CA 2023' (3P) to DB." -f $AU.DeployThirdPartyCA)
}
if (-not $IncludeThirdParty -and -not $state.DbThirdParty2023) {
    $pendingForLater.Add("'Microsoft UEFI CA 2023' (3P) not deployed. Re-run with -IncludeThirdParty if Linux shim / non-Windows boot media is in use.")
}
if ($AllowRevocation) {
    $revokeReady = $state.KEK2023 -and $state.DbWindows2023 -and $state.BootMgrIs2023 -and (-not $IncludeThirdParty -or $state.DbThirdParty2023)
    if ($revokeReady) {
        $desiredMask = $desiredMask -bor $AU.RevokeBootMgr2011
        $plannedActions.Add("Set bit 0x{0:X} to REVOKE the 2011 'Windows Production PCA' boot manager (DESTRUCTIVE)." -f $AU.RevokeBootMgr2011)
    } else {
        $pendingForLater.Add("-AllowRevocation was set, but this device is not yet ready for revocation (prior phases still incomplete). Revocation will be skipped this run.")
    }
}

if ($desiredMask -eq 0) {
    Log "No remediation action required."
    if ($pendingForLater.Count -gt 0) {
        foreach ($n in $pendingForLater) { Log $n 'NOTE' }
    }
    # Summary line for N-central
    $_auText2 = if ($state.CurrentAvailableHex) { $state.CurrentAvailableHex } else { '(unset)' }
    Write-Output ("SUMMARY|Host={0}|Status=Compliant|Action=None|AvailableUpdates={1}" -f $env:COMPUTERNAME, $_auText2)
    exit 0
}

Log ("Planned desired AvailableUpdates mask: 0x{0:X}" -f $desiredMask)
foreach ($a in $plannedActions) { Log $a 'PLAN' }
foreach ($n in $pendingForLater) { Log $n 'NOTE' }

# -----------------------------------------------------------------------------
# 4) Dry-run short-circuit
# -----------------------------------------------------------------------------
if (-not $Apply) {
    Log "Dry-run mode (no -Apply). No registry changes made." 'DRY'
    Log "Re-run with -Apply during a maintenance window to stage these changes." 'DRY'
    Write-Output ("SUMMARY|Host={0}|Status=Dryrun|DesiredMask=0x{1:X}|Actions={2}" -f $env:COMPUTERNAME, $desiredMask, $plannedActions.Count)
    exit 20
}

# -----------------------------------------------------------------------------
# 5) BitLocker suspension (optional but recommended)
# -----------------------------------------------------------------------------
if ($SuspendBitLocker) {
    try {
        $sysDrive = ($env:SystemDrive).TrimEnd('\')
        $bl = Get-BitLockerVolume -MountPoint $sysDrive -ErrorAction Stop
        if ($bl.ProtectionStatus -eq 'On') {
            if ($PSCmdlet.ShouldProcess("BitLocker on $sysDrive", "Suspend-BitLocker -RebootCount 2")) {
                Suspend-BitLocker -MountPoint $sysDrive -RebootCount 2 -ErrorAction Stop | Out-Null
                Log "BitLocker suspended on $sysDrive for 2 reboots." 'ACT'
            }
        } else {
            Log "BitLocker is not currently protecting $sysDrive -- no suspension needed."
        }
    } catch {
        Log "Failed to suspend BitLocker: $($_.Exception.Message). Aborting to avoid a recovery-key prompt." 'ERROR'
        exit 1
    }
} else {
    try {
        $bl = Get-BitLockerVolume -MountPoint ($env:SystemDrive.TrimEnd('\')) -ErrorAction Stop
        if ($bl.ProtectionStatus -eq 'On') {
            Log "BitLocker is ENABLED on the system drive but -SuspendBitLocker was not set. A recovery key prompt may appear on reboot. Confirm you have the recovery key escrowed before proceeding." 'WARN'
        }
    } catch { }
}

# -----------------------------------------------------------------------------
# 6) Apply the registry change (OR the new bits with whatever is already set)
# -----------------------------------------------------------------------------
try {
    if (-not (Test-Path $SbKey)) { New-Item -Path $SbKey -Force | Out-Null }

    $currentValue = 0
    $existing = Get-ItemProperty -Path $SbKey -Name 'AvailableUpdates' -ErrorAction SilentlyContinue
    if ($existing -and $null -ne $existing.AvailableUpdates) { $currentValue = [int]$existing.AvailableUpdates }

    $newValue = $currentValue -bor $desiredMask
    if ($newValue -eq $currentValue) {
        Log ("AvailableUpdates is already 0x{0:X}; no registry write needed." -f $currentValue)
    } else {
        if ($PSCmdlet.ShouldProcess("$SbKey\AvailableUpdates", ("Set DWORD from 0x{0:X} to 0x{1:X}" -f $currentValue, $newValue))) {
            Set-ItemProperty -Path $SbKey -Name 'AvailableUpdates' -Type DWord -Value $newValue
            Log ("AvailableUpdates updated: 0x{0:X} -> 0x{1:X}" -f $currentValue, $newValue) 'ACT'
        }
    }
} catch {
    Log "Failed to write AvailableUpdates: $($_.Exception.Message)" 'ERROR'
    exit 1
}

# -----------------------------------------------------------------------------
# 7) Reboot handling
# -----------------------------------------------------------------------------
Log "Reboot required for Windows to stage the requested phase(s). A second reboot is typically needed to fully apply each phase." 'INFO'

if ($AutoReboot) {
    if ($RebootDelaySeconds -lt 30) { $RebootDelaySeconds = 30 }
    $comment = "Secure Boot 2026 remediation: AvailableUpdates mask updated. Reboot scheduled in $RebootDelaySeconds seconds."
    try {
        Start-Process -FilePath 'shutdown.exe' -ArgumentList @('/r','/t', "$RebootDelaySeconds", '/c', "`"$comment`"") -Wait -NoNewWindow
        Log "Reboot scheduled in $RebootDelaySeconds seconds via shutdown.exe." 'ACT'
        Write-Output ("SUMMARY|Host={0}|Status=Applied+RebootScheduled|NewMask=0x{1:X}|RebootIn={2}s" -f $env:COMPUTERNAME, $newValue, $RebootDelaySeconds)
        exit 11
    } catch {
        Log "Failed to schedule reboot: $($_.Exception.Message). Reboot this device manually." 'ERROR'
    }
}

Write-Output ("SUMMARY|Host={0}|Status=Applied+RebootRequired|NewMask=0x{1:X}" -f $env:COMPUTERNAME, $newValue)
exit 10
