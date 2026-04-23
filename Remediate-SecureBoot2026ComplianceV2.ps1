<#
.SYNOPSIS
    Windows 2026 Secure Boot Certificate Remediation Script (single-write model)

.DESCRIPTION
    Brings a Windows device into compliance with the 2023 Secure Boot
    certificate rollover (KB5025885) by setting the one registry value
    Microsoft now recommends for IT-managed devices:

        HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\AvailableUpdates
        (DWORD) = 0x5944

    That single value is a composite of every phase bit. The built-in
    Secure-Boot-Update scheduled task (\Microsoft\Windows\PI\Secure-Boot-
    Update) runs at startup and every 12 hours as LocalSystem, processes
    each set bit in the correct order over subsequent reboots, and clears
    each bit as its phase completes. When servicing is finished,
    AvailableUpdates settles at 0x4000 (a completion modifier that is
    intentionally never cleared).

    AvailableUpdates bit map (per current Microsoft guidance):
        0x0004  Apply "Microsoft Corporation KEK CA 2023" to KEK
        0x0040  Deploy "Windows UEFI CA 2023" to DB
        0x0100  Install 2023-signed boot manager on the ESP
        0x0800  Deploy "Microsoft Option ROM UEFI CA 2023" to DB
        0x1000  Deploy "Microsoft UEFI CA 2023" (3P) to DB
        0x4000  Completion modifier (stays set as "done")
        Target composite:  0x5944
        Success indicator: AvailableUpdates == 0x4000

    Design goals:
      - SAFE BY DEFAULT. Reports what WOULD be done. Nothing is changed
        until you pass -Apply.
      - IDEMPOTENT. Re-running is harmless; pending bits are re-ORed in,
        already-cleared bits are not re-requested, and devices at 0x4000
        are recognised as complete.
      - BitLocker-aware. Boot config changes can trigger PCR mismatch
        and a recovery-key prompt. Use -SuspendBitLocker to suspend
        protection for 2 reboots before the change.
      - Focused. The dangerous 2011 PCA revocation step is NOT part of
        the current 0x5944 playbook and is intentionally omitted.

    Typical flow:
        1) Run the check script (Check-SecureBoot2026ComplianceV2.ps1).
        2) Run this script with -Apply during a maintenance window.
        3) Reboot. Windows' Secure-Boot-Update task drives the phases
           forward over subsequent reboots / 12-hour cycles.
        4) Re-run the check script to verify AvailableUpdates == 0x4000
           and all 2023 certs / boot manager are in place.

.PARAMETER Apply
    Actually make the changes. Without this, the script runs in dry-run
    mode and only reports what it would do.

.PARAMETER SkipThirdParty
    Omit the "Microsoft UEFI CA 2023" (third-party) bit (0x1000). Use in
    Windows-only estates that never boot Linux shim or non-Windows media.
    Resulting composite is 0x5944 minus 0x1000 = 0x4944.

.PARAMETER SkipOptionRom
    Omit the "Microsoft Option ROM UEFI CA 2023" bit (0x0800). Safe only
    if you are confident no installed hardware relies on option ROMs
    signed under the 2023 chain. Resulting composite is 0x5944 minus
    0x0800 = 0x5144.

.PARAMETER SuspendBitLocker
    Before writing the registry change, issue Suspend-BitLocker against
    the system drive with -RebootCount 2. Prevents a TPM PCR mismatch
    from prompting for a recovery key during the reboots that follow.

.PARAMETER RunTaskNow
    After writing the registry change, trigger the Secure-Boot-Update
    scheduled task to run immediately instead of waiting for the next
    12-hour cycle. The task itself schedules its real work for the next
    boot, so this only speeds up the first-stage processing.

.PARAMETER AutoReboot
    After applying changes, schedule a reboot using shutdown.exe. Without
    this switch the machine must be rebooted manually.

.PARAMETER RebootDelaySeconds
    Delay before auto-reboot. Default 300 (5 min). Ignored unless
    -AutoReboot is set. Minimum enforced: 30.

.PARAMETER MinCuDaysOld
    Prerequisite check: fail if the last cumulative update is older than
    this many days. Default 60. The 2023 servicing and the Secure-Boot-
    Update scheduled task ship via the monthly LCUs.

.NOTES
    Exit codes:
        0   = Already compliant (AvailableUpdates == 0x4000 and certs
              verified present).
        10  = Change applied; reboot required.
        11  = Change applied AND reboot was initiated.
        20  = Dry-run complete; would take action (re-run with -Apply).
        30  = Prerequisite failure (CU out of date, SB disabled, etc.).
        40  = Not applicable (legacy BIOS, no SB support).
        1   = Error during execution.

    Designed for the N-central "Run a Script" tool (PowerShell engine,
    SYSTEM context). SYSTEM has the rights needed to write the registry,
    suspend BitLocker, run the scheduled task, and reboot.

    Reference : https://support.microsoft.com/help/5025885
    Author    : Generated for commander (cshannon@crsassist.com)
    Date      : 2026-04-23 (updated with current MS guidance — single-write)
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Apply,
    [switch]$SkipThirdParty,
    [switch]$SkipOptionRom,
    [switch]$SuspendBitLocker,
    [switch]$RunTaskNow,
    [switch]$AutoReboot,
    [int]   $RebootDelaySeconds = 300,
    [int]   $MinCuDaysOld       = 60
)

$ErrorActionPreference = 'Stop'

# -----------------------------------------------------------------------------
# AvailableUpdates bit map (authoritative: KB5025885).
# -----------------------------------------------------------------------------
$AU = [ordered]@{
    ApplyKEK2023        = 0x0004   # Microsoft Corporation KEK CA 2023 -> KEK
    DeployWindowsCA2023 = 0x0040   # Windows UEFI CA 2023 -> DB
    InstallBootMgr2023  = 0x0100   # 2023-signed boot manager on ESP
    DeployOptionRom2023 = 0x0800   # Microsoft Option ROM UEFI CA 2023 -> DB
    DeployThirdParty    = 0x1000   # Microsoft UEFI CA 2023 (3P) -> DB
    CompletionModifier  = 0x4000   # stays set when all other bits cleared
}
$CompletionValue = $AU.CompletionModifier                      # 0x4000
$FullComposite   = [int]0
foreach ($v in $AU.Values) { $FullComposite = $FullComposite -bor $v } # 0x5944

$SbKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot'

# -----------------------------------------------------------------------------
# Output / helper functions
# -----------------------------------------------------------------------------
function Log {
    param([string]$Msg, [string]$Level = 'INFO')
    Write-Output ("[{0}] [{1,-5}] {2}" -f (Get-Date -Format 'HH:mm:ss'), $Level, $Msg)
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
# 1) Prerequisite checks
# -----------------------------------------------------------------------------
Log "Starting Secure Boot 2026 remediation on $env:COMPUTERNAME (Apply=$Apply)"

$firmwareType = try { (Get-ComputerInfo -Property BiosFirmwareType -ErrorAction Stop).BiosFirmwareType } catch { 'Unknown' }
Log "Firmware type: $firmwareType"
if ($firmwareType -notmatch 'Uefi') {
    Log "Device is not booting in UEFI mode. Secure Boot remediation cannot proceed." 'ERROR'
    Log "Remediation: convert the boot disk to GPT (mbr2gpt.exe /convert /allowFullOS) and switch firmware from Legacy/CSM to UEFI, then re-run." 'ERROR'
    exit 40
}

$sbEnabled = $false
try {
    $sbEnabled = [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
} catch [System.PlatformNotSupportedException] {
    Log "Platform does not support Secure Boot (PlatformNotSupportedException)." 'ERROR'
    Log "Remediation: check OEM firmware update availability; some very old hardware cannot participate in the 2023 rollout." 'ERROR'
    exit 40
} catch {
    Log "Secure Boot is disabled in firmware." 'WARN'
    Log "The Secure-Boot-Update task will not advance while SB is off. Enable Secure Boot in UEFI setup (usually Security -> Secure Boot -> Enabled, OS Type = Windows UEFI) and re-run." 'WARN'
    exit 30
}
Log "Secure Boot enabled: $sbEnabled"

$lastCu    = Get-HotFix -ErrorAction SilentlyContinue | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
$daysSince = if ($lastCu) { [int]((Get-Date) - $lastCu.InstalledOn).TotalDays } else { $null }
if ($lastCu) {
    Log ("Last update installed: {0} on {1:yyyy-MM-dd} ({2} days ago)" -f $lastCu.HotFixID, $lastCu.InstalledOn, $daysSince)
} else {
    Log "Unable to determine last installed update." 'WARN'
}
if ($daysSince -and $daysSince -gt $MinCuDaysOld) {
    Log "Last cumulative update is older than $MinCuDaysOld days. The Secure-Boot-Update scheduled task and 2023 cert payloads ship inside the monthly LCUs." 'ERROR'
    Log "Remediation: install the current monthly CU via Windows Update / your patch tool, then re-run this script." 'ERROR'
    exit 30
}

# -----------------------------------------------------------------------------
# 2) Detect current state
# -----------------------------------------------------------------------------
$state = [ordered]@{
    KEK2023             = Test-SecureBootVarForString -Name 'KEK' -Match 'Microsoft Corporation KEK (2K )?CA 2023'
    DbWindows2023       = Test-SecureBootVarForString -Name 'db'  -Match 'Windows UEFI CA 2023'
    DbThirdParty2023    = Test-SecureBootVarForString -Name 'db'  -Match 'Microsoft UEFI CA 2023'
    DbOptionRom2023     = Test-SecureBootVarForString -Name 'db'  -Match 'Microsoft Option ROM UEFI CA 2023'
    BootMgrIs2023       = $false
    BootMgrSigner       = $null
    CurrentAvailable    = $null
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
    if ($null -ne $cur) {
        $state.CurrentAvailable    = [int]$cur
        $state.CurrentAvailableHex = '0x{0:X}' -f [int]$cur
    }
} catch {}

$_auText = if ($state.CurrentAvailableHex) { $state.CurrentAvailableHex } else { '(unset)' }
Log ("State -> KEK2023={0}  DbWin2023={1}  Db3P2023={2}  DbOptionRom2023={3}  BootMgr2023={4}  AvailableUpdates={5}" -f `
        $state.KEK2023, $state.DbWindows2023, $state.DbThirdParty2023, $state.DbOptionRom2023, $state.BootMgrIs2023, $_auText)

# -----------------------------------------------------------------------------
# 3) Decide whether any action is needed.
#    Compute the "desired" composite value based on which phases the user
#    wants in scope. Skip bits for certs that are already deployed so the
#    task isn't asked to re-run unnecessary phases.
# -----------------------------------------------------------------------------
$desiredMask = 0
$plannedActions = New-Object System.Collections.Generic.List[string]
$pendingForLater = New-Object System.Collections.Generic.List[string]

if (-not $state.KEK2023) {
    $desiredMask = $desiredMask -bor $AU.ApplyKEK2023
    $plannedActions.Add("Request bit 0x{0:X4} — apply 'Microsoft Corporation KEK CA 2023' to KEK." -f $AU.ApplyKEK2023)
}
if (-not $state.DbWindows2023) {
    $desiredMask = $desiredMask -bor $AU.DeployWindowsCA2023
    $plannedActions.Add("Request bit 0x{0:X4} — deploy 'Windows UEFI CA 2023' to DB." -f $AU.DeployWindowsCA2023)
}
if (-not $state.BootMgrIs2023) {
    $desiredMask = $desiredMask -bor $AU.InstallBootMgr2023
    $plannedActions.Add("Request bit 0x{0:X4} — install 2023-signed boot manager on the ESP." -f $AU.InstallBootMgr2023)
}
if (-not $SkipOptionRom) {
    if (-not $state.DbOptionRom2023) {
        $desiredMask = $desiredMask -bor $AU.DeployOptionRom2023
        $plannedActions.Add("Request bit 0x{0:X4} — deploy 'Microsoft Option ROM UEFI CA 2023' to DB." -f $AU.DeployOptionRom2023)
    }
} elseif (-not $state.DbOptionRom2023) {
    $pendingForLater.Add("Microsoft Option ROM UEFI CA 2023 not deployed (-SkipOptionRom set). Re-run without the switch if this device has hardware that uses 2023-signed option ROMs.")
}
if (-not $SkipThirdParty) {
    if (-not $state.DbThirdParty2023) {
        $desiredMask = $desiredMask -bor $AU.DeployThirdParty
        $plannedActions.Add("Request bit 0x{0:X4} — deploy 'Microsoft UEFI CA 2023' (3P) to DB." -f $AU.DeployThirdParty)
    }
} elseif (-not $state.DbThirdParty2023) {
    $pendingForLater.Add("Microsoft UEFI CA 2023 (3P) not deployed (-SkipThirdParty set). Re-run without the switch if this device ever boots Linux shim loaders or non-Windows media.")
}

# Always include the completion modifier bit when requesting any work;
# Windows treats 0x4000 as the "done" marker and won't clear it.
if ($desiredMask -ne 0) { $desiredMask = $desiredMask -bor $AU.CompletionModifier }

# -----------------------------------------------------------------------------
# 4) Short-circuits
# -----------------------------------------------------------------------------

# Already fully compliant: all certs present, boot manager swapped, AvailableUpdates settled at 0x4000
$allCertsPresent = $state.KEK2023 -and $state.DbWindows2023 -and $state.BootMgrIs2023 -and `
                   ($SkipThirdParty -or $state.DbThirdParty2023) -and `
                   ($SkipOptionRom  -or $state.DbOptionRom2023)

if ($allCertsPresent -and ($state.CurrentAvailable -eq $CompletionValue -or $null -eq $state.CurrentAvailable)) {
    Log "Device is already compliant. AvailableUpdates=$_auText; all required 2023 certs and boot manager are in place."
    foreach ($n in $pendingForLater) { Log $n 'NOTE' }
    Write-Output ("SUMMARY|Host={0}|Status=Compliant|Action=None|AvailableUpdates={1}" -f $env:COMPUTERNAME, $_auText)
    exit 0
}

if ($desiredMask -eq 0) {
    # No new bits to request (all certs for our scope already deployed) but
    # AvailableUpdates still shows pending work — let Windows keep working.
    Log "All in-scope certs already deployed. No new bits to request."
    if ($state.CurrentAvailable -and $state.CurrentAvailable -ne $CompletionValue) {
        Log ("AvailableUpdates is currently $_auText; leave it to the Secure-Boot-Update task to settle at 0x4000. Consider rebooting if the device has been up a long time.") 'NOTE'
    }
    foreach ($n in $pendingForLater) { Log $n 'NOTE' }
    Write-Output ("SUMMARY|Host={0}|Status=Waiting|Action=None|AvailableUpdates={1}" -f $env:COMPUTERNAME, $_auText)
    exit 0
}

Log ("Planned desired AvailableUpdates mask: 0x{0:X4} (full composite would be 0x{1:X4})" -f $desiredMask, $FullComposite)
foreach ($a in $plannedActions) { Log $a 'PLAN' }
foreach ($n in $pendingForLater) { Log $n 'NOTE' }

# -----------------------------------------------------------------------------
# 5) Dry-run short-circuit
# -----------------------------------------------------------------------------
if (-not $Apply) {
    Log "Dry-run mode (no -Apply). No registry changes made." 'DRY'
    Log "Re-run with -Apply during a maintenance window to stage these changes." 'DRY'
    Write-Output ("SUMMARY|Host={0}|Status=Dryrun|DesiredMask=0x{1:X4}|Actions={2}" -f $env:COMPUTERNAME, $desiredMask, $plannedActions.Count)
    exit 20
}

# -----------------------------------------------------------------------------
# 6) BitLocker suspension
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
            Log "BitLocker is ENABLED on the system drive but -SuspendBitLocker was not set. A recovery-key prompt may appear on reboot. Confirm you have the recovery key escrowed before proceeding." 'WARN'
        }
    } catch { }
}

# -----------------------------------------------------------------------------
# 7) Apply registry change (OR in whatever bits already exist)
# -----------------------------------------------------------------------------
try {
    if (-not (Test-Path $SbKey)) { New-Item -Path $SbKey -Force | Out-Null }

    $currentValue = 0
    $existing = Get-ItemProperty -Path $SbKey -Name 'AvailableUpdates' -ErrorAction SilentlyContinue
    if ($existing -and $null -ne $existing.AvailableUpdates) { $currentValue = [int]$existing.AvailableUpdates }

    $newValue = $currentValue -bor $desiredMask
    if ($newValue -eq $currentValue) {
        Log ("AvailableUpdates is already 0x{0:X4}; no registry write needed." -f $currentValue)
    } else {
        if ($PSCmdlet.ShouldProcess("$SbKey\AvailableUpdates", ("Set DWORD from 0x{0:X4} to 0x{1:X4}" -f $currentValue, $newValue))) {
            Set-ItemProperty -Path $SbKey -Name 'AvailableUpdates' -Type DWord -Value $newValue
            Log ("AvailableUpdates updated: 0x{0:X4} -> 0x{1:X4}" -f $currentValue, $newValue) 'ACT'
        }
    }
} catch {
    Log "Failed to write AvailableUpdates: $($_.Exception.Message)" 'ERROR'
    exit 1
}

# -----------------------------------------------------------------------------
# 8) Optionally nudge the Secure-Boot-Update task
# -----------------------------------------------------------------------------
if ($RunTaskNow) {
    try {
        $taskPath = '\Microsoft\Windows\PI\'
        $taskName = 'Secure-Boot-Update'
        $t = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop
        Start-ScheduledTask -InputObject $t
        Log "Triggered scheduled task $taskPath$taskName. Real work still staged for next boot." 'ACT'
    } catch {
        Log "Could not start scheduled task Secure-Boot-Update: $($_.Exception.Message). Not fatal; next natural trigger will process the bits." 'WARN'
    }
}

# -----------------------------------------------------------------------------
# 9) Reboot handling
# -----------------------------------------------------------------------------
Log "Reboot required to let Windows progress the requested phase(s). Each phase can take more than one reboot to fully apply; the Secure-Boot-Update task runs at startup and every 12 hours." 'INFO'

if ($AutoReboot) {
    if ($RebootDelaySeconds -lt 30) { $RebootDelaySeconds = 30 }
    $comment = "Secure Boot 2026 remediation: AvailableUpdates updated. Reboot scheduled in $RebootDelaySeconds seconds."
    try {
        Start-Process -FilePath 'shutdown.exe' -ArgumentList @('/r','/t', "$RebootDelaySeconds", '/c', "`"$comment`"") -Wait -NoNewWindow
        Log "Reboot scheduled in $RebootDelaySeconds seconds via shutdown.exe." 'ACT'
        Write-Output ("SUMMARY|Host={0}|Status=Applied+RebootScheduled|NewMask=0x{1:X4}|RebootIn={2}s" -f $env:COMPUTERNAME, $newValue, $RebootDelaySeconds)
        exit 11
    } catch {
        Log "Failed to schedule reboot: $($_.Exception.Message). Reboot this device manually." 'ERROR'
    }
}

Write-Output ("SUMMARY|Host={0}|Status=Applied+RebootRequired|NewMask=0x{1:X4}" -f $env:COMPUTERNAME, $newValue)
exit 10
