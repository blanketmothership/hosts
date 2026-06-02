<#
.SYNOPSIS
    Phase 2 deployment trigger for the Microsoft Secure Boot 2023 certificate
    update (Windows UEFI CA 2023 / KEK 2K CA 2023) on Windows Server.

.DESCRIPTION
    On Windows Server the 2023 certificates are NOT delivered automatically by
    Windows Update / CFR. An administrator must explicitly trigger the in-OS
    servicing operation. This script does that by writing the documented
    AvailableUpdates flag(s) under:

        HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing

    and starting the \Microsoft\Windows\PI\Secure-Boot-Update scheduled task,
    which performs the actual UEFI variable update while the OS is running.

    The operation is STAGED:
      Step 1 (DB cert)       : AvailableUpdates = 0x40
                               -> writes "Windows UEFI CA 2023" into UEFI DB.
                               After success WindowsUEFICA2023Capable -> 1.
      Step 2 (boot manager)  : AvailableUpdates = 0x100
                               -> stages the 2023-signed boot manager.
                               Completes on the NEXT reboot; Capable -> 2.

    SAFETY MODEL:
      * Runs the phase-1 prerequisite gate first and ABORTS if not met.
      * Makes NO changes unless -Execute is supplied (default = dry run / WhatIf).
      * NEVER reboots. The boot-manager transition (Step 2 -> Capable=2) is left
        for your normal maintenance-window reboot. A transient UEFICA2023Error
        after Step 2 is EXPECTED ("staged, awaiting reboot"), not a failure.
      * -Stage controls how far it goes: Db (0x40 only), Full (0x40 then 0x100).

    All output uses Write-Host for N-central AMP capture, with NCENTRAL: scrape
    tokens matching the phase-1 audit script's custom-service property set.

.PARAMETER Execute
    Actually write the registry flag and start the task. Without this switch the
    script performs a dry run only (reports what it WOULD do).

.PARAMETER Stage
    'Db'   = Step 1 only (write 0x40, enroll DB cert).
    'Full' = Step 1 then Step 2 (0x40 then 0x100, stage boot manager).
    Default = 'Full'.

.PARAMETER SkipPrereqGate
    Bypass the built-in prerequisite re-check. NOT recommended; intended only
    for cases where phase-1 has already been validated immediately prior.

.NOTES
    Companion to Test-SecureBootCertPrereqs.ps1. Read that first / run that as
    your gate. This script does NOT reboot. Confirm vendor firmware is current
    before running in production (firmware bugs can reject the DB update).

    Reference: Microsoft KB 5062710 / KB 5068202 (registry deployment method).

    v1.0.0 - Initial release.
#>

[CmdletBinding()]
param(
    [switch]$Execute,
    [ValidateSet('Db','Full')]
    [string]$Stage = 'Full',
    [switch]$SkipPrereqGate
)

$ScriptVersion = '1.0.0'

# Documented AvailableUpdates flag values (Microsoft KB 5068202 / servicing).
$FLAG_DB_CERT     = 0x40    # Step 1: enroll Windows UEFI CA 2023 into DB
$FLAG_BOOTMGR     = 0x100   # Step 2: stage 2023-signed boot manager

$servKey  = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing'
$taskPath = '\Microsoft\Windows\PI\'
$taskName = 'Secure-Boot-Update'

$abort = $false
$actionsTaken = New-Object System.Collections.Generic.List[string]

Write-Host "==============================================================="
Write-Host " Secure Boot 2023 Certificate Update - DEPLOYMENT TRIGGER"
Write-Host " Script version : $ScriptVersion"
Write-Host " Computer       : $env:COMPUTERNAME"
Write-Host " Timestamp      : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host " Mode           : $(if ($Execute) { 'EXECUTE (changes WILL be made)' } else { 'DRY RUN (no changes)' })"
Write-Host " Stage          : $Stage"
Write-Host "==============================================================="
Write-Host ""

# ---------------------------------------------------------------------------
# 0. Hard safety gate: elevation
# ---------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[ABORT] Not running as Administrator. Cannot proceed."
    Write-Host "NCENTRAL:DEPLOY_RESULT=ABORTED_NOT_ADMIN"
    Write-Host "NCENTRAL:SCRIPT_VERSION=$ScriptVersion"
    return
}

# ---------------------------------------------------------------------------
# 1. Inline prerequisite gate (mirrors phase-1 hard gates)
# ---------------------------------------------------------------------------
function Test-Gate {
    $problems = New-Object System.Collections.Generic.List[string]

    # Secure Boot enabled (also confirms UEFI)
    try {
        if (-not (Confirm-SecureBootUEFI -ErrorAction Stop)) {
            $problems.Add('Secure Boot is not enabled.')
        }
    } catch {
        $problems.Add('Secure Boot/UEFI not available (legacy BIOS or cmdlet unsupported).')
    }

    # Secure-Boot-Update task present
    try {
        $null = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop
    } catch {
        try { $null = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop }
        catch { $problems.Add('Secure-Boot-Update scheduled task missing (servicing stack out of date).') }
    }

    # Windows Update service not disabled
    try {
        $wu = Get-Service -Name wuauserv -ErrorAction Stop
        if ($wu.StartType -eq 'Disabled') { $problems.Add('Windows Update service (wuauserv) is disabled.') }
    } catch {
        $problems.Add('Could not query Windows Update service (wuauserv).')
    }

    # Existing deployment error?
    try {
        $sp = Get-ItemProperty -Path $servKey -ErrorAction Stop
        if ($null -ne $sp.UEFICA2023Error -and [int64]$sp.UEFICA2023Error -ne 0) {
            $problems.Add(("Existing UEFICA2023Error present: 0x{0:x} (resolve before re-triggering)." -f [int64]$sp.UEFICA2023Error))
        }
    } catch { }

    return $problems
}

if ($SkipPrereqGate) {
    Write-Host "[WARN] Prerequisite gate SKIPPED by -SkipPrereqGate."
} else {
    Write-Host "----- PREREQUISITE GATE ---------------------------------------"
    $gateProblems = Test-Gate
    if ($gateProblems.Count -gt 0) {
        Write-Host "[GATE FAILED] The following must be resolved before deployment:"
        $n = 1
        foreach ($p in $gateProblems) { Write-Host (" {0}. {1}" -f $n, $p); $n++ }
        $abort = $true
    } else {
        Write-Host "[GATE PASSED] Core prerequisites met."
    }
    Write-Host ""
}

if ($abort) {
    Write-Host "==============================================================="
    Write-Host " RESULT: ABORTED - prerequisites not met. No changes made."
    Write-Host "==============================================================="
    Write-Host "NCENTRAL:DEPLOY_RESULT=ABORTED_PREREQ"
    Write-Host "NCENTRAL:SCRIPT_VERSION=$ScriptVersion"
    return
}

# ---------------------------------------------------------------------------
# 2. Report current state before acting
# ---------------------------------------------------------------------------
$preProps = $null
try { $preProps = Get-ItemProperty -Path $servKey -ErrorAction Stop } catch { }
$preStatus  = if ($preProps.UEFICA2023Status) { $preProps.UEFICA2023Status } else { 'Not started' }
$preCapable = if ($null -eq $preProps.WindowsUEFICA2023Capable) { 'absent' } else { "$($preProps.WindowsUEFICA2023Capable)" }
$preAvail   = if ($null -eq $preProps.AvailableUpdates) { 'absent' } else { ('0x{0:x}' -f [int64]$preProps.AvailableUpdates) }
Write-Host "----- CURRENT STATE -------------------------------------------"
Write-Host " UEFICA2023Status        : $preStatus"
Write-Host " WindowsUEFICA2023Capable: $preCapable (reference only)"
Write-Host " AvailableUpdates        : $preAvail"
Write-Host ""

# If DB cert already enrolled (Capable >= 1), Step 1 is a no-op per MS guidance.
$capableVal = if ($null -eq $preProps.WindowsUEFICA2023Capable) { -1 } else { [int]$preProps.WindowsUEFICA2023Capable }

# ---------------------------------------------------------------------------
# 3. Helper to apply one staged flag and trigger the task
# ---------------------------------------------------------------------------
function Invoke-Flag {
    param(
        [int]$FlagValue,
        [string]$Label
    )
    $hex = ('0x{0:x}' -f $FlagValue)
    if ($Execute) {
        Write-Host "[EXEC] $Label - setting AvailableUpdates = $hex"
        Set-ItemProperty -Path $servKey -Name 'AvailableUpdates' `
            -Value $FlagValue -Type DWord -ErrorAction Stop
        $actionsTaken.Add("Set AvailableUpdates=$hex ($Label)")

        Write-Host "[EXEC] $Label - starting scheduled task $taskName"
        try {
            Start-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop
        } catch {
            Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
        }
        $actionsTaken.Add("Started $taskName ($Label)")

        # Give the task a moment; it runs asynchronously.
        Start-Sleep -Seconds 5
        Write-Host "[EXEC] $Label - task triggered (runs asynchronously)."
    } else {
        Write-Host "[DRYRUN] WOULD set AvailableUpdates = $hex then start $taskName ($Label)."
    }
}

# ---------------------------------------------------------------------------
# 4. Execute the staged sequence
# ---------------------------------------------------------------------------
Write-Host "----- DEPLOYMENT ACTIONS --------------------------------------"

if ($capableVal -ge 1) {
    Write-Host "[SKIP] DB cert already present (Capable=$capableVal). Skipping Step 1 (0x40)."
} else {
    Invoke-Flag -FlagValue $FLAG_DB_CERT -Label 'Step 1: enroll DB cert'
}

if ($Stage -eq 'Full') {
    Invoke-Flag -FlagValue $FLAG_BOOTMGR -Label 'Step 2: stage boot manager'
} else {
    Write-Host "[INFO] Stage=Db: Step 2 (boot manager 0x100) intentionally NOT performed."
}
Write-Host ""

# ---------------------------------------------------------------------------
# 5. Post-action state read (informational)
# ---------------------------------------------------------------------------
$postProps = $null
try { $postProps = Get-ItemProperty -Path $servKey -ErrorAction Stop } catch { }
$postStatus  = if ($postProps.UEFICA2023Status) { $postProps.UEFICA2023Status } else { 'Not started' }
$postCapable = if ($null -eq $postProps.WindowsUEFICA2023Capable) { 'absent' } else { "$($postProps.WindowsUEFICA2023Capable)" }
$postErrRaw  = $postProps.UEFICA2023Error
$postErr     = if ($null -ne $postErrRaw) { ('0x{0:x}' -f [int64]$postErrRaw) } else { 'none' }

Write-Host "----- POST-ACTION STATE ---------------------------------------"
Write-Host " UEFICA2023Status        : $postStatus"
Write-Host " WindowsUEFICA2023Capable: $postCapable (reference only)"
Write-Host " UEFICA2023Error         : $postErr"
if ($null -ne $postErrRaw -and [int64]$postErrRaw -ne 0 -and $Stage -eq 'Full' -and $Execute) {
    Write-Host ""
    Write-Host " NOTE: A UEFICA2023Error after staging the boot manager is EXPECTED."
    Write-Host "       It typically means 'boot manager staged, awaiting reboot' -"
    Write-Host "       NOT a failed end state. It should clear after the next reboot."
}
Write-Host ""

# ---------------------------------------------------------------------------
# 6. Summary + reboot guidance (this script does NOT reboot)
# ---------------------------------------------------------------------------
Write-Host "==============================================================="
if (-not $Execute) {
    Write-Host " RESULT: DRY RUN COMPLETE - no changes were made."
    Write-Host " Re-run with -Execute during your maintenance window to apply."
    $deployResult = 'DRYRUN'
} else {
    Write-Host " RESULT: DEPLOYMENT TRIGGER COMPLETE"
    Write-Host " Actions taken:"
    foreach ($a in $actionsTaken) { Write-Host "   - $a" }
    Write-Host ""
    Write-Host " A REBOOT IS REQUIRED to complete the boot-manager transition"
    Write-Host " (Capable -> 2). This script did NOT reboot. Schedule the reboot"
    Write-Host " in your normal maintenance window, then re-run the phase-1 audit"
    Write-Host " to verify UEFICA2023Status = Updated / Capable = 2."
    $deployResult = if ($actionsTaken.Count -gt 0) { 'TRIGGERED' } else { 'NOOP' }
}
Write-Host "==============================================================="
Write-Host ""

# ---------------------------------------------------------------------------
# MACHINE-PARSEABLE OUTPUT FOR N-CENTRAL (matches phase-1 token style)
# ---------------------------------------------------------------------------
Write-Host "----- NCENTRAL SCRAPE TOKENS ----------------------------------"
Write-Host ("NCENTRAL:DEPLOY_RESULT={0}"     -f $deployResult)   # DRYRUN|TRIGGERED|NOOP|ABORTED_*
Write-Host ("NCENTRAL:UEFI_STATUS={0}"       -f $postStatus)
Write-Host ("NCENTRAL:CAPABLE_REF={0}"       -f $postCapable)
Write-Host ("NCENTRAL:UEFI_ERROR={0}"        -f $postErr)
Write-Host ("NCENTRAL:REBOOT_REQUIRED={0}"   -f $(if ($Execute -and $deployResult -eq 'TRIGGERED') { 'True' } else { 'False' }))
Write-Host ("NCENTRAL:SCRIPT_VERSION={0}"    -f $ScriptVersion)
