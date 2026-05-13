#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Patch Compliance Check & Remediation Script
    Combined check + targeted remediation. Designed for N-central
    "Run a Script" deployment.

    Supported operating systems (build number >= 9200):
        Windows 8.1                  (build 9600)
        Windows 10  (all branches)   (build 10240+)
        Windows 11  (all branches)   (build 22000+)
        Windows Server 2012          (build 9200)
        Windows Server 2012 R2       (build 9600)
        Windows Server 2016          (build 14393)
        Windows Server 2019          (build 17763)
        Windows Server 2022          (build 20348)
        Windows Server 2025          (build 26100)

    Explicitly NOT supported:
        Windows 7 / Server 2008 / Server 2008 R2 (and earlier).

.DESCRIPTION
    PHASE 1 - CHECK
        V13 check functions plus an LCU bookkeeping-health signal.
        No state changes.

    PHASE 2 - REMEDIATE  (V4: gated; runs only what Phase 1 indicates)
        | Step                          | Runs when                                     |
        | ----------------------------- | --------------------------------------------- |
        | Disk cleanup                  | Free < (MinFreeGB+10) OR LCU stale OR -ForceCleanup |
        | Service health (observation)  | Always (cheap)                                |
        | WU Component Reset            | WU services degraded OR WUA COM not reachable |
        |                               | OR bookkeeping degraded AND no recent .bak    |
        |                               | OR -ForceComponentReset                       |
        | pending.xml rename            | pending.xml exists AND >threshold days        |
        | w32tm /resync /force          | TimeSync WARN/FAIL                            |
        | DISM /CheckHealth             | Always (1-2 sec)                              |
        | DISM /ScanHealth              | CheckHealth flagged damage OR -ForceFullDISM  |
        | DISM /RestoreHealth           | ScanHealth found damage                       |
        | sfc /scannow                  | DISM ScanHealth found damage OR -ForceSfc     |
        | Force WU detection            | Always (cheap; sets up Phase 3 demote logic)  |
        | Install applicable updates    | -InstallApplicable AND >0 found               |

        Aggressive WU recipe (when triggered):
          stop services -> rename SoftwareDistribution + catroot2 ->
          clear BITS qmgr*.dat -> regsvr32 WU/COM DLLs (deprecated DLLs
          on Win10/Server 2016+ are flagged SKIPPED, not FAILED) ->
          reset WinHTTP proxy (skipped if a proxy is configured) ->
          restart services -> prune .bak-* folders older than $BakRetentionDays.

        WSUS / N-central PME safe: never modifies HKLM\SOFTWARE\Policies\
        Microsoft\Windows\WindowsUpdate.

        Never reboots.

    PHASE 3 - RE-CHECK
        Re-runs the previously-failing checks. v4 demotes LCU
        bookkeeping failures to "deferred" when the WU detection
        step succeeded - the stack is functional and history will
        repopulate as patches install.

    REPORT
        V13-style with PRE-FLIGHT, REMEDIATIONS APPLIED, BEFORE/AFTER
        comparison sections. Mirrored to a transcript file for
        N-central truncation insurance.

.NOTES
    Exit codes (for N-central):
        0 = PASS or REMEDIATED
        1 = WARN or PARTIAL
        2 = FAIL or UNSUPPORTED OS

    Version : v4.19 (Two tactical polish items observed in v4.18 runs:
                     1) sfc /scannow returning exit 1 in under 60s
                        with no recognised output phrase is now
                        recorded as FAILED rather than INFO. A real
                        SFC scan takes several minutes; a fast
                        non-zero exit means SFC bailed out before
                        actually scanning (typically Trusted
                        Installer access or component-store
                        integrity issues). Cases where SFC ran a
                        full scan and exited non-zero with a
                        recognised diagnostic phrase
                        ("successfully repaired", "found corrupt
                        files but was unable to fix", etc.) still
                        record as INFO so the diagnostic detail is
                        preserved.
                     2) wuapi.dll added to the deprecated-DLLs skip
                        list. On Windows 10/11 the file's ACL/MIC
                        makes regsvr32 consistently return exit 5
                        (access denied). Joining the existing
                        skips for mshtml/shdocvw/browseui/wuaueng/
                        qmgr removes the noise from the re-register
                        step's failure tally - the step will now
                        report "OK (19 ok / 0 failed / 6 skipped)"
                        on healthy modern Windows hosts.)
              v4.18 (Captured-process wrapper rewritten to use
                     [System.Diagnostics.Process]::Start with async
                     stream reads instead of Start-Process -PassThru
                     with temp-file redirection. The .NET API gives
                     a reliably-populated ExitCode after WaitForExit
                     even in non-interactive hosting contexts, where
                     Start-Process's returned object could leave
                     ExitCode null. Async stream reads via
                     ReadToEndAsync prevent the stderr-buffer-fill
                     hang that v4.11 worked around with /Quiet.
                     Three concrete improvements:
                     1) Reliable ExitCode reading on DISM/SFC/regsvr32
                        - the "no exit code returned" pattern observed
                          across many hosts was a wrapper bug, not a
                          DISM/SFC problem.
                     2) Progress-line filter regex extended to match
                        SFC's "Verification NN% complete." format
                        in addition to DISM's "[=====] N.N%" so the
                        diagnostic block no longer dumps hundreds of
                        progress lines.
                     3) When DISM produces no captured output (because
                        of /Quiet), wrapper now tails dism.log entries
                        inside the step's time window and surfaces the
                        last ~20 lines as fallback diagnostic context.
                     No call-site changes - existing 5 callers in
                     Invoke-DiskCleanupRemediation and
                     Invoke-ComponentStoreRepair work unchanged.)
              v4.17 (New Phase 1 check Test-FeatureUpdateReadiness and
                     gated Phase 2 remediation. Detects: TargetReleaseVersion
                     / ProductVersion / DeferFeatureUpdates* policy pins,
                     AllowTelemetry level, CPU SSE4.2 support via P/Invoke
                     to kernel32!IsProcessorFeaturePresent, stale upgrade
                     artifacts ($WINDOWS.~BT, $WINDOWS.~WS, Windows.old)
                     with age and size, 64 GB feature-update disk band,
                     WSUS-managed status, and a registry heuristic for
                     safeguard holds. Skipped on Server SKUs and on hosts
                     already at 24H2 or later (build 26100+). Phase 2
                     always cleans stale artifacts older than 14 days; the
                     new -UnblockFeatureUpdates switch additionally
                     removes the policy pins, zeroes DeferFeatureUpdates,
                     raises AllowTelemetry from 0 to 1, and runs
                     gpupdate /force. WU registry is backed up before
                     any destructive policy change.)
              v4.16 (Per-step "timeout NN min" log messages updated
                     to reflect that v4.13 removed those caps - each
                     DISM/SFC step now uses the remaining wall-clock
                     budget as its deadline. Also adds output-tail
                     diagnostics inside the captured-command wrapper:
                     when ExitCode comes back null after WaitForExit
                     the wrapper now logs the last ~15 non-empty lines
                     of captured stdout/stderr so operators can tell
                     a silently-successful run apart from a real
                     error masked by the unreadable exit code.)
              v4.15 (Sanitised: removed author, repo, and per-incident
                     host references from the changelog and code
                     comments. No code or behaviour changes.)
              v4.14 (Test-DiskSpace format-string fix: outer parens
                     around the concatenated message so '-f' applies
                     to the whole assembled string. Both WARN and
                     FAIL branches.)
              v4.13 (Wall-clock budget default 50 -> 120 min.
                     Per-step TimeoutSec on DISM /CheckHealth,
                     /ScanHealth, /RestoreHealth,
                     /StartComponentCleanup, and sfc /scannow
                     removed. Both timeout wrappers default to
                     remaining budget when TimeoutSec is omitted.)
              v4.12 (Phase-1 LCU lookup chain reordered to make WUA
                     COM the primary source. Get-HotFix and
                     Win32_QuickFixEngineering wrapped in a 60s
                     job-based timeout to fail-fast on broken WMI
                     providers. Pre-flight booleans default to $null
                     and render as 'Unknown' when Phase 2 pre-flight
                     has not run.)
              v4.11 (DISM /Quiet flag added on every DISM call;
                     wrapper redirects stderr to a temp file. Closes
                     a stderr-buffer-fill hang in non-interactive
                     hosting contexts.)
              v4.10 (DISM LOG ERROR SUMMARY always renders when any
                     DISM step failed. sfc /scannow with null/empty
                     ExitCode now FAILED, not INFO. New
                     REBOOT_REQUIRED outcome (exit 0) for CBS-only
                     pending-reboot blockers.)
              v4.9  (DISM log auto-triage: tail dism.log, extract
                     recent HRESULTs, translate common codes to
                     plain English. New DISM LOG ERROR SUMMARY
                     section in the report.)
              v4.8  (Symmetric ScanHealth escalation: non-zero
                     /ScanHealth proceeds to /RestoreHealth.)
              v4.7  (Truncated-step demote: REMEDIATED -> PARTIAL.
                     Empty-exit-code messaging consistent across
                     DISM/SFC. Dynamic version footer.)
              v4.6  (.Count fix in report tally. DISM /CheckHealth
                     failure escalates to ScanHealth. WaitForExit()
                     guarantees ExitCode is populated.)
              v4.5  (Tightened /StartComponentCleanup gating;
                     disk-low buffer set to MinFreeGB+5; WU-degraded
                     hosts skip cleanup so RestoreHealth gets the
                     budget.)
              v4.3  (Hard time budget + bounded long-running ops:
                     DISM/SFC wrapped with per-step kill-on-timeout;
                     DISM order biased to fix-first/cleanup-last;
                     report guaranteed via try/finally.)
              v4.2  (Report headline leads with post-remediation
                     outcome.)
              v4.1  (StrictMode fix in report tally.)
              v4    (Gating layer; deprecated-DLL handling; reg.exe
                     stdout redirected; .bak prune;
                     -InstallApplicable; before/after column trim.)
              v3    (Reliability + observability pass.)
              v2    (OS gate added; refuses Win 7 / Server 2008 /
                     2008 R2.)
              v1    (Initial.)
#>

# ============================================================
#  CONFIGURATION
# ============================================================
param(
    [int]    $PatchStaleDays    = 55,
    [int]    $MinFreeGB         = 25,
    [int]    $UptimeWarnDays    = 30,
    [int]    $UptimeFailDays    = 60,
    [int]    $TimeSyncWarnSec   = 60,
    [int]    $TimeSyncFailSec   = 300,
    [int]    $PendingXmlAgeDays = 30,
    [int]    $BakRetentionDays  = 30,

    [switch] $SkipRecheck,
    [switch] $ForceComponentReset,
    [switch] $ForceFullDISM,
    [switch] $ForceSfc,
    [switch] $ForceCleanup,
    [switch] $InstallApplicable,
    [switch] $ForceAll,

    # v4.17: opt-in unblock for feature-update readiness blockers.
    # When set, the Phase 2 remediation removes TargetReleaseVersion /
    # ProductVersion policy pins, zeroes DeferFeatureUpdates*, and raises
    # AllowTelemetry from 0 to 1. WU registry is backed up first. Without
    # this switch the readiness check still reports blockers but the
    # policy/telemetry keys are not touched.
    [switch] $UnblockFeatureUpdates,

    # Hard wall-clock budget for the entire script.
    # Default chosen to match an N-central "Run a Script" 2-hour wall
    # exactly. There is no headroom for the report writer or transcript
    # stop in that configuration: if a step runs to the very end of the
    # budget the final report may not ship, and the on-host transcript
    # file is the fallback record. Pass a smaller -MaxRuntimeMinutes if
    # you'd rather leave headroom for reporting (e.g. 110 for 10 min of
    # buffer under a 120-min host wall).
    [int]    $MaxRuntimeMinutes = 120
)

if ($ForceAll) {
    $ForceComponentReset = $true
    $ForceFullDISM       = $true
    $ForceSfc            = $true
    $ForceCleanup        = $true
}

# ============================================================
#  EXECUTION POLICY BYPASS
# ============================================================
try {
    $currentPolicy = Get-ExecutionPolicy -Scope Process
    if ($currentPolicy -ne 'Bypass' -and $currentPolicy -ne 'Unrestricted') {
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop
    }
}
catch {
    Write-Host "[WARN] Could not set process execution policy to Bypass: $_"
}

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ============================================================
#  GLOBAL STATE
# ============================================================
$Script:Version        = "v4.19"
$Script:ScriptName     = "Remediate-PatchCompliance$Script:Version.ps1"
$Script:Log            = [System.Collections.Generic.List[string]]::new()
$Script:Results        = [ordered]@{}
$Script:OverallStatus  = "PASS"
$Script:RemediationOutcome = "NONE"
$Script:Remediations   = [System.Collections.Generic.List[object]]::new()
$Script:PreCheckSnapshot = [ordered]@{}
$Script:Environment    = [ordered]@{
    # v4.12: pre-flight booleans default to $null so the report can
    # distinguish 'never detected' (Phase-1 crash) from 'detected = No'.
    # All three are populated by the Phase 2 pre-flight functions.
    IsServer             = $null
    IsDomainController   = $null
    WsusManaged          = $null
    HasPSWindowsUpdate   = $false
    RegBackupPath        = $null
    TranscriptPath       = $null
    RemediationStartTime = $null
    RemediationEndTime   = $null
    OSBuild              = 0
    IsModernWindows      = $false
}

# ============================================================
#  TIME BUDGET (v4.3)
# ============================================================
$Script:StartUtc    = (Get-Date).ToUniversalTime()
$Script:DeadlineUtc = $Script:StartUtc.AddMinutes($MaxRuntimeMinutes)
$Script:TruncatedSteps = [System.Collections.Generic.List[string]]::new()
# v4.9: collect DISM log findings for the report (most recent HRESULT
# per failed step, plus a top-N summary section).
$Script:DISMFindings   = [System.Collections.Generic.List[object]]::new()
$Script:CBSRebootOnly  = $false  # v4.10: set true if only blocker is CBS pending reboot
$Script:DISMAttempted  = $false  # v4.10: set true once any DISM step has been launched

function Get-RemainingBudgetSec {
    [int][math]::Max(0, ($Script:DeadlineUtc - (Get-Date).ToUniversalTime()).TotalSeconds)
}

function Test-RemainingBudget {
    param([int]$NeededSec = 0)
    return ((Get-RemainingBudgetSec) -gt $NeededSec)
}

function Format-Budget {
    $sec = Get-RemainingBudgetSec
    "{0}m{1:00}s remaining of {2}m budget" -f [int]([math]::Floor($sec/60)), ($sec%60), $MaxRuntimeMinutes
}

# ============================================================
#  HELPER: Invoke-CmdletWithTimeout (v4.12)
#  Bounds an arbitrary in-process cmdlet (Get-HotFix,
#  Get-CimInstance, etc.) so it cannot wedge Phase 1 when the
#  underlying provider is broken (corrupt WMI repository, dead
#  CIM provider, hung DCOM endpoint).
#
#  Pattern: run the scriptblock in a child Start-Job, Wait-Job
#  with a hard timeout, kill the job on timeout. The job runs
#  in its own runspace so cancelling it cannot leave the parent
#  runspace in a half-cancelled CIM state.
#
#  Returns @{ Success; TimedOut; Result; Error; Duration }
#  Caller decides what to do on timeout - usually log a WARN
#  and treat the data source as 'Unknown', then fall through.
# ============================================================
function Invoke-CmdletWithTimeout {
    param(
        [Parameter(Mandatory)] [scriptblock]$ScriptBlock,
        # v4.13: TimeoutSec is now optional. When omitted (or set to 0)
        # the cmdlet inherits the remaining wall-clock budget as its
        # deadline - "take as long as you need, but at most the rest
        # of the script's budget". Callers that want a hard fail-fast
        # cap (e.g. the WMI probes that should give up after 60s on a
        # broken provider) still pass an explicit TimeoutSec.
        [int]$TimeoutSec = 0,
        [string]$Label = "(unnamed cmdlet)",
        [object[]]$ArgumentList = @()
    )

    # Default TimeoutSec to remaining script budget. Cap any caller-
    # supplied value at the remaining budget so we never blow past
    # the wall-clock deadline waiting on a hung cmdlet.
    $remaining = Get-RemainingBudgetSec
    if ($remaining -le 0) {
        return @{
            Success  = $false
            TimedOut = $true
            Result   = $null
            Error    = "no remaining script budget; cmdlet skipped"
            Duration = 0
        }
    }
    if ($TimeoutSec -le 0) {
        $TimeoutSec = $remaining
    } elseif ($TimeoutSec -gt $remaining) {
        Write-Log ("  [budget] {0}: capping cmdlet timeout at {1}s (remaining script budget)" -f $Label, $remaining)
        $TimeoutSec = $remaining
    }

    $start = Get-Date
    $job   = $null
    try {
        $job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop
        $finished = Wait-Job -Job $job -Timeout $TimeoutSec

        if (-not $finished) {
            # Hung. Kill the job (Stop-Job + Remove-Job -Force) so its
            # runspace is torn down even if the cmdlet inside it is
            # blocked in unmanaged code.
            Write-Log ("  [TIMEOUT] {0} exceeded {1}s; stopping background job" -f $Label, $TimeoutSec) "WARN"
            try { Stop-Job   -Job $job -ErrorAction SilentlyContinue | Out-Null } catch {}
            try { Remove-Job -Job $job -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
            return @{
                Success  = $false
                TimedOut = $true
                Result   = $null
                Error    = "cmdlet exceeded ${TimeoutSec}s timeout"
                Duration = ((Get-Date) - $start).TotalSeconds
            }
        }

        # Capture both result and any non-terminating errors that the
        # job emitted on its error stream.
        $result   = Receive-Job -Job $job -ErrorAction SilentlyContinue -ErrorVariable jobErr
        $errText  = if ($jobErr -and $jobErr.Count -gt 0) { ($jobErr | ForEach-Object { $_.ToString() }) -join "; " } else { $null }
        $jobState = $job.State
        try { Remove-Job -Job $job -Force -ErrorAction SilentlyContinue | Out-Null } catch {}

        return @{
            Success  = ($jobState -eq 'Completed' -and -not $errText)
            TimedOut = $false
            Result   = $result
            Error    = $errText
            Duration = ((Get-Date) - $start).TotalSeconds
        }
    }
    catch {
        if ($job) { try { Remove-Job -Job $job -Force -ErrorAction SilentlyContinue | Out-Null } catch {} }
        return @{
            Success  = $false
            TimedOut = $false
            Result   = $null
            Error    = "$_"
            Duration = ((Get-Date) - $start).TotalSeconds
        }
    }
}


# ============================================================
#  HELPER: Invoke-CapturedCommandWithTimeout (v4.3)
#  Like Invoke-CapturedCommand but kills the process if it
#  exceeds TimeoutSec. Returns a hashtable that includes a
#  TimedOut flag so callers can log a TIMEOUT result instead
#  of a generic FAILED.
# ============================================================
function Invoke-CapturedCommandWithTimeout {
    param(
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter(Mandatory)] [string[]]$ArgumentList,
        # v4.13: TimeoutSec is now optional. When omitted (or set to 0)
        # the step inherits the remaining wall-clock budget as its
        # deadline. The N-central wall is the only ceiling.
        [int]$TimeoutSec = 0,
        [string]$OutputEncoding = "Default",
        [string]$Label = "(unnamed step)"
    )

    # Default TimeoutSec to remaining script budget. Cap any caller-
    # supplied value at the remaining budget so we never outlast
    # N-central's wall.
    $remaining = Get-RemainingBudgetSec
    if ($remaining -le 0) {
        return @{
            ExitCode = -2
            Output   = ""
            Duration = 0
            TimedOut = $true
            Reason   = "no remaining script budget; step skipped"
        }
    }
    if ($TimeoutSec -le 0) {
        $TimeoutSec = $remaining
    } elseif ($TimeoutSec -gt $remaining) {
        Write-Log ("  [budget] {0}: capping step timeout at {1}s (remaining script budget)" -f $Label, $remaining)
        $TimeoutSec = $remaining
    }

    $start    = Get-Date
    $proc     = $null
    $timedOut = $false
    $stdoutTask = $null
    $stderrTask = $null

    # v4.18: progress-line regex matches both DISM's bracketed bar
    # (e.g. "[=====        ]   23.5%") AND SFC's "Verification NN% complete."
    # output. Used to keep the diagnostic block readable on slow SFC runs
    # that emit ~150 progress lines.
    $progressRegex = '^(\[=*\s*\]\s+\d+\.\d+%|Verification \d+% complete\.)$'

    try {
        # v4.18: use [System.Diagnostics.Process]::Start with async stream
        # reads instead of Start-Process -PassThru + temp-file redirection.
        # Two wins:
        #   1) ExitCode is populated reliably after WaitForExit() (the
        #      Start-Process-returned object loses ExitCode in some
        #      non-interactive hosting contexts - the long-running mystery
        #      behind the "no exit code returned" reports on DISM/SFC).
        #   2) ReadToEndAsync() drains stdout/stderr concurrently so the
        #      child cannot block on a full stderr pipe - replaces the
        #      temp-file redirection mechanism v4.11 introduced. /Quiet
        #      can still be passed for DISM, but is no longer strictly
        #      necessary to avoid hangs.
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName               = $FilePath
        $psi.Arguments              = ($ArgumentList -join ' ')
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.UseShellExecute        = $false
        $psi.CreateNoWindow         = $true
        $psi.WindowStyle            = 'Hidden'
        if ($OutputEncoding -eq "Unicode") {
            $psi.StandardOutputEncoding = [System.Text.Encoding]::Unicode
            $psi.StandardErrorEncoding  = [System.Text.Encoding]::Unicode
        }

        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi
        $launched = $false
        try { $launched = $proc.Start() } catch {
            return @{
                ExitCode = -1
                Output   = "Process.Start threw: $_"
                Duration = ((Get-Date) - $start).TotalSeconds
                TimedOut = $false
                Error    = "$_"
            }
        }
        if (-not $launched) {
            return @{
                ExitCode = -1
                Output   = "Process.Start returned false (process did not launch)"
                Duration = ((Get-Date) - $start).TotalSeconds
                TimedOut = $false
                Error    = "Process did not start"
            }
        }

        # Start async stream reads to drain pipes continuously
        $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
        $stderrTask = $proc.StandardError.ReadToEndAsync()

        # Poll for exit with budget-bounded deadline
        $deadline = $start.AddSeconds($TimeoutSec)
        while (-not $proc.HasExited) {
            if ((Get-Date) -ge $deadline) { $timedOut = $true; break }
            Start-Sleep -Seconds 1
        }

        if ($timedOut) {
            Write-Log ("  [TIMEOUT] {0} exceeded {1}s; killing PID {2} and any children" -f $Label, $TimeoutSec, $proc.Id) "WARN"
            try {
                # taskkill /T kills the whole tree. DISM forks workers.
                Start-Process -FilePath "taskkill.exe" -ArgumentList @('/F','/T','/PID',[string]$proc.Id) `
                              -NoNewWindow -Wait -ErrorAction SilentlyContinue | Out-Null
            } catch {}
            try { if (-not $proc.HasExited) { $proc.Kill() } } catch {}
            $Script:TruncatedSteps.Add($Label) | Out-Null
        }

        # Ensure WaitForExit so ExitCode is finalised (idempotent)
        try { $proc.WaitForExit() } catch {}

        # Collect captured streams from the async tasks
        $stdout = ""
        $stderr = ""
        try { $stdout = $stdoutTask.GetAwaiter().GetResult() } catch {}
        try { $stderr = $stderrTask.GetAwaiter().GetResult() } catch {}

        # Filter progress-bar / SFC-progress lines and blanks from both
        if ($stdout) {
            $stdout = (($stdout -split "`r?`n") | Where-Object {
                ($_ -notmatch $progressRegex) -and ($_.Trim() -ne '')
            }) -join "`n"
        }
        if ($stderr) {
            $stderr = (($stderr -split "`r?`n") | Where-Object {
                ($_ -notmatch $progressRegex) -and ($_.Trim() -ne '')
            }) -join "`n"
        }

        $output = if ($stdout -and $stderr) { "$stdout`n[stderr]`n$stderr" }
                  elseif ($stdout)          { $stdout }
                  elseif ($stderr)          { "[stderr]`n$stderr" }
                  else                       { "" }

        $exitCode = if ($timedOut) { -1 } else { $proc.ExitCode }

        # v4.18: when DISM produced no captured output (likely /Quiet),
        # tail dism.log for entries inside the step's time window so the
        # operator can still see what DISM did.
        if (-not $timedOut -and -not $output -and ((Split-Path -Leaf $FilePath).ToLowerInvariant()) -eq 'dism.exe') {
            $dismLog = Join-Path $env:WINDIR 'Logs\DISM\dism.log'
            if (Test-Path -LiteralPath $dismLog) {
                try {
                    $stepStartIso = $start.ToString('yyyy-MM-dd HH:mm:ss')
                    $stepEndIso   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                    $logTail = Get-Content -LiteralPath $dismLog -Tail 400 -ErrorAction SilentlyContinue
                    if ($logTail) {
                        $inWindow = $logTail | Where-Object {
                            if ($_ -match '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})') {
                                $ts = $Matches[1]
                                ($ts -ge $stepStartIso) -and ($ts -le $stepEndIso)
                            } else { $false }
                        } | Select-Object -Last 20
                        if ($inWindow -and $inWindow.Count -gt 0) {
                            $output = "[dism.log tail (step window)]`n" + ($inWindow -join "`n")
                        }
                    }
                } catch {}
            }
        }

        # v4.16/v4.18: diagnostic surfacing when ExitCode is null/empty
        # despite the step not timing out. With the v4.18 wrapper rewrite
        # this should become rare, but it stays as a safety net for any
        # process where .NET still can't populate ExitCode.
        if (-not $timedOut -and ($null -eq $exitCode -or "$exitCode" -eq "")) {
            if ($output) {
                $tailLines = @(
                    $output -split "`r?`n" |
                        Where-Object {
                            $_ -ne $null -and
                            $_.Trim() -ne '' -and
                            $_ -notmatch $progressRegex
                        } |
                        Select-Object -Last 15
                )
                if ($tailLines.Count -gt 0) {
                    Write-Log ("  [diagnostic] {0}: ExitCode unreadable; last {1} captured line(s):" -f $Label, $tailLines.Count) "WARN"
                    foreach ($ln in $tailLines) {
                        Write-Log ("    | " + $ln) "WARN"
                    }
                } else {
                    Write-Log ("  [diagnostic] {0}: ExitCode unreadable and captured output had no non-empty non-progress content." -f $Label) "WARN"
                }
            } else {
                Write-Log ("  [diagnostic] {0}: ExitCode unreadable and no captured output (process may have failed to start)." -f $Label) "WARN"
            }
        }

        return @{
            ExitCode = $exitCode
            Output   = $output
            Duration = ((Get-Date) - $start).TotalSeconds
            TimedOut = $timedOut
        }
    }
    catch {
        return @{
            ExitCode = -1
            Output   = "$_"
            Duration = ((Get-Date) - $start).TotalSeconds
            TimedOut = $false
            Error    = "$_"
        }
    }
    finally {
        if ($proc) { try { $proc.Dispose() } catch {} }
    }
}


# ============================================================
#  HELPER: Write-Log
# ============================================================
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Level] $Message"
    $Script:Log.Add($line)
    Write-Host $line
}

# ============================================================
#  HELPER: Set-Status
# ============================================================
function Set-Status {
    param([string]$NewStatus)
    $priority = @{ PASS = 0; WARN = 1; FAIL = 2 }
    if ($priority[$NewStatus] -gt $priority[$Script:OverallStatus]) {
        $Script:OverallStatus = $NewStatus
    }
}

# ============================================================
#  HELPER: Add-Remediation
# ============================================================
function Add-Remediation {
    param(
        [string]$Step,
        [ValidateSet("OK","FAILED","SKIPPED","INFO")] [string]$Result,
        [string]$Detail = "",
        [string]$ErrorMessage = "",
        [double]$DurationSec = 0
    )
    $entry = [ordered]@{
        Step     = $Step
        Result   = $Result
        Detail   = $Detail
        Error    = $ErrorMessage
        Duration = $DurationSec
        Time     = Get-Date -Format "HH:mm:ss"
    }
    $Script:Remediations.Add([pscustomobject]$entry) | Out-Null

    $level = switch ($Result) { "FAILED" {"ERROR"} "SKIPPED" {"WARN"} default {"REMEDIATE"} }
    $durStr = if ($DurationSec -gt 0) {
        if ($DurationSec -ge 60) { "  ({0:N0}m{1:N0}s)" -f [math]::Floor($DurationSec/60), ($DurationSec%60) }
        else                      { "  ({0:N0}s)" -f $DurationSec }
    } else { "" }
    $msg = "[REMEDIATION] $Step -> $Result$durStr" + $(if ($Detail) {"  ($Detail)"} else {""}) + $(if ($ErrorMessage) {"  ERR: $ErrorMessage"} else {""})
    Write-Log $msg -Level $level
}

# ============================================================
#  HELPER: Test-SupportedOS
# ============================================================
function Test-SupportedOS {
    Write-Log "=== OS gate: verifying supported Windows version ==="
    $minBuild = 9200

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    } catch {
        Write-Host ""
        Write-Host "================================================================="
        Write-Host "  REMEDIATE-PATCHCOMPLIANCE - UNSUPPORTED ENVIRONMENT"
        Write-Host "  Could not query Win32_OperatingSystem: $_"
        Write-Host "  Refusing to run."
        Write-Host "================================================================="
        exit 2
    }

    $build = 0
    [void][int]::TryParse([string]$os.BuildNumber, [ref]$build)
    $caption = $os.Caption
    $Script:Environment.OSBuild         = $build
    $Script:Environment.IsModernWindows = ($build -ge 14393)

    if ($build -lt $minBuild) {
        Write-Host ""
        Write-Host "================================================================="
        Write-Host "  REMEDIATE-PATCHCOMPLIANCE - UNSUPPORTED OPERATING SYSTEM"
        Write-Host "  Detected : $caption  (build $build)"
        Write-Host "  Required : Windows Server 2012 / Windows 8.1 (build 9200) or later"
        Write-Host ""
        Write-Host "  Windows 7 / Server 2008 / Server 2008 R2 are explicitly NOT"
        Write-Host "  supported by this script."
        Write-Host ""
        Write-Host "  Host        : $env:COMPUTERNAME"
        Write-Host "  Report Time : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        Write-Host "================================================================="
        Write-Host ""
        exit 2
    }

    Write-Log "  OK: $caption (build $build) is at or above the minimum supported build ($minBuild)."
    if ($Script:Environment.IsModernWindows) {
        Write-Log "  Modern Windows detected (>=14393); legacy regsvr32 calls for deprecated DLLs will be SKIPPED."
    }
}
function Get-SystemInfo {
    Write-Log "=== Collecting System Information ==="

    $os   = Get-CimInstance -ClassName Win32_OperatingSystem
    $comp = Get-CimInstance -ClassName Win32_ComputerSystem

    $info = [PSCustomObject]@{
        Hostname        = $env:COMPUTERNAME
        Domain          = $comp.Domain
        OS_Caption      = $os.Caption
        OS_Version      = $os.Version
        OS_BuildNumber  = [string]$os.BuildNumber
        Architecture    = $os.OSArchitecture
        LastBootTime    = $os.LastBootUpTime
        ReportGenerated = (Get-Date)
    }

    $info.PSObject.Properties | ForEach-Object {
        Write-Log ("  {0,-20}: {1}" -f $_.Name, $_.Value)
    }

    $Script:Results["SystemInfo"] = $info
    return $info
}

# ============================================================
#  SECTION 2a - ESU LICENSE CHECK
#  Detects valid Extended Security Update licenses via three
#  methods (slmgr, registry, WMI) and returns a structured
#  result.  Called from Test-WindowsEOL so it can override
#  the EOL flag when a valid ESU is found.
#
#  ESU Y1/Y2/Y3 coverage dates per product:
#    Windows 7 / Server 2008 R2  ESU Y1 ends 2020-01-14
#                                ESU Y2 ends 2021-01-12
#                                ESU Y3 ends 2022-01-11
#    Windows Server 2012 / R2    ESU Y1 ends 2024-10-08
#                                ESU Y2 ends 2025-10-14
#                                ESU Y3 ends 2026-10-13
#    Windows 10 LTSC 2019        ESU Y1 ends 2025-01-14
#                                ESU Y2 ends 2026-01-13
#    Windows 10 (non-LTSC)       Not eligible for ESU
# ============================================================
function Get-ESULicenseStatus {
    Write-Log "=== Checking Extended Security Update (ESU) License ==="

    $esuResult = [ordered]@{
        ESUCapable          = $false   # Is this OS even eligible for ESU?
        ESULicenseFound     = $false   # Did we find any ESU license key/SKU?
        ESULicenseActive    = $false   # Is the license in a Licensed/Active state?
        ESULicenseValid     = $false   # Active AND not yet expired?
        ESUYear             = "N/A"    # Y1 / Y2 / Y3
        ESUExpiryDate       = "N/A"
        ESUActivationMethod = "N/A"    # MAK / Azure Arc / AVMA / WS-Management
        ESUDetails          = ""
        OverridesEOL        = $false   # Final flag consumed by Test-WindowsEOL
    }

    # ---- Identify ESU-eligible builds & their year coverage ----
    # Key: BuildNumber, Value: @(ProductLabel, @{ Year => ExpiryDate }, ESUCapable)
    $esuTable = @{
        # NOTE: Windows 7 / Server 2008 R2 (build 7601) entries removed -
        # those OSes are no longer supported by this script. The OS gate
        # at startup will refuse to run before this table is consulted.

        # Windows Server 2012 (Build 9200)
        "9200"  = @{
            Label   = "Windows Server 2012"
            Capable = $true
            Years   = @{
                "Y1" = [datetime]"2024-10-08"
                "Y2" = [datetime]"2025-10-14"
                "Y3" = [datetime]"2026-10-13"
            }
        }
        # Windows Server 2012 R2 (Build 9600)
        "9600"  = @{
            Label   = "Windows Server 2012 R2"
            Capable = $true
            Years   = @{
                "Y1" = [datetime]"2024-10-08"
                "Y2" = [datetime]"2025-10-14"
                "Y3" = [datetime]"2026-10-13"
            }
        }
        # Windows 10 LTSC 2019 / Server 2019 share build 17763.
        # Server 2019 is still in mainstream support; only Win10 LTSC 2019 needs ESU.
        "17763" = @{
            Label   = "Windows 10 LTSC 2019"
            Capable = $true
            Years   = @{
                "Y1" = [datetime]"2025-01-14"
                "Y2" = [datetime]"2026-01-13"
            }
        }
    }

    $os        = Get-CimInstance -ClassName Win32_OperatingSystem
    $build     = $os.BuildNumber
    $today     = (Get-Date).Date
    $caption   = $os.Caption

    # Server 2019 shares build 17763 - skip ESU check for it (still in mainstream)
    if ($build -eq "17763" -and $caption -match "Server 2019") {
        Write-Log "  Build 17763 is Windows Server 2019 (mainstream support) - ESU not applicable."
        $esuResult.ESUDetails = "Server 2019 is in mainstream support; ESU not required."
        $Script:Results["ESU"] = $esuResult
        return $esuResult
    }

    if (-not $esuTable.ContainsKey($build)) {
        Write-Log "  This OS build ($build) is not in the ESU-eligible build table."
        $esuResult.ESUDetails = "OS build $build is not ESU-eligible (or not yet expired)."
        $Script:Results["ESU"] = $esuResult
        return $esuResult
    }

    $esuEntry           = $esuTable[$build]
    $esuResult.ESUCapable = $esuEntry.Capable
    Write-Log "  OS is ESU-eligible: $($esuEntry.Label)"

    # ----------------------------------------------------------------
    # METHOD 1 - SoftwareLicensingProduct (WMI/CIM)
    #   Microsoft publishes ESU SKU Application IDs.  We search for
    #   any product whose name contains "Extended Security" and whose
    #   LicenseStatus = 1 (Licensed).
    # ----------------------------------------------------------------
    Write-Log "  [Method 1] Querying SoftwareLicensingProduct via CIM..."
    $esuSkus = @()
    try {
        $esuSkus = @(Get-CimInstance -ClassName SoftwareLicensingProduct -ErrorAction Stop |
            Where-Object {
                ($_.Name -like "*Extended Security*" -or
                 $_.Name -like "*ESU*" -or
                 $_.Description -like "*Extended Security*") -and
                $_.LicenseStatus -ne $null
            })
    }
    catch {
        Write-Log "  [Method 1] CIM query failed: $_" -Level "WARN"
    }

    if ($esuSkus.Count -gt 0) {
        $esuResult.ESULicenseFound = $true
        $activeSku = @($esuSkus | Where-Object { $_.LicenseStatus -eq 1 })

        if ($activeSku) {
            $esuResult.ESULicenseActive    = $true
            $esuResult.ESUActivationMethod = "SoftwareLicensing (WMI/MAK or Azure Arc)"
            Write-Log ("  [Method 1] Active ESU SKU found: {0} (LicenseStatus=1)" -f ($activeSku | Select-Object -First 1).Name)
        } else {
            $statuses = ($esuSkus | ForEach-Object { $_.LicenseStatus }) -join ", "
            Write-Log "  [Method 1] ESU SKU(s) found but none are Licensed (statuses: $statuses)" -Level "WARN"
        }
    } else {
        Write-Log "  [Method 1] No ESU SoftwareLicensingProduct entries found."
    }

    # ----------------------------------------------------------------
    # METHOD 2 - Registry sentinel keys written by MAK / Azure Arc ESU
    #   HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ESU
    #   HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ESU
    # ----------------------------------------------------------------
    Write-Log "  [Method 2] Checking ESU registry sentinel keys..."
    $esuRegPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ESU",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ESU"
    )

    foreach ($regPath in $esuRegPaths) {
        if (Test-Path $regPath) {
            try {
                $regValues = Get-ItemProperty -Path $regPath -ErrorAction Stop
                Write-Log "  [Method 2] ESU registry key found: $regPath"

                # Look for any value that contains a date or non-null content
                $regValues.PSObject.Properties |
                    Where-Object { $_.Name -notmatch "^PS" } |
                    ForEach-Object {
                        Write-Log ("    -> {0} = {1}" -f $_.Name, $_.Value)
                    }

                # If the key exists and has values, treat as evidence of ESU
                if (-not $esuResult.ESULicenseFound) {
                    $esuResult.ESULicenseFound = $true
                }
                if (-not $esuResult.ESULicenseActive) {
                    $esuResult.ESULicenseActive    = $true
                    $esuResult.ESUActivationMethod = "Registry sentinel (MAK/Azure Arc)"
                    Write-Log "  [Method 2] ESU activation evidence found in registry."
                }
            }
            catch {
                Write-Log "  [Method 2] Could not read $regPath - $_" -Level "WARN"
            }
        }
    }

    if (-not $esuResult.ESULicenseFound) {
        Write-Log "  [Method 2] No ESU registry sentinel keys found."
    }

    # ----------------------------------------------------------------
    # METHOD 3 - slmgr.vbs /dlv output (fallback text parse)
    #   Captures slmgr output and looks for "Extended Security" lines.
    #   Slower (~5s) but catches edge cases missed by Methods 1 & 2.
    # ----------------------------------------------------------------
    if (-not $esuResult.ESULicenseActive) {
        Write-Log "  [Method 3] Running slmgr.vbs /dlv (may take a few seconds)..."
        try {
            $slmgrOutput = & cscript.exe //NoLogo "$env:SystemRoot\System32\slmgr.vbs" /dlv 2>&1
            $slmgrText   = $slmgrOutput -join "`n"

            if ($slmgrText -match "Extended Security|ESU") {
                Write-Log "  [Method 3] ESU-related entry found in slmgr /dlv output."
                $esuResult.ESULicenseFound = $true

                # Check if status line says "Licensed"
                if ($slmgrText -match "License Status:\s*Licensed") {
                    $esuResult.ESULicenseActive    = $true
                    $esuResult.ESUActivationMethod = "slmgr.vbs /dlv"
                    Write-Log "  [Method 3] ESU license shows 'Licensed' in slmgr output."
                } else {
                    Write-Log "  [Method 3] ESU entry found but License Status is not 'Licensed'." -Level "WARN"
                }
            } else {
                Write-Log "  [Method 3] No ESU entries found in slmgr /dlv output."
            }
        }
        catch {
            Write-Log "  [Method 3] slmgr.vbs execution failed: $_" -Level "WARN"
        }
    }

    # ----------------------------------------------------------------
    # DETERMINE ESU YEAR & EXPIRY
    # Match the detected active license against the ESU year table to
    # confirm it has not itself expired.
    # ----------------------------------------------------------------
    if ($esuResult.ESULicenseActive) {
        # Walk years from highest to lowest; pick the most recent unexpired one
        $validYear  = $null
        $yearsSorted = $esuEntry.Years.GetEnumerator() | Sort-Object { $_.Value } -Descending

        foreach ($yr in $yearsSorted) {
            if ($today -le $yr.Value) {
                $validYear = $yr
            }
        }

        if ($validYear) {
            $esuResult.ESUYear        = $validYear.Key
            $esuResult.ESUExpiryDate  = $validYear.Value.ToString("yyyy-MM-dd")
            $esuResult.ESULicenseValid = $true
            $esuResult.OverridesEOL   = $true
            Write-Log ("  ESU license is VALID - {0} coverage through {1}" -f
                $validYear.Key, $validYear.Value.ToString("yyyy-MM-dd"))
        } else {
            # License was active but all ESU years have expired
            $lastYear   = $esuEntry.Years.GetEnumerator() | Sort-Object { $_.Value } | Select-Object -Last 1
            $esuResult.ESUYear        = $lastYear.Key
            $esuResult.ESUExpiryDate  = $lastYear.Value.ToString("yyyy-MM-dd")
            $esuResult.ESULicenseValid = $false
            $esuResult.OverridesEOL   = $false
            Write-Log ("  ESU license found but ALL ESU years have EXPIRED (last: {0} on {1})" -f
                $lastYear.Key, $lastYear.Value.ToString("yyyy-MM-dd")) -Level "WARN"
            Set-Status "WARN"
        }
    } else {
        Write-Log "  No active ESU license detected via any method."
    }

    $esuResult.ESUDetails = if ($esuResult.ESULicenseValid) {
        "Valid $($esuResult.ESUYear) ESU license active via $($esuResult.ESUActivationMethod) - expires $($esuResult.ESUExpiryDate)"
    } elseif ($esuResult.ESULicenseFound) {
        "ESU license found but is NOT active or has expired."
    } else {
        "No ESU license detected."
    }

    Write-Log "  ESU Summary: $($esuResult.ESUDetails)"
    $Script:Results["ESU"] = $esuResult
    return $esuResult
}

# ============================================================
#  SECTION 2b - EOL CHECK (calls ESU check internally)
#  Source: Microsoft lifecycle pages (encoded here for offline use)
#  Build numbers map to support end dates.
#  Update this table annually or replace with an API call.
# ============================================================
function Test-WindowsEOL {
    param([string]$BuildNumber)

    Write-Log "=== Checking Windows EOL Status (Build: $BuildNumber) ==="

    # Key = BuildNumber, Value = @(ProductName, EndOfSupportDate)
    # Covers Windows 10 (all supported channels) and Windows 11
    $lifecycleTable = @{
        # NOTE: Windows 7 / Server 2008 R2 (build 7601) removed - unsupported
        # by this script (the OS gate at startup refuses to run on those builds).

        # Windows Server 2012
        "9200"  = @("Windows Server 2012",             [datetime]"2023-10-10")
        # Windows Server 2012 R2
        "9600"  = @("Windows Server 2012 R2",          [datetime]"2023-10-10")
        # Windows 10
        "19041" = @("Windows 10 2004",                [datetime]"2021-12-14")
        "19042" = @("Windows 10 20H2",                [datetime]"2022-05-10")
        "19043" = @("Windows 10 21H1",                [datetime]"2022-12-13")
        "19044" = @("Windows 10 21H2 (Home/Pro)",     [datetime]"2023-06-13")
        "19045" = @("Windows 10 22H2 (Home/Pro)",     [datetime]"2025-10-14")
        # Windows Server 2016
        "14393" = @("Windows Server 2016",            [datetime]"2027-01-12")
        # Windows Server 2019
        "17763" = @("Windows Server 2019",            [datetime]"2029-01-09")
        # Windows Server 2022
        "20348" = @("Windows Server 2022",            [datetime]"2031-10-14")
        # Windows 11
        "22000" = @("Windows 11 21H2 (Home/Pro)",     [datetime]"2023-10-10")
        "22621" = @("Windows 11 22H2 (Home/Pro)",     [datetime]"2024-10-08")
        "22631" = @("Windows 11 23H2 (Home/Pro)",     [datetime]"2025-11-11")
        "26100" = @("Windows 11 24H2",                [datetime]"2026-10-13")
        # Windows Server 2025
        "26080" = @("Windows Server 2025",            [datetime]"2034-10-10")
    }

    $today     = (Get-Date).Date
    $eolResult = [ordered]@{}

    # ---- Run ESU check first - result can override IsEOL below ----
    $esuInfo = Get-ESULicenseStatus

    if ($lifecycleTable.ContainsKey($BuildNumber)) {
        $entry       = $lifecycleTable[$BuildNumber]
        $productName = $entry[0]
        $eosDate     = $entry[1]
        $daysLeft    = ($eosDate - $today).Days
        $rawEOL      = ($today -gt $eosDate)

        # Override: if past EOS but a VALID ESU is active, treat as supported
        $isEOL = $rawEOL -and (-not $esuInfo.OverridesEOL)

        $eolResult = [ordered]@{
            ProductName       = $productName
            BuildNumber       = $BuildNumber
            EndOfSupportDate  = $eosDate.ToString("yyyy-MM-dd")
            DaysUntilEOL      = if ($rawEOL) { "EXPIRED ($([Math]::Abs($daysLeft)) days ago)" } else { $daysLeft }
            RawEOL            = $rawEOL
            ESUOverride       = $esuInfo.OverridesEOL
            ESUExpiryDate     = $esuInfo.ESUExpiryDate
            IsEOL             = $isEOL
        }

        if ($isEOL) {
            Write-Log ("  OS is END OF LIFE: $productName (expired {0} days ago, no valid ESU)" -f
                [Math]::Abs($daysLeft)) -Level "FAIL"
            Set-Status "FAIL"
        } elseif ($rawEOL -and $esuInfo.OverridesEOL) {
            Write-Log ("  OS is past standard EOS but covered by valid ESU ({0}) through {1}" -f
                $esuInfo.ESUYear, $esuInfo.ESUExpiryDate) -Level "WARN"
            Set-Status "WARN"   # Raise a WARN so admins know ESU is in play
        } elseif ($daysLeft -le 90) {
            Write-Log "  WARNING: OS approaching EOL in $daysLeft days - $productName" -Level "WARN"
            Set-Status "WARN"
        } else {
            Write-Log "  OS is supported: $productName - $daysLeft days remaining"
        }
    } else {
        # Build not in table - may be a newer release; treat as supported but flag it
        $eolResult = [ordered]@{
            ProductName      = "Unknown (Build $BuildNumber)"
            BuildNumber      = $BuildNumber
            EndOfSupportDate = "Unknown"
            DaysUntilEOL     = "Unknown"
            RawEOL           = $false
            ESUOverride      = $false
            ESUExpiryDate    = "N/A"
            IsEOL            = $false
        }
        Write-Log "  Build $BuildNumber not found in EOL table - treating as Supported (verify manually)" -Level "WARN"
        Set-Status "WARN"
    }

    $Script:Results["EOL"] = $eolResult
    return $eolResult
}

# ============================================================
#  SECTION 3 - LAST CUMULATIVE UPDATE CHECK
#  Excludes Servicing Stack Updates (SSU) by title keyword.
# ============================================================
function Get-LastCumulativeUpdate {
    Write-Log "=== Checking Last Installed Cumulative Update ==="

    # Keywords that identify SSUs - excluded from LCU check
    $ssuPatterns = @(
        "Servicing Stack",
        "Servicing stack",
        "SSU",
        "Service Stack"
    )

    # Patterns that identify genuine Cumulative Updates
    $lcuPatterns = @(
        "Cumulative Update for Windows",
        "Cumulative Update for Microsoft",
        "Cumulative Security Update",
        "Monthly Rollup",
        "Security Monthly"
    )

    $cutoffDate   = (Get-Date).AddDays(-$PatchStaleDays)
    $dataSource   = "None"   # V3: tracks which lookup method produced the result
    $hotfixCount  = 0        # >=0 = LCUs visible to Get-HotFix; -1 = lookup timed out / errored
    $wmiCount     = 0        # >=0 = LCUs visible to Win32_QuickFixEngineering; -1 = lookup timed out / errored
    $lcuHistory   = @()

    # ----------------------------------------------------------------
    # v4.12: WUA COM is now the PRIMARY lookup, not the third fallback.
    # Reasons:
    #   1) On Server 2016/2019 cumulative updates often have blank or
    #      missing Description fields in Win32_QuickFixEngineering, so
    #      Get-HotFix was unreliable as a primary source anyway.
    #   2) Get-HotFix and Get-CimInstance Win32_QuickFixEngineering both
    #      route through the WMI repository, which can wedge for 20+ min
    #      when the repo is corrupt (observed in v4.11). WUA COM
    #      talks to the WU agent directly and is unaffected.
    # Get-HotFix and WMI are still consulted below, but as bounded
    # bookkeeping probes rather than blocking primary lookups.
    # ----------------------------------------------------------------
    Write-Log "  Querying WUA COM update history (primary lookup)..."
    try {
        $wuaSession   = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
        $wuaSearcher  = $wuaSession.CreateUpdateSearcher()
        $totalHistory = $wuaSearcher.GetTotalHistoryCount()

        if ($totalHistory -gt 0) {
            $wuaHistory = $wuaSearcher.QueryHistory(0, $totalHistory)

            # ResultCode 1=InProgress 2=Succeeded 3=SucceededWithErrors 4=Failed 5=Aborted
            # Operation  1=Installation 2=Uninstallation 3=OtherSoftwareInstallation
            $lcuHistory = @($wuaHistory | Where-Object {
                $title = $_.Title
                $matchesLCU = @($lcuPatterns | Where-Object { $title -like "*$_*" })
                $isSSU      = @($ssuPatterns | Where-Object { $title -like "*$_*" })
                ($matchesLCU.Count -gt 0) -and ($isSSU.Count -eq 0) -and
                ($_.ResultCode -eq 2) -and ($_.Operation -eq 1)
            } | Sort-Object Date -Descending)

            if ($lcuHistory.Count -gt 0) {
                Write-Log ("  WUA COM history found {0} LCU(s)" -f $lcuHistory.Count)
                $dataSource = "WUA COM (Microsoft.Update.Session)"
                # Normalise property names - WUA uses .Title and .Date instead of .HotFixID / .InstalledOn
                $lcuHistory = @($lcuHistory | ForEach-Object {
                    [PSCustomObject]@{
                        HotFixID    = if ($_.Title -match '(KB\d+)') { $Matches[1] } else { 'Unknown' }
                        InstalledOn = $_.Date
                        Description = $_.Title
                    }
                })
            } else {
                Write-Log "  WUA COM returned history but no LCU titles matched - will probe legacy lookups for fallback data"
            }
        } else {
            Write-Log "  WUA COM history is empty (GetTotalHistoryCount=0) - will probe legacy lookups for fallback data" -Level "WARN"
        }
    }
    catch {
        Write-Log "  WUA COM history query failed: $_" -Level "WARN"
    }

    # ----------------------------------------------------------------
    # Bookkeeping probe 1: Get-HotFix (bounded, 60s)
    # We still want to know whether the legacy lookups work because a
    # populated WUA COM history with empty Get-HotFix/WMI is a strong
    # signal of SoftwareDistribution\DataStore corruption that the
    # operator should know about. On timeout we record -1 (Unknown).
    # ----------------------------------------------------------------
    $hotfixProbe = Invoke-CmdletWithTimeout -TimeoutSec 60 -Label "Get-HotFix probe" -ScriptBlock {
        @(Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn -ne $null })
    }
    if ($hotfixProbe.TimedOut) {
        Write-Log "  Get-HotFix probe timed out after 60s; treating as Unknown for bookkeeping signal" -Level "WARN"
        $hotfixCount = -1
    } elseif (-not $hotfixProbe.Success) {
        Write-Log ("  Get-HotFix probe failed: {0}" -f $hotfixProbe.Error) -Level "WARN"
        $hotfixCount = -1
    } else {
        $hotfixHistory = @($hotfixProbe.Result)
        $hotfixLcus = @($hotfixHistory | Where-Object {
            $desc = $_.Description
            $matchesLCU = @($lcuPatterns | Where-Object { $desc -like "*$_*" })
            $isSSU      = @($ssuPatterns | Where-Object { $desc -like "*$_*" })
            ($matchesLCU.Count -gt 0) -and ($isSSU.Count -eq 0)
        } | Sort-Object InstalledOn -Descending)
        $hotfixCount = $hotfixLcus.Count

        # Secondary fallback: if WUA COM came back empty, use Get-HotFix
        # results so we still produce a usable LCU date.
        if ($lcuHistory.Count -eq 0 -and $hotfixCount -gt 0) {
            Write-Log ("  WUA COM empty; falling back to Get-HotFix ({0} LCU(s))" -f $hotfixCount)
            $lcuHistory = $hotfixLcus
            $dataSource = "Get-HotFix"
        }
    }

    # ----------------------------------------------------------------
    # Bookkeeping probe 2: Win32_QuickFixEngineering (bounded, 60s)
    # ----------------------------------------------------------------
    $wmiProbe = Invoke-CmdletWithTimeout -TimeoutSec 60 -Label "Win32_QuickFixEngineering probe" -ScriptBlock {
        @(Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction SilentlyContinue)
    }
    if ($wmiProbe.TimedOut) {
        Write-Log "  Win32_QuickFixEngineering probe timed out after 60s; treating as Unknown for bookkeeping signal" -Level "WARN"
        $wmiCount = -1
    } elseif (-not $wmiProbe.Success) {
        Write-Log ("  Win32_QuickFixEngineering probe failed: {0}" -f $wmiProbe.Error) -Level "WARN"
        $wmiCount = -1
    } else {
        $wmiHistory = @($wmiProbe.Result)
        $wmiLcus = @($wmiHistory | Where-Object {
            $desc = $_.Description
            $matchesLCU = @($lcuPatterns | Where-Object { $desc -like "*$_*" })
            $isSSU      = @($ssuPatterns | Where-Object { $desc -like "*$_*" })
            ($matchesLCU.Count -gt 0) -and ($isSSU.Count -eq 0)
        } | Sort-Object InstalledOn -Descending)
        $wmiCount = $wmiLcus.Count

        # Tertiary fallback: if both WUA COM and Get-HotFix came back
        # empty but WMI returned something, use WMI.
        if ($lcuHistory.Count -eq 0 -and $wmiCount -gt 0) {
            Write-Log ("  WUA COM and Get-HotFix empty; falling back to Win32_QuickFixEngineering ({0} LCU(s))" -f $wmiCount)
            $lcuHistory = $wmiLcus
            $dataSource = "Win32_QuickFixEngineering (WMI)"
        }
    }

    $lcuResult = [ordered]@{
        TotalLCUsFound      = $lcuHistory.Count
        ThresholdDays       = $PatchStaleDays
        ThresholdDate       = $cutoffDate.ToString("yyyy-MM-dd")
        LastLCU_KB          = "None found"
        LastLCU_Date        = "N/A"
        LastLCU_DaysAgo     = "N/A"
        WithinThreshold     = $false
        SSUsExcluded        = $true
        # V3 additions: bookkeeping health signal
        DataSource          = $dataSource
        HotFixCount         = $hotfixCount
        WMICount            = $wmiCount
        # Healthy = at least one of the legacy lookups (Get-HotFix or WMI) works.
        # Degraded = only WUA COM has visibility into history. This is a strong
        # signal that SoftwareDistribution\DataStore is corrupt or out of sync,
        # and is a primary indicator that remediation is needed.
        BookkeepingHealthy  = ($hotfixCount -gt 0 -or $wmiCount -gt 0)
    }

    if ($lcuHistory.Count -gt 0) {
        $latest               = $lcuHistory[0]
        $installedDate        = [datetime]$latest.InstalledOn
        $daysAgo              = ((Get-Date) - $installedDate).Days

        $lcuResult.LastLCU_KB      = $latest.HotFixID
        $lcuResult.LastLCU_Date    = $installedDate.ToString("yyyy-MM-dd")
        $lcuResult.LastLCU_DaysAgo = $daysAgo
        $lcuResult.WithinThreshold = ($installedDate -ge $cutoffDate)

        if ($lcuResult.WithinThreshold) {
            Write-Log ("  PASS - Last LCU: {0} installed {1} days ago ({2})" -f
                $latest.HotFixID, $daysAgo, $installedDate.ToString("yyyy-MM-dd"))
        } else {
            Write-Log ("  FAIL - Last LCU: {0} installed {1} days ago - exceeds {2}-day threshold!" -f
                $latest.HotFixID, $daysAgo, $PatchStaleDays) -Level "WARN"
            Set-Status "WARN"
        }
    } else {
        Write-Log "  No Cumulative Updates found in installed update history!" -Level "ERROR"
        Set-Status "FAIL"
    }

    # V3: bookkeeping-health post-check. Only meaningful when at least the COM
    # API found history; if everything was empty the FAIL above already covered it.
    # v4.12: render -1 as "Unknown (timed out)" so the report distinguishes
    # 'legacy lookups returned 0 LCUs' from 'legacy lookups never completed'.
    if ($lcuHistory.Count -gt 0 -and -not $lcuResult.BookkeepingHealthy) {
        $hfDisp  = if ($hotfixCount -lt 0) { "Unknown (timed out)" } else { $hotfixCount }
        $wmiDisp = if ($wmiCount    -lt 0) { "Unknown (timed out)" } else { $wmiCount    }
        Write-Log ("  WARN: Patch bookkeeping is DEGRADED. Get-HotFix={0}, WMI={1}, but WUA COM history has {2} LCU(s). Likely cause: SoftwareDistribution\DataStore corruption (or hung WMI provider if probes timed out - check 'winmgmt /verifyrepository')." -f $hfDisp, $wmiDisp, $lcuHistory.Count) -Level "WARN"
        Set-Status "WARN"
    }

    $Script:Results["LCUCheck"] = $lcuResult
    return $lcuResult
}

# ============================================================
#  SECTION 3b - SYSTEM DISK FREE SPACE CHECK
#  Verifies the system drive (typically C:) has at least
#  $MinFreeGB free before attempting any update operations.
#  Flags WARN if space is low but above the hard floor, FAIL
#  if below the minimum required.
# ============================================================
function Test-DiskSpace {
    param([int]$MinFreeGB = 25)

    Write-Log "=== Checking System Disk Free Space (minimum: $MinFreeGB GB) ==="

    $diskResult = [ordered]@{
        DriveLetter       = "Unknown"
        TotalGB           = 0
        FreeGB            = 0
        UsedGB            = 0
        PercentFree       = 0
        MinRequiredGB     = $MinFreeGB
        MeetsMinimum      = $false
        Status            = "FAIL"
    }

    try {
        # Identify the system drive from the OS environment
        $sysDrive  = $env:SystemDrive.TrimEnd('\')   # e.g. "C:"
        $diskObj   = Get-CimInstance -ClassName Win32_LogicalDisk `
                         -Filter "DeviceID='$sysDrive'" -ErrorAction Stop

        if (-not $diskObj) {
            Write-Log "  Could not query disk for drive $sysDrive" -Level "ERROR"
            Set-Status "WARN"
            $Script:Results["DiskSpace"] = $diskResult
            return $diskResult
        }

        $totalGB   = [Math]::Round($diskObj.Size        / 1GB, 2)
        $freeGB    = [Math]::Round($diskObj.FreeSpace   / 1GB, 2)
        $usedGB    = [Math]::Round(($diskObj.Size - $diskObj.FreeSpace) / 1GB, 2)
        $pctFree   = if ($totalGB -gt 0) { [Math]::Round(($freeGB / $totalGB) * 100, 1) } else { 0 }

        $diskResult.DriveLetter   = $sysDrive
        $diskResult.TotalGB       = $totalGB
        $diskResult.FreeGB        = $freeGB
        $diskResult.UsedGB        = $usedGB
        $diskResult.PercentFree   = $pctFree
        $diskResult.MeetsMinimum  = ($freeGB -ge $MinFreeGB)

        if ($freeGB -ge $MinFreeGB) {
            $diskResult.Status = "PASS"
            Write-Log ("  PASS - Drive {0}: {1} GB free of {2} GB total ({3}% free)" -f
                $sysDrive, $freeGB, $totalGB, $pctFree)
        } elseif ($freeGB -ge ($MinFreeGB * 0.75)) {
            # Between 75% and 100% of minimum - warn but allow remediation to proceed
            $diskResult.Status = "WARN"
            # v4.14: outer parens around the concatenated string force the
            # whole assembled message through the -f operator. Without them
            # PowerShell's precedence rules apply -f to only the second
            # string, leaving the first string's {0}/{1}/{2} placeholders
            # unsubstituted in the log output.
            Write-Log (("  WARN - Drive {0}: only {1} GB free (minimum {2} GB). " +
                "Remediation will proceed but space is tight.") -f
                $sysDrive, $freeGB, $MinFreeGB) -Level "WARN"
            Set-Status "WARN"
        } else {
            # Below 75% of the minimum - too low to safely attempt updates
            $diskResult.Status = "FAIL"
            # v4.14: outer parens around the concatenated string force the
            # whole assembled message through the -f operator. See the WARN
            # branch above for the operator-precedence explanation.
            Write-Log (("  FAIL - Drive {0}: only {1} GB free. Minimum {2} GB required. " +
                "Remediation will be SKIPPED to avoid a failed or partial update.") -f
                $sysDrive, $freeGB, $MinFreeGB) -Level "ERROR"
            Set-Status "FAIL"
        }
    }
    catch {
        $diskResult.Status = "ERROR"
        Write-Log "  Disk space check failed: $_" -Level "ERROR"
        Set-Status "WARN"
    }

    $Script:Results["DiskSpace"] = $diskResult
    return $diskResult
}

# ============================================================
#  SECTION 3c - WINDOWS UPDATE SERVICES STATUS CHECK
#  Validates that all services required for Windows Update
#  are present, running (or set to an acceptable start type),
#  and that the WUA COM object is reachable.
#  Services checked:
#    wuauserv  - Windows Update
#    bits      - Background Intelligent Transfer Service
#    cryptsvc  - Cryptographic Services
#    trustedinstaller - Windows Modules Installer
#    msiserver - Windows Installer  (advisory only)
#    dosvc     - Delivery Optimization (advisory only)
# ============================================================
function Test-WindowsUpdateServices {
    Write-Log "=== Checking Windows Update Service Health ==="

    # Define required services and their expected running states.
    # Mandatory = $true means a non-running state raises the overall status.
    # Advisory   = $false means we report but do not fail/warn the overall status.
    $serviceDefinitions = @(
        [ordered]@{ Name = "wuauserv";         DisplayName = "Windows Update";                     Mandatory = $true  }
        [ordered]@{ Name = "bits";             DisplayName = "Background Intelligent Transfer";     Mandatory = $true  }
        [ordered]@{ Name = "cryptsvc";         DisplayName = "Cryptographic Services";              Mandatory = $true  }
        [ordered]@{ Name = "trustedinstaller"; DisplayName = "Windows Modules Installer";           Mandatory = $true  }
        [ordered]@{ Name = "msiserver";        DisplayName = "Windows Installer";                   Mandatory = $false }
        [ordered]@{ Name = "dosvc";            DisplayName = "Delivery Optimization";               Mandatory = $false }
    )

    $serviceResults = [System.Collections.Generic.List[object]]::new()
    $allMandatoryOk = $true

    foreach ($svcDef in $serviceDefinitions) {
        $svcName    = $svcDef.Name
        $svcDisplay = $svcDef.DisplayName
        $mandatory  = $svcDef.Mandatory

        $row = [ordered]@{
            ServiceName  = $svcName
            DisplayName  = $svcDisplay
            Status       = "Not Found"
            StartType    = "N/A"
            Mandatory    = $mandatory
            Healthy      = $false
            Note         = ""
        }

        try {
            $svc = Get-Service -Name $svcName -ErrorAction Stop

            $row.Status    = $svc.Status.ToString()
            $row.StartType = $svc.StartType.ToString()

            # A service is healthy if Running, OR if Stopped with Manual start type
            # and it is a known demand-start service. BITS and TrustedInstaller are
            # by design Manual/demand-start - Windows starts them when needed.
            # Only flag Stopped as unhealthy when StartType is Automatic (should be
            # running but isn't) or Disabled.
            $demandStartServices = @('bits', 'trustedinstaller', 'msiserver', 'dosvc')
            $isKnownDemandStart  = $svcName -in $demandStartServices

            $isRunning     = ($svc.Status -eq 'Running')
            $isOnDemandOk  = ($svc.Status -eq 'Stopped') -and
                             ($svc.StartType -eq 'Manual') -and
                             $isKnownDemandStart

            if ($isRunning) {
                $row.Healthy = $true
                $row.Note    = "Running"
                Write-Log ("  OK       {0,-20} : {1} ({2})" -f $svcName, $svc.Status, $svc.StartType)
            } elseif ($isOnDemandOk) {
                # Known demand-start service - Stopped/Manual is healthy
                $row.Healthy = $true
                $row.Note    = "Stopped (demand-start) - acceptable"
                Write-Log ("  OK       {0,-20} : Stopped/demand-start - acceptable" -f $svcName)
            } elseif ($svc.StartType -eq 'Disabled') {
                $row.Healthy = $false
                $row.Note    = "DISABLED - must be re-enabled"
                Write-Log ("  {0} {1,-20} : DISABLED" -f $(if ($mandatory) {"FAIL    "} else {"WARN    "}), $svcName) -Level $(if ($mandatory) {"ERROR"} else {"WARN"})
                if ($mandatory) { $allMandatoryOk = $false; Set-Status "FAIL" } else { Set-Status "WARN" }
            } else {
                $row.Healthy = $false
                $row.Note    = "Stopped unexpectedly (StartType: $($svc.StartType))"
                Write-Log ("  {0} {1,-20} : Stopped - StartType={2}" -f $(if ($mandatory) {"FAIL    "} else {"WARN    "}), $svcName, $svc.StartType) -Level "WARN"
                if ($mandatory) { $allMandatoryOk = $false; Set-Status "WARN" }
            }
        }
        catch {
            $row.Note    = "Service not found or query failed: $_"
            $row.Healthy = $false
            if ($mandatory) {
                $allMandatoryOk = $false
                Write-Log ("  FAIL     {0,-20} : Not found / query error" -f $svcName) -Level "ERROR"
                Set-Status "FAIL"
            } else {
                Write-Log ("  WARN     {0,-20} : Not found (advisory - may not be installed)" -f $svcName) -Level "WARN"
            }
        }

        $serviceResults.Add($row)
    }

    # ---- WUA COM reachability test ----
    Write-Log "  Testing WUA COM object reachability (Microsoft.Update.Session)..."
    $wuaReachable = $false
    $wuaNote      = ""
    try {
        $session      = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
        $searcher     = $session.CreateUpdateSearcher()
        # A lightweight call - just verify the object responds, don't run a full search
        $null         = $searcher.GetTotalHistoryCount()
        $wuaReachable = $true
        $wuaNote      = "COM object responding normally"
        Write-Log "  OK       WUA COM object is reachable and responding"
    }
    catch {
        $wuaNote = "COM object unreachable: $_"
        Write-Log "  WARN     WUA COM object is NOT reachable - $_" -Level "WARN"
        Set-Status "WARN"
    }

    $wuServiceResult = [ordered]@{
        Services          = $serviceResults
        AllMandatoryOK    = $allMandatoryOk
        WUAComReachable   = $wuaReachable
        WUAComNote        = $wuaNote
        OverallHealthy    = ($allMandatoryOk -and $wuaReachable)
    }

    $Script:Results["WUServices"] = $wuServiceResult
    return $wuServiceResult
}

# ============================================================
#  SECTION 3d - PENDING REBOOT CHECK
#  Inspects every registry location and file-rename queue that
#  Windows uses to signal a reboot is required.  A pending
#  reboot before patching can cause update failures, stuck
#  installations, or CBS corruption.
#
#  Sources checked:
#    CBS  - Component Based Servicing (DISM/SFC repairs)
#    WU   - Windows Update client
#    PFR  - PendingFileRenameOperations (in-use file swaps)
#    SCCM - ConfigMgr client (if present)
#    Join - Domain join / computer rename pending
# ============================================================
function Test-PendingReboot {
    Write-Log "=== Checking Pending Reboot State ==="

    $rebootResult = [ordered]@{
        RebootPending       = $false   # True only for CBS/WU/SCCM/DomainJoin sources
        PFROnlyPending      = $false   # PendingFileRenameOperations - informational only
        Sources             = [System.Collections.Generic.List[string]]::new()
        PFRSources          = [System.Collections.Generic.List[string]]::new()
        CBSPending          = $false
        WUPending           = $false
        PFRPending          = $false
        SCCMPending         = $false
        DomainJoinPending   = $false
        RecommendedAction   = ""
    }

    # ---- CBS (Component Based Servicing) ----
    try {
        $cbsKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing"
        if (Test-Path "$cbsKey\RebootPending") {
            $rebootResult.CBSPending = $true
            $rebootResult.Sources.Add("CBS - RebootPending")
            Write-Log "  PENDING: CBS\RebootPending key exists" -Level "WARN"
        }
        if (Test-Path "$cbsKey\RebootInProgress") {
            $rebootResult.CBSPending = $true
            $rebootResult.Sources.Add("CBS - RebootInProgress")
            Write-Log "  PENDING: CBS\RebootInProgress key exists" -Level "WARN"
        }
        if (Test-Path "$cbsKey\PackagesPending") {
            $rebootResult.CBSPending = $true
            $rebootResult.Sources.Add("CBS - PackagesPending")
            Write-Log "  PENDING: CBS\PackagesPending key exists" -Level "WARN"
        }
    }
    catch { Write-Log "  CBS reboot check error: $_" -Level "WARN" }

    # ---- Windows Update ----
    try {
        $wuKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
        if (Test-Path "$wuKey\RebootRequired") {
            $rebootResult.WUPending = $true
            $rebootResult.Sources.Add("Windows Update - RebootRequired")
            Write-Log "  PENDING: WU\RebootRequired key exists" -Level "WARN"
        }
        if (Test-Path "$wuKey\PostRebootReporting") {
            $rebootResult.WUPending = $true
            $rebootResult.Sources.Add("Windows Update - PostRebootReporting")
            Write-Log "  PENDING: WU\PostRebootReporting key exists" -Level "WARN"
        }
    }
    catch { Write-Log "  Windows Update reboot check error: $_" -Level "WARN" }

    # ---- PendingFileRenameOperations ----
    try {
        $pfrPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
        $pfr     = Get-ItemProperty -Path $pfrPath `
                       -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
        if ($pfr -and $pfr.PendingFileRenameOperations -and
            $pfr.PendingFileRenameOperations.Count -gt 0) {
            $rebootResult.PFRPending     = $true
            $rebootResult.PFROnlyPending = $true
            $rebootResult.PFRSources.Add("PendingFileRenameOperations ($($pfr.PendingFileRenameOperations.Count) entries)")
            # Logged at INFO - PFR entries are normal OS behaviour and do not
            # indicate a problem on their own; remediation is still blocked but
            # no WARN status is raised against the overall health score.
            Write-Log ("  INFO: PendingFileRenameOperations has {0} entries (informational - reboot will clear)" -f
                $pfr.PendingFileRenameOperations.Count)
        }
    }
    catch { Write-Log "  PendingFileRenameOperations check error: $_" -Level "WARN" }

    # ---- SCCM / ConfigMgr client ----
    try {
        $sccmKey = "HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client\Reboot Management\RebootData"
        if (Test-Path $sccmKey) {
            $sccmData = Get-ItemProperty -Path $sccmKey -ErrorAction SilentlyContinue
            if ($sccmData -and $sccmData.RebootPending -eq 1) {
                $rebootResult.SCCMPending = $true
                $rebootResult.Sources.Add("SCCM/ConfigMgr - RebootPending")
                Write-Log "  PENDING: SCCM client indicates reboot required" -Level "WARN"
            }
        }
    }
    catch { Write-Log "  SCCM reboot check error (non-fatal): $_" -Level "WARN" }

    # ---- Computer Rename / Domain Join ----
    try {
        $joinKey   = "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName"
        $activeKey = "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName"
        if ((Test-Path $joinKey) -and (Test-Path $activeKey)) {
            $pending = (Get-ItemProperty $joinKey   -ErrorAction SilentlyContinue).ComputerName
            $active  = (Get-ItemProperty $activeKey -ErrorAction SilentlyContinue).ComputerName
            if ($pending -and $active -and ($pending -ne $active)) {
                $rebootResult.DomainJoinPending = $true
                $rebootResult.Sources.Add("Computer Rename Pending ($active -> $pending)")
                Write-Log "  PENDING: Computer rename pending: $active -> $pending" -Level "WARN"
            }
        }
        if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\JoinDomain") {
            $rebootResult.DomainJoinPending = $true
            $rebootResult.Sources.Add("Domain Join Pending")
            Write-Log "  PENDING: Domain join operation pending" -Level "WARN"
        }
    }
    catch { Write-Log "  Domain join/rename check error: $_" -Level "WARN" }

    # ---- Determine overall state ----
    # RebootPending = serious sources only (CBS, WU, SCCM, domain join).
    # PFR is tracked separately - it blocks remediation but does not raise
    # the overall WARN status since it is normal OS behaviour.
    $rebootResult.RebootPending = (
        $rebootResult.CBSPending     -or $rebootResult.WUPending -or
        $rebootResult.SCCMPending    -or $rebootResult.DomainJoinPending
    )

    # Combined flag used by remediation gate - blocks on either serious or PFR
    $rebootResult.AnyRebootPending = (
        $rebootResult.RebootPending -or $rebootResult.PFROnlyPending
    )

    if ($rebootResult.RebootPending) {
        $rebootResult.RecommendedAction =
            "Reboot the system before starting patch maintenance to avoid update conflicts."
        Write-Log ("  WARN: Reboot is PENDING ({0} source(s) detected). Patching may fail or stall." -f
            $rebootResult.Sources.Count) -Level "WARN"
        Set-Status "WARN"
    } elseif ($rebootResult.PFROnlyPending) {
        $rebootResult.RecommendedAction =
            "PendingFileRenameOperations detected. Remediation is paused until next reboot clears the queue."
        Write-Log "  INFO: Only PendingFileRenameOperations detected - no WARN raised. Remediation will be paused."
    } else {
        $rebootResult.RecommendedAction = "No action required."
        Write-Log "  PASS: No pending reboot detected across all checked registry sources."
    }

    $Script:Results["PendingReboot"] = $rebootResult
    return $rebootResult
}

# ============================================================
#  SECTION 3e - SYSTEM UPTIME CHECK
#  Long uptimes indicate the system has not rebooted to finish
#  applying previous patches, may have deferred WU state, or
#  could be carrying stale drivers/in-memory state.
#  Thresholds:
#    <= 30 days  - PASS  (normal operations)
#    31-60 days  - WARN  (patching will likely work; reboot overdue)
#    >  60 days  - FAIL  (high risk; reboot strongly recommended first)
# ============================================================
function Test-SystemUptime {
    param(
        [int]$WarnDays = 30,
        [int]$FailDays = 60
    )

    Write-Log "=== Checking System Uptime ==="

    $uptimeResult = [ordered]@{
        LastBootTime    = "Unknown"
        UptimeDays      = 0
        UptimeTotalHours = 0
        UptimeFormatted = ""
        WarnThreshold   = $WarnDays
        FailThreshold   = $FailDays
        Status          = "PASS"
        Note            = ""
    }

    try {
        $os        = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $lastBoot  = $os.LastBootUpTime
        $uptime    = (Get-Date) - $lastBoot
        $days      = [Math]::Floor($uptime.TotalDays)
        $formatted = "{0}d {1}h {2}m" -f $days, $uptime.Hours, $uptime.Minutes

        $uptimeResult.LastBootTime     = $lastBoot.ToString("yyyy-MM-dd HH:mm:ss")
        $uptimeResult.UptimeDays       = $days
        $uptimeResult.UptimeTotalHours = [Math]::Floor($uptime.TotalHours)
        $uptimeResult.UptimeFormatted  = $formatted

        if ($days -le $WarnDays) {
            $uptimeResult.Status = "PASS"
            $uptimeResult.Note   = "Uptime is within acceptable range."
            Write-Log "  PASS: System uptime is $formatted (last boot: $($lastBoot.ToString('yyyy-MM-dd HH:mm:ss')))"
        } elseif ($days -le $FailDays) {
            $uptimeResult.Status = "WARN"
            $uptimeResult.Note   = "Uptime exceeds ${WarnDays}d. A reboot before patch maintenance is recommended."
            Write-Log "  WARN: Uptime $formatted exceeds ${WarnDays}-day warning threshold." -Level "WARN"
            Set-Status "WARN"
        } else {
            $uptimeResult.Status = "WARN"   # WARN not FAIL - high uptime is a risk, not a hard blocker
            $uptimeResult.Note   = "Uptime exceeds ${FailDays}d. Reboot strongly recommended before patching."
            Write-Log "  WARN: Uptime $formatted exceeds ${FailDays}-day critical threshold. Reboot before patching." -Level "ERROR"
            Set-Status "WARN"
        }
    }
    catch {
        $uptimeResult.Status = "ERROR"
        $uptimeResult.Note   = "Could not determine uptime: $_"
        Write-Log "  Uptime check failed: $_" -Level "WARN"
    }

    $Script:Results["Uptime"] = $uptimeResult
    return $uptimeResult
}

# ============================================================
#  SECTION 3f - TIME SYNC / CLOCK ACCURACY CHECK
#  Windows Update, Kerberos, TLS certificate validation, and
#  WSUS all require accurate system time.  Kerberos rejects
#  tickets with > 5 minutes skew; TLS validation fails on
#  certificates that appear expired or not-yet-valid.
#
#  Checks performed:
#    1. W32Time service is running (attempts auto-start if not)
#    2. Current NTP source and stratum via w32tm /query /status
#    3. Clock offset against the configured time source via
#       w32tm /stripchart  (offset >60s = WARN, >300s = FAIL)
#    4. Last successful sync time
# ============================================================
function Test-TimeSync {
    param(
        [int]$WarnOffsetSeconds = 60,
        [int]$FailOffsetSeconds = 300    # 5 minutes - Kerberos hard limit
    )

    Write-Log "=== Checking Time Synchronisation ==="

    $timeResult = [ordered]@{
        W32tmServiceRunning = $false
        NTPSource           = "Unknown"
        Stratum             = "Unknown"
        LastSyncTime        = "Unknown"
        OffsetSeconds       = $null
        OffsetFormatted     = "Unknown"
        WarnThreshold       = "${WarnOffsetSeconds}s"
        FailThreshold       = "${FailOffsetSeconds}s (Kerberos limit)"
        Status              = "UNKNOWN"
        Note                = ""
    }

    # ---- Step 1: W32Time service ----
    try {
        $w32tm = Get-Service -Name W32Time -ErrorAction Stop
        $timeResult.W32tmServiceRunning = ($w32tm.Status -eq 'Running')

        if (-not $timeResult.W32tmServiceRunning) {
            Write-Log "  WARN: W32Time service is not running (Status: $($w32tm.Status)) - attempting start." -Level "WARN"
            Set-Status "WARN"
            try {
                Start-Service W32Time -ErrorAction Stop
                Start-Sleep -Seconds 3
                $timeResult.W32tmServiceRunning = $true
                Write-Log "  W32Time service started successfully."
            }
            catch {
                Write-Log "  Could not start W32Time: $_ - skipping offset measurement." -Level "WARN"
                $timeResult.Status = "WARN"
                $timeResult.Note   = "W32Time service could not be started. Time accuracy unknown."
                $Script:Results["TimeSync"] = $timeResult
                return $timeResult
            }
        } else {
            Write-Log "  W32Time service is Running."
        }
    }
    catch {
        Write-Log "  W32Time service query failed: $_" -Level "WARN"
        $timeResult.Status = "ERROR"
        $timeResult.Note   = "W32Time service query failed: $_"
        $Script:Results["TimeSync"] = $timeResult
        return $timeResult
    }

    # ---- Step 2: w32tm /query /status ----
    try {
        $queryText = (& w32tm.exe /query /status 2>&1) -join "`n"

        if ($queryText -match "Source\s*:\s*(.+)")                  { $timeResult.NTPSource    = $Matches[1].Trim() }
        if ($queryText -match "Stratum\s*:\s*(\d+)")                { $timeResult.Stratum      = $Matches[1].Trim() }
        if ($queryText -match "Last Successful Sync Time\s*:\s*(.+)") { $timeResult.LastSyncTime = $Matches[1].Trim() }

        Write-Log "  NTP Source  : $($timeResult.NTPSource)"
        Write-Log "  Stratum     : $($timeResult.Stratum)"
        Write-Log "  Last Sync   : $($timeResult.LastSyncTime)"

        # Flag sources that indicate the clock is free-running with no external reference
        if ($timeResult.NTPSource -match "Local CMOS Clock|Free-running|ntp\.m\|0x0\|0\.0\.0\.0") {
            Write-Log "  WARN: NTP source indicates clock is not synced to an external time server." -Level "WARN"
            Set-Status "WARN"
        }
    }
    catch { Write-Log "  w32tm /query /status failed: $_" -Level "WARN" }

    # ---- Step 3: w32tm /stripchart - measure actual offset ----
    try {
        $stripText = (& w32tm.exe /stripchart /computer:$($timeResult.NTPSource) `
                         /samples:1 /dataonly 2>&1) -join "`n"

        # Typical output line: "14:22:31, +00.0153245s"
        if ($stripText -match '\d{2}:\d{2}:\d{2},\s*([+-]?\d+\.?\d*)s') {
            $rawOffset  = [double]$Matches[1]
            $absOffset  = [Math]::Abs($rawOffset)
            $direction  = if ($rawOffset -lt 0) { "behind" } else { "ahead" }

            $timeResult.OffsetSeconds   = [Math]::Round($absOffset, 3)
            $timeResult.OffsetFormatted = "{0:F3}s {1}" -f $absOffset, $direction

            Write-Log "  Clock offset: $($timeResult.OffsetFormatted)"

            if ($absOffset -le $WarnOffsetSeconds) {
                $timeResult.Status = "PASS"
                $timeResult.Note   = "Clock offset is within acceptable range."
                Write-Log "  PASS: Offset $($timeResult.OffsetFormatted) is within ${WarnOffsetSeconds}s threshold."
            } elseif ($absOffset -le $FailOffsetSeconds) {
                $timeResult.Status = "WARN"
                $timeResult.Note   = "Clock offset exceeds ${WarnOffsetSeconds}s. Run 'w32tm /resync /force' to correct."
                Write-Log "  WARN: Offset $($timeResult.OffsetFormatted) exceeds ${WarnOffsetSeconds}s threshold." -Level "WARN"
                Set-Status "WARN"
            } else {
                $timeResult.Status = "FAIL"
                $timeResult.Note   = "Clock offset exceeds ${FailOffsetSeconds}s (Kerberos limit). Run 'w32tm /resync /force' immediately before patching."
                Write-Log "  FAIL: Offset $($timeResult.OffsetFormatted) exceeds ${FailOffsetSeconds}s Kerberos limit." -Level "ERROR"
                Set-Status "FAIL"
            }
        } else {
            # Check if this is a VM/Hyper-V time source - stripchart cannot query these
            # and the inability to measure offset is expected, not an error.
            $isVMTimeSource = $timeResult.NTPSource -match 
                'VM IC Time|vmictimeprovider|Hyper-V|VMware|Virtual Machine'

            if ($isVMTimeSource) {
                $timeResult.Status          = "PASS"
                $timeResult.OffsetFormatted = "N/A (VM host-based time sync)"
                $timeResult.Note            = "VM is using Hyper-V/host time synchronisation. Clock accuracy is managed by the hypervisor."
                Write-Log "  PASS: VM host-based time sync detected - offset measurement not applicable."
            } else {
                $timeResult.Status          = "WARN"
                $timeResult.OffsetFormatted = "Could not measure (NTP source may be unreachable)"
                $timeResult.Note            = "Unable to measure clock offset. Verify NTP source connectivity."
                Write-Log "  WARN: Could not parse clock offset from w32tm /stripchart output." -Level "WARN"
                Set-Status "WARN"
            }
        }
    }
    catch {
        $timeResult.Status = "WARN"
        $timeResult.Note   = "w32tm /stripchart failed: $_"
        Write-Log "  w32tm /stripchart failed: $_" -Level "WARN"
        Set-Status "WARN"
    }

    $Script:Results["TimeSync"] = $timeResult
    return $timeResult
}

# ============================================================
#  SECTION 3g - TPM VERSION CHECK (Windows 10 only)
#  Checks the TPM version installed on the device. TPM 2.0 is
#  a hard requirement for Windows 11 upgrade. If the device is
#  running Windows 10 and the TPM version is below 2.0 (or no
#  TPM is present), a WARN is raised advising that the TPM
#  will block an in-place upgrade to Windows 11.
#
#  Detection methods (in order):
#    1. Win32_Tpm WMI class (most reliable on Win10/Server)
#    2. Get-Tpm PowerShell cmdlet (fallback)
#    3. Registry TPM device enumeration (last resort)
#
#  Only runs on Windows 10 builds (19041-19045). Skipped on
#  Windows 11, Server, and other OS families.
# ============================================================
function Test-TPMVersion {
    Write-Log "=== Checking TPM Version ==="

    # Windows 10 build numbers (all supported channels)
    $win10Builds = @('19041','19042','19043','19044','19045')

    $tpmResult = [ordered]@{
        Applicable        = $false   # Only true on Windows 10
        TPMPresent        = $false
        TPMVersion        = "Unknown"
        TPMVersionMajor   = 0
        SpecVersion       = "Unknown"
        ManufacturerName  = "Unknown"
        Enabled           = $false
        Activated         = $false
        MeetsWin11Req     = $false
        DetectionMethod   = "None"
        Status            = "SKIP"
        Note              = ""
    }

    # Determine if this is a Windows 10 device
    try {
        $os       = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $build    = [string]$os.BuildNumber
        $caption  = $os.Caption

        if ($build -notin $win10Builds) {
            $tpmResult.Note   = "TPM upgrade check only applies to Windows 10 devices. Skipped for: $caption"
            Write-Log "  Skipping TPM check - not a Windows 10 device (Build: $build, OS: $caption)"
            $Script:Results["TPM"] = $tpmResult
            return $tpmResult
        }

        $tpmResult.Applicable = $true
        Write-Log "  Windows 10 detected (Build: $build) - proceeding with TPM check"
    }
    catch {
        Write-Log "  Could not determine OS version for TPM check: $_" -Level "WARN"
        $tpmResult.Note   = "OS version check failed: $_"
        $tpmResult.Status = "ERROR"
        $Script:Results["TPM"] = $tpmResult
        return $tpmResult
    }

    # ---- Method 1: Win32_Tpm WMI class ----
    Write-Log "  [Method 1] Querying Win32_Tpm via WMI..."
    try {
        $tpmWmi = Get-CimInstance -Namespace "root\CIMv2\Security\MicrosoftTpm" `
                      -ClassName Win32_Tpm -ErrorAction Stop

        if ($tpmWmi) {
            $tpmResult.TPMPresent       = $true
            $tpmResult.DetectionMethod  = "Win32_Tpm WMI"
            $tpmResult.Enabled          = [bool]$tpmWmi.IsEnabled_InitialValue
            $tpmResult.Activated        = [bool]$tpmWmi.IsActivated_InitialValue

            # SpecVersion is a comma-separated string e.g. "2.0, 0, 1.38"
            # or "1.2" - extract the primary version number
            $specVer = $tpmWmi.SpecVersion
            if ($specVer) {
                $tpmResult.SpecVersion = $specVer.Trim()
                # Parse the major version from the first segment
                $firstSeg = ($specVer -split ',')[0].Trim()
                if ($firstSeg -match '^(\d+)\.(\d+)') {
                    $tpmResult.TPMVersion      = $firstSeg
                    $tpmResult.TPMVersionMajor = [int]$Matches[1]
                }
            }

            if ($tpmWmi.ManufacturerIdTxt) {
                $tpmResult.ManufacturerName = $tpmWmi.ManufacturerIdTxt.Trim()
            }

            Write-Log "  [Method 1] TPM found - SpecVersion: $($tpmResult.SpecVersion), Enabled: $($tpmResult.Enabled), Activated: $($tpmResult.Activated)"
        } else {
            Write-Log "  [Method 1] Win32_Tpm returned no instances - no TPM detected via WMI"
        }
    }
    catch {
        Write-Log "  [Method 1] Win32_Tpm query failed: $_ - trying fallback" -Level "WARN"
    }

    # ---- Method 2: Get-Tpm cmdlet (fallback) ----
    if (-not $tpmResult.TPMPresent) {
        Write-Log "  [Method 2] Trying Get-Tpm cmdlet..."
        try {
            $tpmCmd = Get-Tpm -ErrorAction Stop
            if ($tpmCmd) {
                $tpmResult.TPMPresent      = $tpmCmd.TpmPresent
                $tpmResult.Enabled         = $tpmCmd.TpmEnabled
                $tpmResult.Activated       = $tpmCmd.TpmActivated
                $tpmResult.DetectionMethod = "Get-Tpm cmdlet"

                # Get-Tpm doesn't expose spec version directly - supplement with WMI if possible
                if ($tpmCmd.TpmPresent) {
                    Write-Log "  [Method 2] TPM present via Get-Tpm (version detail may be limited)"
                    # Attempt registry supplement for version
                    $regVer = Get-ItemProperty `
                        "HKLM:\SYSTEM\CurrentControlSet\Services\TPM\Enum" `
                        -ErrorAction SilentlyContinue
                    if ($regVer -and $regVer.Count -gt 0) {
                        Write-Log "  [Method 2] Registry TPM enum found - checking for version info"
                    }
                }
            }
        }
        catch {
            Write-Log "  [Method 2] Get-Tpm failed: $_" -Level "WARN"
        }
    }

    # ---- Method 3: Registry device enumeration (last resort) ----
    if (-not $tpmResult.TPMPresent) {
        Write-Log "  [Method 3] Checking registry for TPM device..."
        try {
            $tpmRegPaths = @(
                "HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\TPM",
                "HKLM:\SYSTEM\CurrentControlSet\Enum\PCI"
            )
            foreach ($regPath in $tpmRegPaths) {
                if (Test-Path $regPath) {
                    $tpmKeys = Get-ChildItem $regPath -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -like "*TPM*" -or $_.PSChildName -like "*TPM*" }
                    if (@($tpmKeys).Count -gt 0) {
                        $tpmResult.TPMPresent      = $true
                        $tpmResult.DetectionMethod = "Registry device enumeration"
                        Write-Log "  [Method 3] TPM device found in registry: $regPath"
                        break
                    }
                }
            }
        }
        catch {
            Write-Log "  [Method 3] Registry TPM check failed: $_" -Level "WARN"
        }
    }

    # ---- Evaluate results ----
    if (-not $tpmResult.TPMPresent) {
        $tpmResult.Status          = "WARN"
        $tpmResult.MeetsWin11Req   = $false
        $tpmResult.Note            = "No TPM detected. A TPM 2.0 chip is required for Windows 11 upgrade. " +
                                     "The device cannot be upgraded to Windows 11 until a compatible TPM is enabled or installed."
        Write-Log "  WARN: No TPM detected on this Windows 10 device." -Level "WARN"
        Set-Status "WARN"
    } elseif ($tpmResult.TPMVersionMajor -ge 2) {
        $tpmResult.Status        = "PASS"
        $tpmResult.MeetsWin11Req = $true
        $tpmResult.Note          = "TPM $($tpmResult.TPMVersion) meets the Windows 11 upgrade requirement (TPM 2.0+)."
        Write-Log "  PASS: TPM $($tpmResult.TPMVersion) detected - meets Windows 11 requirement."
    } elseif ($tpmResult.TPMVersionMajor -eq 1) {
        $tpmResult.Status        = "WARN"
        $tpmResult.MeetsWin11Req = $false
        $tpmResult.Note          = "TPM $($tpmResult.TPMVersion) detected. Windows 11 requires TPM 2.0. " +
                                   "This device cannot be upgraded to Windows 11 until the TPM is updated or replaced. " +
                                   "Check BIOS/UEFI firmware settings - some devices support TPM 2.0 via a firmware update."
        Write-Log "  WARN: TPM $($tpmResult.TPMVersion) is below the required 2.0 for Windows 11 upgrade." -Level "WARN"
        Set-Status "WARN"
    } else {
        # TPM present but version could not be determined
        $tpmResult.Status        = "WARN"
        $tpmResult.MeetsWin11Req = $false
        $tpmResult.Note          = "TPM detected but version could not be determined. " +
                                   "Manually verify TPM version in Device Manager or BIOS to confirm Windows 11 upgrade eligibility."
        Write-Log "  WARN: TPM present but version undetermined - manual check required." -Level "WARN"
        Set-Status "WARN"
    }

    $Script:Results["TPM"] = $tpmResult
    return $tpmResult
}


# ============================================================
#  SECTION 3h - WINDOWS FEATURE UPDATE READINESS (v4.17)
#  Reports what is preventing a Windows 10/11 client below 24H2
#  from receiving a feature update offer. Skipped on Server
#  SKUs and on hosts already at 24H2+ (build 26100 or higher).
#
#  Detects:
#    1. Policy pins: TargetReleaseVersion / TargetReleaseVersionInfo
#                    / ProductVersion under HKLM\SOFTWARE\Policies
#                    \Microsoft\Windows\WindowsUpdate
#    2. Deferrals: DeferFeatureUpdates + DeferFeatureUpdatesPeriodInDays
#    3. Safeguard-hold heuristic on HKLM\SOFTWARE\Microsoft
#       \WindowsUpdate\UX\Settings (registry signals only;
#       authoritative source is Get-WindowsUpdateLog output)
#    4. CPU SSE4.2 support via kernel32!IsProcessorFeaturePresent(38)
#       - proxy for the POPCNT/SSE4.2 requirement added in 24H2
#    5. AllowTelemetry level (HKLM\SOFTWARE\Policies\Microsoft
#       \Windows\DataCollection)
#    6. WSUS-managed status (informational; upstream approval not
#       queryable from client)
#    7. Stale upgrade artifacts: C:\$WINDOWS.~BT, C:\$WINDOWS.~WS,
#       C:\Windows.old - reports path, age, and size
#    8. Disk space band for 64 GB feature update install
# ============================================================
function Test-FeatureUpdateReadiness {
    Write-Log "=== Checking Windows Feature Update Readiness ==="

    $r = [ordered]@{
        Applicable                  = $false
        CurrentBuild                = 0
        CurrentReleaseVersion       = "Unknown"
        TargetReleaseVersion        = $null
        TargetReleaseVersionEnabled = $null
        ProductVersion              = $null
        DeferFeatureUpdates         = $null
        DeferFeatureUpdatesDays     = $null
        AllowTelemetry              = $null
        WSUSManaged                 = $null
        CPUSupportsSSE42            = $null
        CPUName                     = $null
        StaleArtifacts              = @()
        DiskFreeGB                  = $null
        DiskNeedsGB                 = 64
        DiskSufficientForFeatureUpd = $null
        SafeguardSignals            = @()
        BlockingReasons             = @()
        Status                      = "SKIP"
    }

    # ---- Gate: only runs on Windows 10/11 client below 24H2 ----
    try {
        $os    = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $build = [int]$os.BuildNumber
        $r.CurrentBuild = $build

        if ($os.ProductType -ne 1) {
            Write-Log "  Skipping - not a client OS (ProductType=$($os.ProductType))"
            $Script:Results["FeatureUpdateReadiness"] = $r
            return $r
        }

        $rv = switch ($build) {
            19041 { "20H2" }
            19042 { "20H2" }
            19043 { "21H1" }
            19044 { "21H2" }
            19045 { "22H2 (Win10)" }
            22000 { "21H2" }
            22621 { "22H2" }
            22631 { "23H2" }
            26100 { "24H2" }
            26200 { "25H2" }
            default { "build $build" }
        }
        $r.CurrentReleaseVersion = $rv

        if ($build -ge 26100) {
            Write-Log "  Skipping - already on $rv; feature update readiness check not relevant"
            $Script:Results["FeatureUpdateReadiness"] = $r
            return $r
        }

        $r.Applicable = $true
        Write-Log "  Host is $($os.Caption) - $rv (build $build). Checking next-feature-update readiness."
    }
    catch {
        Write-Log "  Could not determine OS for readiness check: $_" -Level "WARN"
        $Script:Results["FeatureUpdateReadiness"] = $r
        return $r
    }

    $hasProp = { param($obj, $name) ($obj -and $obj.PSObject.Properties.Name -contains $name) }

    # ---- (1) & (2): WU policy keys ----
    try {
        $wu = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue
        if ($wu) {
            if (& $hasProp $wu 'TargetReleaseVersion')     { $r.TargetReleaseVersionEnabled = [int]$wu.TargetReleaseVersion }
            if (& $hasProp $wu 'TargetReleaseVersionInfo' -and $wu.TargetReleaseVersionInfo) {
                $r.TargetReleaseVersion = "$($wu.TargetReleaseVersionInfo)"
                $r.BlockingReasons += "TargetReleaseVersionInfo policy pins this host to $($wu.TargetReleaseVersionInfo)"
            }
            if (& $hasProp $wu 'ProductVersion' -and $wu.ProductVersion) {
                $r.ProductVersion = "$($wu.ProductVersion)"
                if (-not $r.TargetReleaseVersion) {
                    $r.BlockingReasons += "ProductVersion policy set to $($wu.ProductVersion) (used together with TargetReleaseVersionInfo)"
                }
            }
            if (& $hasProp $wu 'DeferFeatureUpdates' -and [int]$wu.DeferFeatureUpdates -eq 1) {
                $r.DeferFeatureUpdates = 1
                $days = 0
                if (& $hasProp $wu 'DeferFeatureUpdatesPeriodInDays') { $days = [int]$wu.DeferFeatureUpdatesPeriodInDays }
                $r.DeferFeatureUpdatesDays = $days
                if ($days -gt 0) {
                    $r.BlockingReasons += "Feature updates deferred for $days day(s) via DeferFeatureUpdatesPeriodInDays"
                }
            }
        }
    } catch {
        Write-Log "  Could not read WU policy keys: $_" -Level "WARN"
    }

    # ---- (5): Telemetry level ----
    try {
        $dc = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ErrorAction SilentlyContinue
        if (& $hasProp $dc 'AllowTelemetry') {
            $r.AllowTelemetry = [int]$dc.AllowTelemetry
            if ($r.AllowTelemetry -eq 0) {
                $r.BlockingReasons += "AllowTelemetry policy is 0 (Security/Off); Microsoft requires >=1 (Required) to service feature updates"
            }
        } else {
            $r.AllowTelemetry = -1
        }
    } catch {
        Write-Log "  Could not read AllowTelemetry: $_" -Level "WARN"
    }

    # ---- (6): WSUS-managed (informational) ----
    try {
        $au = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue
        if ((& $hasProp $au 'UseWUServer') -and [int]$au.UseWUServer -eq 1) {
            $r.WSUSManaged = $true
            $r.BlockingReasons += "Host is WSUS/PME-managed; feature updates require upstream approval (not queryable from client)"
        } else {
            $r.WSUSManaged = $false
        }
    } catch {
        Write-Log "  Could not check WSUS status: $_" -Level "WARN"
    }

    # ---- (4): CPU SSE4.2 ----
    try {
        if (-not ('Win32.PFP' -as [type])) {
            Add-Type -Namespace Win32 -Name PFP -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll")]
public static extern bool IsProcessorFeaturePresent(uint ProcessorFeature);
'@ -ErrorAction Stop | Out-Null
        }
        # PF_SSE4_2_INSTRUCTIONS_AVAILABLE = 38
        $r.CPUSupportsSSE42 = [Win32.PFP]::IsProcessorFeaturePresent(38)
        try {
            $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
            if ($cpu -and (& $hasProp $cpu 'Name')) { $r.CPUName = "$($cpu.Name)" }
        } catch {}
        if (-not $r.CPUSupportsSSE42) {
            $r.BlockingReasons += "CPU does not support SSE4.2 (a 24H2 hard requirement). CPU: $($r.CPUName)"
        }
    } catch {
        Write-Log "  CPU instruction probe failed: $_" -Level "WARN"
    }

    # ---- (7): Stale upgrade artifacts ----
    $artifacts = @(
        @{ Name = '$WINDOWS.~BT'; Path = 'C:\$WINDOWS.~BT' }
        @{ Name = '$WINDOWS.~WS'; Path = 'C:\$WINDOWS.~WS' }
        @{ Name = 'Windows.old';  Path = 'C:\Windows.old'  }
    )
    foreach ($a in $artifacts) {
        if (Test-Path -LiteralPath $a.Path) {
            try {
                $item    = Get-Item -LiteralPath $a.Path -Force -ErrorAction Stop
                $ageDays = [int]((Get-Date) - $item.CreationTime).TotalDays
                $sizeGB  = $null
                try {
                    $bytes = (Get-ChildItem -LiteralPath $a.Path -Recurse -Force -File -ErrorAction SilentlyContinue |
                              Measure-Object Length -Sum -ErrorAction SilentlyContinue).Sum
                    if ($bytes) { $sizeGB = [Math]::Round($bytes / 1GB, 2) }
                } catch {}
                $r.StaleArtifacts += [ordered]@{
                    Name    = $a.Name
                    Path    = $a.Path
                    AgeDays = $ageDays
                    SizeGB  = $sizeGB
                }
                if ($ageDays -ge 14) {
                    $r.BlockingReasons += "Stale upgrade artifact $($a.Path) (age $ageDays days) - clean on remediate"
                }
            } catch {
                Write-Log "  Could not stat $($a.Path): $_" -Level "WARN"
            }
        }
    }

    # ---- (8): Disk space for 64 GB feature update ----
    try {
        $sd  = $env:SystemDrive.TrimEnd('\')
        $obj = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$sd'" -ErrorAction Stop
        if ($obj) {
            $r.DiskFreeGB = [Math]::Round($obj.FreeSpace / 1GB, 2)
            $r.DiskSufficientForFeatureUpd = ($r.DiskFreeGB -ge 64)
            if (-not $r.DiskSufficientForFeatureUpd) {
                $r.BlockingReasons += "System drive has $($r.DiskFreeGB) GB free; feature update install needs ~64 GB"
            }
        }
    } catch {
        Write-Log "  Could not measure disk space for readiness band: $_" -Level "WARN"
    }

    # ---- (3): Safeguard hold heuristic ----
    try {
        $ux = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -ErrorAction SilentlyContinue
        if ($ux) {
            foreach ($p in $ux.PSObject.Properties) {
                if ($p.Name -match '(Safeguard|GatedBlock|BlockedUpdates|FeatureGated)' -and $p.Value) {
                    $r.SafeguardSignals += "$($p.Name) = $($p.Value)"
                }
            }
            if ($r.SafeguardSignals.Count -gt 0) {
                $r.BlockingReasons += "Possible safeguard hold (registry heuristic). Run 'Get-WindowsUpdateLog' and search the output for 'Safeguard' to confirm and identify the specific block."
            }
        }
    } catch {
        Write-Log "  Could not read UX\Settings for safeguard heuristic: $_" -Level "WARN"
    }

    # ---- Final status ----
    if ($r.BlockingReasons.Count -gt 0) {
        $r.Status = "WARN"
        Write-Log ("  WARN - {0} readiness blocker(s):" -f $r.BlockingReasons.Count)
        foreach ($b in $r.BlockingReasons) { Write-Log "    - $b" -Level "WARN" }
        Set-Status "WARN"
    } else {
        $r.Status = "PASS"
        Write-Log "  PASS - no feature update readiness blockers detected from client side"
    }

    $Script:Results["FeatureUpdateReadiness"] = $r
    return $r
}


# ============================================================
#  SECTION 0 - PRE-FLIGHT (environment detection + setup)
# ============================================================

function Test-IsServer {
    Write-Log "=== Pre-flight: detecting OS product type ==="
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $isServer = ($os.ProductType -ne 1)
        $isDC     = ($os.ProductType -eq 2)
        $Script:Environment.IsServer            = $isServer
        $Script:Environment.IsDomainController  = $isDC
        Write-Log ("  ProductType={0}  IsServer={1}  IsDomainController={2}" -f $os.ProductType, $isServer, $isDC)
        if ($isDC) {
            Write-Log "  Domain Controller detected; per operator policy this script proceeds with the standard recipe." -Level "WARN"
        }
    }
    catch {
        Write-Log "  Failed to determine OS product type: $_" -Level "WARN"
    }
}

function Test-IsWsusManaged {
    Write-Log "=== Pre-flight: detecting WSUS / PME management ==="
    # v4.12: explicitly set $false in every "definitively not WSUS-managed"
    # branch so the report distinguishes "No" from "Unknown" (which is
    # reserved for "we couldn't determine - probably because pre-flight
    # never ran, or the registry threw").
    $wsusKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    try {
        $auKey = Get-Item -Path $wsusKey -ErrorAction SilentlyContinue
        if (-not $auKey) {
            Write-Log "  Not WSUS-managed (HKLM\...\WindowsUpdate\AU not present)."
            $Script:Environment.WsusManaged = $false
            return
        }

        if ($auKey.Property -notcontains 'UseWUServer') {
            Write-Log "  AU key present but UseWUServer value is not set; treating as NOT WSUS-managed."
            Write-Log "  (This often indicates a partial GPO or a stale residual policy worth a manual gpresult /h check.)"
            $Script:Environment.WsusManaged = $false
            return
        }

        $val = (Get-ItemProperty -Path $wsusKey -Name UseWUServer -ErrorAction Stop).UseWUServer
        if ($val -eq 1) {
            $Script:Environment.WsusManaged = $true
            $wuKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
            $wuItem = Get-Item -Path $wuKey -ErrorAction SilentlyContinue
            $serverKey = if ($wuItem -and $wuItem.Property -contains 'WUServer') {
                (Get-ItemProperty -Path $wuKey -Name WUServer -ErrorAction SilentlyContinue).WUServer
            } else { "(not set)" }
            Write-Log "  WSUS-managed: UseWUServer=1, WUServer=$serverKey"
            Write-Log "  Remediation will preserve all HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate keys."
            return
        }

        Write-Log "  Not WSUS-managed (UseWUServer=$val)."
        $Script:Environment.WsusManaged = $false
    }
    catch {
        # Leave WsusManaged = $null so the report shows "Unknown" rather than
        # falsely claiming "No" when the registry probe itself failed.
        Write-Log "  WSUS detection error (cannot determine; leaving as Unknown): $_" -Level "WARN"
    }
}

function Install-PSWindowsUpdateIfMissing {
    Write-Log "=== Pre-flight: PSWindowsUpdate module ==="
    try {
        if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
            $Script:Environment.HasPSWindowsUpdate = $true
            Write-Log "  PSWindowsUpdate is already installed."
            Add-Remediation -Step "Pre-flight: PSWindowsUpdate" -Result "INFO" -Detail "already present"
            return
        }
    }
    catch {}

    Write-Log "  PSWindowsUpdate not found. Attempting install from PSGallery..."
    try {
        try {
            [Net.ServicePointManager]::SecurityProtocol =
                [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        } catch {}

        if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers -ErrorAction Stop | Out-Null
        }

        Install-Module -Name PSWindowsUpdate -Force -Scope AllUsers -AllowClobber -SkipPublisherCheck -ErrorAction Stop
        Import-Module PSWindowsUpdate -ErrorAction Stop
        $Script:Environment.HasPSWindowsUpdate = $true
        Write-Log "  PSWindowsUpdate installed successfully."
        Add-Remediation -Step "Pre-flight: install PSWindowsUpdate" -Result "OK" -Detail "from PSGallery"
    }
    catch {
        Write-Log "  PSWindowsUpdate install failed: $_" -Level "WARN"
        Add-Remediation -Step "Pre-flight: install PSWindowsUpdate" -Result "FAILED" -ErrorMessage "$_" -Detail "will fall back to WUA COM"
    }
}

function Backup-WindowsUpdateRegistry {
    # V4: only called on demand (Ensure-WURegistryBackup), not unconditionally.
    # Also: reg.exe stdout/stderr now redirected so the report stays clean.
    if ($Script:Environment.RegBackupPath) {
        Write-Log "=== Pre-flight: WU registry snapshot already taken: $($Script:Environment.RegBackupPath) ==="
        return
    }

    Write-Log "=== Pre-flight: WU registry snapshot ==="
    $stamp   = Get-Date -Format "yyyyMMdd-HHmmss"
    $tmpDir  = "C:\Windows\Temp"
    $regFile = Join-Path $tmpDir "PatchRemediate-WU-Backup-$stamp.reg"

    if (-not (Test-Path $tmpDir)) {
        try { New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null } catch {}
    }

    $keys = @(
        'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate',
        'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate',
        'HKLM\SYSTEM\CurrentControlSet\Services\wuauserv',
        'HKLM\SYSTEM\CurrentControlSet\Services\bits',
        'HKLM\SYSTEM\CurrentControlSet\Services\cryptsvc'
    )

    $combined = New-Object System.Text.StringBuilder
    [void]$combined.AppendLine("Windows Registry Editor Version 5.00")
    [void]$combined.AppendLine("")
    [void]$combined.AppendLine("; PatchRemediate WU snapshot - $stamp")
    [void]$combined.AppendLine("; Host: $env:COMPUTERNAME")
    [void]$combined.AppendLine("")

    $exported = 0
    foreach ($k in $keys) {
        $tmp = Join-Path $tmpDir ("regexp-{0}.tmp" -f ([Guid]::NewGuid().Guid.Substring(0,8)))
        $tmpOut = "$tmp.out"
        $tmpErr = "$tmp.err"
        try {
            # V4: redirect stdout/stderr so reg.exe's "The operation completed successfully."
            # doesn't leak through to N-central's captured output
            $proc = Start-Process -FilePath "reg.exe" -ArgumentList @('export', $k, $tmp, '/y') `
                                  -NoNewWindow -Wait -PassThru `
                                  -RedirectStandardOutput $tmpOut `
                                  -RedirectStandardError  $tmpErr `
                                  -ErrorAction Stop
            if ($proc.ExitCode -eq 0 -and (Test-Path $tmp)) {
                $content = [System.IO.File]::ReadAllText($tmp, [System.Text.Encoding]::Unicode)
                $content = $content -replace '^\s*Windows Registry Editor Version 5\.00\s*\r?\n', ''
                [void]$combined.AppendLine("; ---- $k ----")
                [void]$combined.AppendLine($content)
                $exported++
            } else {
                Write-Log "  reg export skipped for $k (key may not exist; exit=$($proc.ExitCode))" -Level "INFO"
            }
        }
        catch {
            Write-Log "  reg export error for $k : $_" -Level "WARN"
        }
        finally {
            foreach ($f in @($tmp, $tmpOut, $tmpErr)) {
                if (Test-Path $f) { Remove-Item $f -Force -ErrorAction SilentlyContinue }
            }
        }
    }

    try {
        [System.IO.File]::WriteAllText($regFile, $combined.ToString(), [System.Text.UnicodeEncoding]::new($false, $true))
        $Script:Environment.RegBackupPath = $regFile
        Write-Log "  WU registry snapshot saved: $regFile  (subtrees: $exported)"
        Add-Remediation -Step "WU registry backup" -Result "OK" -Detail "$exported subtrees -> $regFile"
    }
    catch {
        Write-Log "  Could not write registry backup: $_" -Level "WARN"
        Add-Remediation -Step "WU registry backup" -Result "FAILED" -ErrorMessage "$_"
    }
}

# V4 helper: lazy-call the registry backup the first time a destructive
# remediation needs it. Cheaper than always running it pre-flight.
function Ensure-WURegistryBackup {
    if (-not $Script:Environment.RegBackupPath) {
        Backup-WindowsUpdateRegistry
    }
}

# V4 helper: detect whether SoftwareDistribution was already renamed by
# this script (or another tool) in the recent past. Prevents re-renaming
# on back-to-back runs which destroys patch history every time.
function Test-RecentSoftwareDistributionReset {
    param([int]$WithinHours = 24)
    try {
        $sysroot = $env:SystemRoot
        $bakDirs = Get-ChildItem -Path $sysroot -Directory -Filter "SoftwareDistribution.bak-*" -ErrorAction SilentlyContinue
        if (-not $bakDirs) { return $false }
        $newest = $bakDirs | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        $age = (Get-Date) - $newest.LastWriteTime
        return ($age.TotalHours -lt $WithinHours)
    } catch {
        return $false
    }
}

# ============================================================
#  REMEDIATION FUNCTIONS  (V4 - gated)
# ============================================================

# Common helper: run a native command silently, redirect stdout to a temp
# file, return @{ ExitCode; Output; Duration } so callers can parse the
# output cleanly without leaking it into N-central's buffer.
function Invoke-CapturedCommand {
    param(
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter(Mandatory)] [string[]]$ArgumentList,
        [string]$OutputEncoding = "Default"
    )
    $tmp = Join-Path $env:TEMP ("captured-{0}.tmp" -f ([Guid]::NewGuid().Guid.Substring(0,8)))
    $start = Get-Date
    try {
        $p = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList `
                           -NoNewWindow -Wait -PassThru `
                           -RedirectStandardOutput $tmp `
                           -ErrorAction Stop
        $output = if (Test-Path $tmp) {
            switch ($OutputEncoding) {
                "Unicode" { [System.IO.File]::ReadAllText($tmp, [System.Text.Encoding]::Unicode) }
                default   { Get-Content -LiteralPath $tmp -Raw -ErrorAction SilentlyContinue }
            }
        } else { "" }
        return @{
            ExitCode = $p.ExitCode
            Output   = $output
            Duration = ((Get-Date) - $start).TotalSeconds
        }
    }
    catch {
        return @{
            ExitCode = -1
            Output   = "$_"
            Duration = ((Get-Date) - $start).TotalSeconds
            Error    = "$_"
        }
    }
    finally {
        if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }
}

# ----------------------------------------------------------------
#  Helper: translate a DISM HRESULT to plain English (v4.9).
#  Covers the codes that show up in 95% of online-repair failures.
#  Anything outside the table returns a generic note that prompts
#  the operator to look up the code on Microsoft Learn.
# ----------------------------------------------------------------
function Get-DISMErrorMeaning {
    param([string]$HResult)
    if (-not $HResult) { return "" }
    switch ($HResult.ToLower()) {
        '0x800f081f' { 'Source files could not be found - component store too damaged for online repair, no usable replacements; rebuild or in-place upgrade required' }
        '0x800f0906' { 'Could not download source files from Windows Update - connectivity, WSUS, or proxy issue' }
        '0x800f0907' { 'DISM blocked by network policy or firewall; source download refused' }
        '0x800f0922' { 'Failed to access repair source location - path invalid or inaccessible' }
        '0x800f081e' { 'No applicable update package found in source - source ISO/WIM is wrong build or edition' }
        '0x800f0831' { 'Package mismatch - manifest does not match installed components; staging payload corrupt' }
        '0x80070003' { 'Path not found - a system file or component manifest is missing on disk' }
        '0x80070005' { 'Access denied - permissions or ACL issue on a system file' }
        '0x80070057' { 'Invalid parameter passed to DISM' }
        '0x80073712' { 'Component store metadata corruption (0x80073712 ERROR_SXS_COMPONENT_STORE_CORRUPT) - severe damage; rebuild candidate' }
        '0x800705b4' { 'Internal DISM operation timed out (different from our wrapper timeout)' }
        '0x80244022' { 'Windows Update server unreachable - cannot pull source files' }
        '0x800f0954' { 'CBS package staging failed - component manifests do not match' }
        '0x800f08a1' { 'Generic CBS error - check CBS.log for the underlying cause' }
        default      { "Unknown DISM HRESULT - search Microsoft Learn for $HResult" }
    }
}

# ----------------------------------------------------------------
#  Helper: tail dism.log and extract recent error HRESULTs (v4.9).
#  Reads the last N lines (default 10000), filters to Error-level
#  rows whose timestamp is at-or-after $Since, and pulls any
#  HRESULT it finds. Returns the list newest-first.
# ----------------------------------------------------------------
function Get-DISMLogErrors {
    param(
        [datetime]$Since = (Get-Date).AddHours(-1),
        [int]$TailLines  = 10000
    )

    $logPath = "$env:WINDIR\Logs\DISM\dism.log"
    if (-not (Test-Path $logPath)) {
        return [pscustomobject]@{ Found = $false; Errors = @(); Note = "dism.log not present" }
    }

    try {
        $tail = Get-Content -LiteralPath $logPath -Tail $TailLines -ErrorAction Stop
    } catch {
        return [pscustomobject]@{ Found = $false; Errors = @(); Note = "could not read dism.log: $_" }
    }

    $errors = [System.Collections.Generic.List[object]]::new()
    foreach ($line in $tail) {
        # DISM log lines: 'YYYY-MM-DD HH:MM:SS, Error  ...' (commas/spacing vary)
        if ($line -notmatch '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})[, ]+(Error|Warning|Info)') { continue }
        if ($matches[2] -ne 'Error') { continue }

        $ts = $null
        try { $ts = [datetime]::ParseExact($matches[1], 'yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture) } catch { continue }
        if ($ts -lt $Since) { continue }

        # Pull HRESULT - DISM uses several formats: [HRESULT = 0x...], [0x...], or a raw 0x... token
        $hr = $null
        if     ($line -match 'HRESULT\s*=\s*(0x[0-9a-fA-F]{8})')                          { $hr = $matches[1].ToLower() }
        elseif ($line -match '\[(0x[0-9a-fA-F]{8})\]')                                     { $hr = $matches[1].ToLower() }
        elseif ($line -match '(?<![0-9a-fA-F])(0x[0-9a-fA-F]{8})(?![0-9a-fA-F])')          { $hr = $matches[1].ToLower() }

        if (-not $hr) { continue }   # skip Error lines without a code; they're rarely actionable

        $errors.Add([pscustomobject]@{
            Time    = $ts
            HResult = $hr
            Line    = $line.Trim()
        }) | Out-Null
    }

    return [pscustomobject]@{ Found = $true; Errors = $errors; Note = ("scanned tail of {0} lines" -f $TailLines) }
}

# ----------------------------------------------------------------
#  Helper: after a DISM step fails, look up its HRESULTs in
#  dism.log and append a plain-English summary to the result so
#  the FAILED report row shows what actually went wrong.
# ----------------------------------------------------------------
function Add-DISMTriage {
    param(
        [Parameter(Mandatory)] [string]$Step,
        [Parameter(Mandatory)] [datetime]$StepStartTime,
        [Parameter(Mandatory)] [string]$BaseError
    )

    $Script:DISMAttempted = $true
    $triage = Get-DISMLogErrors -Since $StepStartTime
    if (-not $triage.Found -or $triage.Errors.Count -eq 0) {
        return $BaseError
    }

    # Most recent code is usually the most informative
    $latest  = $triage.Errors | Select-Object -Last 1
    $meaning = Get-DISMErrorMeaning $latest.HResult

    $Script:DISMFindings.Add([pscustomobject]@{
        Step     = $Step
        Time     = $latest.Time
        HResult  = $latest.HResult
        Meaning  = $meaning
    }) | Out-Null

    return ("{0}; dism.log shows {1}: {2}" -f $BaseError, $latest.HResult, $meaning)
}

# ----------------------------------------------------------------
#  Helper: format an exit code for the report (v4.7).
#  Returns "exit N" when ExitCode is non-null, otherwise a candid
#  "no exit code returned" message.  DISM and SFC on a damaged
#  component store can exit without producing a readable code.
# ----------------------------------------------------------------
function Format-ExitCode {
    param($Result)
    if (-not $Result) { return "no exit code returned" }

    # Defensively probe for the ExitCode key. Under Set-StrictMode -Version
    # Latest, a bare $Result.ExitCode access throws when the property is
    # absent. The wrapper always sets ExitCode but this keeps callers safe.
    $code = $null
    if ($Result -is [System.Collections.IDictionary]) {
        if ($Result.Contains("ExitCode")) { $code = $Result["ExitCode"] }
    } else {
        $hasExit = Get-Member -InputObject $Result -Name "ExitCode" -MemberType Properties -ErrorAction SilentlyContinue
        if ($hasExit) { $code = $Result.ExitCode }
    }

    if ($null -eq $code -or "$code" -eq "") { return "no exit code returned" }
    return "exit $code"
}

# ----------------------------------------------------------------
#  Disk cleanup - GATED
# ----------------------------------------------------------------
function Invoke-DiskCleanupRemediation {
    Write-Log "=== Remediation: Disk cleanup ==="

    $disk = $Script:Results["DiskSpace"]
    $wuS  = $Script:Results["WUServices"]

    # v4.5: tightened gating.
    #   - LCU-stale trigger DROPPED. Stale LCU usually points at WU stack
    #     failure (services dead, COM broken, WSUS misrouted), not disk
    #     pressure. Running /StartComponentCleanup against a damaged store
    #     hangs for 60+ minutes and accomplishes nothing - it does not
    #     repair, only frees space.
    #   - Disk-low buffer tightened from MinFreeGB+10 to MinFreeGB+5.
    #   - When WU services are degraded, we skip cleanup entirely - the
    #     real cure is Phase 2 component reset + DISM /RestoreHealth.
    $diskLow      = ($disk -and $disk["FreeGB"] -lt ($MinFreeGB + 5))
    $wuDegraded   = ($wuS  -and -not $wuS["OverallHealthy"])

    $reasons = @()
    if ($ForceCleanup)                  { $reasons += "-ForceCleanup specified" }
    if ($diskLow -and -not $wuDegraded) { $reasons += ("free disk {0} GB below MinFreeGB+5 ({1} GB) buffer" -f $disk['FreeGB'], ($MinFreeGB + 5)) }
    if ($diskLow -and $wuDegraded)      { Write-Log "  Disk-low detected but WU services degraded; deferring cleanup so Phase 2 RestoreHealth has the budget." }

    if (-not $reasons) {
        $skipDetail = if ($wuDegraded) {
            "disk free $($disk['FreeGB']) GB; WU stack degraded - Phase 2 will handle the component store"
        } else {
            "disk free $($disk['FreeGB']) GB; no cleanup needed"
        }
        Add-Remediation -Step "Disk cleanup" -Result "SKIPPED" -Detail $skipDetail
        return
    }
    Write-Log ("  Cleanup justified by: {0}" -f ($reasons -join '; '))

    # 1. DISM /StartComponentCleanup  (v4.5: bounded; outer gate already
    #    excluded WU-degraded boxes. Inner gate is now budget-only.)
    $cleanupSkipReason = $null
    if ((Get-RemainingBudgetSec) -lt 1800) {
        $cleanupSkipReason = "remaining budget under 30 min; reserving budget for RestoreHealth/SFC"
    }

    if ($cleanupSkipReason) {
        Add-Remediation -Step "DISM StartComponentCleanup" -Result "SKIPPED" -Detail $cleanupSkipReason
    } else {
        Write-Log "  Running DISM /Online /Cleanup-Image /StartComponentCleanup ..."
        $stepStart = Get-Date
        $r = Invoke-CapturedCommandWithTimeout -FilePath "dism.exe" `
                -ArgumentList @('/Online','/Cleanup-Image','/StartComponentCleanup','/Quiet') `
                -Label "DISM StartComponentCleanup"
        if ($r.TimedOut) {
            $base = "TIMEOUT after $([int]$r.Duration)s; component store likely damaged - Phase 2 RestoreHealth will retry"
            $msg  = Add-DISMTriage -Step "DISM StartComponentCleanup" -StepStartTime $stepStart -BaseError $base
            Add-Remediation -Step "DISM StartComponentCleanup" -Result "FAILED" -DurationSec $r.Duration `
                -ErrorMessage $msg
        } elseif ($r.ExitCode -eq 0 -or $r.ExitCode -eq 3010) {
            Add-Remediation -Step "DISM StartComponentCleanup" -Result "OK" -DurationSec $r.Duration
        } else {
            $exitTxt = Format-ExitCode $r
            $base = $exitTxt
            $msg  = Add-DISMTriage -Step "DISM StartComponentCleanup" -StepStartTime $stepStart -BaseError $base
            Add-Remediation -Step "DISM StartComponentCleanup" -Result "FAILED" -DurationSec $r.Duration -ErrorMessage $msg
        }
    }

    # 2. Prune %WINDIR%\Temp
    Write-Log "  Pruning C:\Windows\Temp of files older than 7 days ..."
    $start = Get-Date
    try {
        $cutoff  = (Get-Date).AddDays(-7)
        $removed = 0; $bytes = 0
        Get-ChildItem -Path "C:\Windows\Temp" -File -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $cutoff -and $_.FullName -notmatch 'PatchRemediate-' } |
            ForEach-Object {
                try {
                    $bytes  += $_.Length
                    Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop
                    $removed++
                } catch {}
            }
        $mb  = [math]::Round($bytes / 1MB, 2)
        $dur = ((Get-Date) - $start).TotalSeconds
        Add-Remediation -Step "Prune C:\Windows\Temp (>7 days)" -Result "OK" -DurationSec $dur -Detail "removed $removed files, ${mb} MB"
    }
    catch {
        Add-Remediation -Step "Prune C:\Windows\Temp (>7 days)" -Result "FAILED" -ErrorMessage "$_"
    }
}

# ----------------------------------------------------------------
#  Service health - always runs (cheap; observation-only when healthy)
# ----------------------------------------------------------------
function Invoke-ServicesRemediation {
    Write-Log "=== Remediation: Windows Update services ==="
    $alwaysRunning = @('wuauserv', 'cryptsvc')
    $demandStart   = @('bits', 'msiserver', 'appidsvc', 'dosvc', 'TrustedInstaller')

    foreach ($name in ($alwaysRunning + $demandStart)) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $svc) {
            Add-Remediation -Step "Service '$name'" -Result "SKIPPED" -Detail "service not present on this OS"
            continue
        }

        $startType = "Unknown"
        try {
            $startType = (Get-CimInstance -ClassName Win32_Service -Filter "Name='$name'" -ErrorAction Stop).StartMode
        } catch {}

        if ($startType -eq 'Disabled') {
            Add-Remediation -Step "Service '$name'" -Result "SKIPPED" -Detail "currently Disabled - admin intent preserved"
            continue
        }

        if ($name -in $alwaysRunning) {
            if ($svc.Status -ne 'Running') {
                try {
                    Start-Service -Name $name -ErrorAction Stop
                    Add-Remediation -Step "Service '$name' Start" -Result "OK" -Detail "was $($svc.Status), StartType=$startType"
                } catch {
                    Add-Remediation -Step "Service '$name' Start" -Result "FAILED" -ErrorMessage "$_"
                }
            } else {
                Add-Remediation -Step "Service '$name'" -Result "INFO" -Detail "Running ($startType) - OK"
            }
        } else {
            Add-Remediation -Step "Service '$name'" -Result "INFO" -Detail "$($svc.Status) ($startType) - demand-start, no action"
        }
    }
}

# ----------------------------------------------------------------
#  WU Component Reset - GATED (most aggressive step in the script)
# ----------------------------------------------------------------
function Invoke-WUComponentReset {
    Write-Log "=== Remediation: WU Component Reset (gated) ==="

    $reasons = @()

    if ($ForceComponentReset) { $reasons += "-ForceComponentReset specified" }

    $wuS = $Script:Results["WUServices"]
    if ($wuS -and -not $wuS["OverallHealthy"])     { $reasons += "WU service health DEGRADED" }
    if ($wuS -and -not $wuS["AllMandatoryOK"])     { $reasons += "required WU service in unhealthy state" }
    if ($wuS -and -not $wuS["WUAComReachable"])    { $reasons += "WUA COM not reachable" }

    $lcu = $Script:Results["LCUCheck"]
    if ($lcu -and $lcu.Contains("BookkeepingHealthy") -and -not $lcu["BookkeepingHealthy"]) {
        # Only count as a reason if we DIDN'T already reset recently. Otherwise
        # the bookkeeping is degraded because we just reset it - re-running
        # would destroy whatever rebuild has happened so far.
        if (-not (Test-RecentSoftwareDistributionReset -WithinHours 24)) {
            $reasons += "patch bookkeeping DEGRADED (no recent reset detected)"
        } else {
            Write-Log "  Bookkeeping is degraded but a SoftwareDistribution.bak-* from the last 24h was found." -Level "INFO"
            Write-Log "  Skipping component reset to allow the rebuild to complete." -Level "INFO"
        }
    }

    if (-not $reasons) {
        Add-Remediation -Step "WU Component Reset" -Result "SKIPPED" `
            -Detail "WU stack healthy, no reset needed (use -ForceComponentReset to override)"
        return
    }
    Write-Log ("  Component reset triggered by: {0}" -f ($reasons -join '; '))

    # Take registry backup before doing anything destructive
    Ensure-WURegistryBackup

    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"

    # ---- Step 1: stop services in dependency order ----
    $stopServices = @('wuauserv', 'bits', 'cryptsvc', 'msiserver', 'appidsvc')
    foreach ($n in $stopServices) {
        try {
            $s = Get-Service -Name $n -ErrorAction SilentlyContinue
            if (-not $s) { continue }
            if ($s.Status -ne 'Stopped') {
                Stop-Service -Name $n -Force -ErrorAction Stop
                Add-Remediation -Step "Stop $n" -Result "OK"
            } else {
                Add-Remediation -Step "Stop $n" -Result "INFO" -Detail "already stopped"
            }
        } catch {
            Add-Remediation -Step "Stop $n" -Result "FAILED" -ErrorMessage "$_"
        }
    }

    # ---- Step 2: rename SoftwareDistribution and catroot2 ----
    $renameTargets = @(
        @{ Path = "$env:SystemRoot\SoftwareDistribution"; NewName = "SoftwareDistribution.bak-$stamp" },
        @{ Path = "$env:SystemRoot\System32\catroot2";    NewName = "catroot2.bak-$stamp" }
    )
    foreach ($t in $renameTargets) {
        try {
            if (Test-Path $t.Path) {
                Rename-Item -LiteralPath $t.Path -NewName $t.NewName -Force -ErrorAction Stop
                Add-Remediation -Step "Rename $(Split-Path $t.Path -Leaf)" -Result "OK" -Detail "-> $($t.NewName)"
            } else {
                Add-Remediation -Step "Rename $(Split-Path $t.Path -Leaf)" -Result "SKIPPED" -Detail "path not present"
            }
        } catch {
            Add-Remediation -Step "Rename $(Split-Path $t.Path -Leaf)" -Result "FAILED" -ErrorMessage "$_"
        }
    }

    # ---- Step 3: clear BITS qmgr*.dat ----
    $bitsPath = "$env:ALLUSERSPROFILE\Microsoft\Network\Downloader"
    try {
        if (Test-Path $bitsPath) {
            $files = Get-ChildItem -Path $bitsPath -Filter "qmgr*.dat" -ErrorAction SilentlyContinue
            $count = 0
            foreach ($f in $files) {
                try { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop; $count++ } catch {}
            }
            Add-Remediation -Step "Clear BITS qmgr*.dat" -Result "OK" -Detail "removed $count file(s)"
        } else {
            Add-Remediation -Step "Clear BITS qmgr*.dat" -Result "SKIPPED" -Detail "Downloader path not present"
        }
    } catch {
        Add-Remediation -Step "Clear BITS qmgr*.dat" -Result "FAILED" -ErrorMessage "$_"
    }

    # ---- Step 4: re-register WU/COM DLLs (V4: deprecated DLLs SKIPPED on modern Windows) ----
    $dlls = @(
        'atl.dll','urlmon.dll','mshtml.dll','shdocvw.dll','browseui.dll',
        'jscript.dll','vbscript.dll','scrrun.dll','msxml.dll','msxml3.dll','msxml6.dll',
        'actxprxy.dll','softpub.dll','wintrust.dll','dssenh.dll','rsaenh.dll',
        'gpkcsp.dll','sccbase.dll','slbcsp.dll','cryptdlg.dll','oleaut32.dll','ole32.dll',
        'shell32.dll','initpki.dll',
        'wuapi.dll','wuaueng.dll','wuaueng1.dll','wucltui.dll','wups.dll','wups2.dll','wuweb.dll',
        'qmgr.dll','qmgrprxy.dll','wucltux.dll','muweb.dll','wuwebv.dll'
    )
    # DLLs whose DllRegisterServer is locked or removed on Server 2016+ / Win 10+.
    # Calling regsvr32 against these always returns exit 4. Mark as SKIPPED.
    $deprecatedOnModern = @{
        'mshtml.dll'   = 'IE rendering engine - DllRegisterServer locked on Win10/2016+'
        'shdocvw.dll'  = 'IE Shell - DllRegisterServer locked on Win10/2016+'
        'browseui.dll' = 'IE BrowseUI - DllRegisterServer locked on Win10/2016+'
        'wuaueng.dll'  = 'WU engine - DllRegisterServer locked on Win10/2016+'
        'qmgr.dll'     = 'BITS queue manager - DllRegisterServer locked on Win10/2016+'
        # v4.19: wuapi.dll's ACL/MIC on Win10/11 causes regsvr32 to fail
        # with exit 5 (access denied). The DLL is already correctly
        # registered as part of the WU service install; re-registering
        # is unnecessary on modern Windows.
        'wuapi.dll'    = 'WU API - regsvr32 blocked by ACL/MIC on Win10/11'
    }

    $sys32 = "$env:SystemRoot\System32"
    $okList   = New-Object System.Collections.Generic.List[string]
    $missList = New-Object System.Collections.Generic.List[string]
    $failList = New-Object System.Collections.Generic.List[string]
    $skipList = New-Object System.Collections.Generic.List[string]
    $start = Get-Date
    foreach ($dll in $dlls) {
        $full = Join-Path $sys32 $dll
        if (-not (Test-Path $full)) { $missList.Add($dll); continue }

        if ($Script:Environment.IsModernWindows -and $deprecatedOnModern.ContainsKey($dll)) {
            $skipList.Add($dll)
            Add-Remediation -Step "regsvr32 /s $dll" -Result "SKIPPED" -Detail $deprecatedOnModern[$dll]
            continue
        }

        try {
            $p = Start-Process -FilePath "regsvr32.exe" -ArgumentList @('/s', $full) -NoNewWindow -Wait -PassThru -ErrorAction Stop
            if ($p.ExitCode -eq 0) { $okList.Add($dll) } else {
                $failList.Add(("{0} (exit {1})" -f $dll, $p.ExitCode))
                Add-Remediation -Step "regsvr32 /s $dll" -Result "FAILED" -ErrorMessage "exit $($p.ExitCode)"
            }
        } catch {
            $failList.Add(("{0} (exception)" -f $dll))
            Add-Remediation -Step "regsvr32 /s $dll" -Result "FAILED" -ErrorMessage "$_"
        }
    }
    $dur = ((Get-Date) - $start).TotalSeconds

    $summary = "{0} ok / {1} failed / {2} skipped (deprecated) / {3} not-present" -f $okList.Count, $failList.Count, $skipList.Count, $missList.Count
    if ($failList.Count -eq 0) {
        Add-Remediation -Step "Re-register WU/COM DLLs (regsvr32 /s)" -Result "OK" -DurationSec $dur -Detail $summary
    } else {
        Add-Remediation -Step "Re-register WU/COM DLLs (regsvr32 /s)" -Result "FAILED" -DurationSec $dur `
            -Detail "$summary; failed: $($failList -join ', ')"
    }

    # ---- Step 5: reset WinHTTP proxy (skip if a proxy is configured) ----
    try {
        $proxy = (& netsh winhttp show proxy 2>&1) -join "`n"
        if ($proxy -match 'Direct access \(no proxy server\)') {
            Add-Remediation -Step "Reset WinHTTP proxy" -Result "SKIPPED" -Detail "already Direct access, no change needed"
        } elseif ($proxy -match 'Proxy Server\(s\)\s*:\s*(\S+)') {
            $proxyValue = $matches[1]
            Add-Remediation -Step "Reset WinHTTP proxy" -Result "SKIPPED" -Detail "proxy configured ($proxyValue) - preserving"
        } else {
            $r = & netsh winhttp reset proxy 2>&1
            Add-Remediation -Step "Reset WinHTTP proxy" -Result "OK" -Detail (($r | Out-String).Trim())
        }
    } catch {
        Add-Remediation -Step "Reset WinHTTP proxy" -Result "FAILED" -ErrorMessage "$_"
    }

    # ---- Step 6: restart services ----
    $startServices = @('cryptsvc', 'bits', 'msiserver', 'appidsvc', 'wuauserv')
    foreach ($n in $startServices) {
        try {
            $s = Get-Service -Name $n -ErrorAction SilentlyContinue
            if (-not $s) { continue }
            if ((Get-CimInstance -ClassName Win32_Service -Filter "Name='$n'" -ErrorAction SilentlyContinue).StartMode -eq 'Disabled') {
                Add-Remediation -Step "Start $n" -Result "SKIPPED" -Detail "Disabled - admin intent preserved"
                continue
            }
            if ($s.Status -ne 'Running') {
                Start-Service -Name $n -ErrorAction Stop
                Add-Remediation -Step "Start $n" -Result "OK"
            } else {
                Add-Remediation -Step "Start $n" -Result "INFO" -Detail "already running"
            }
        } catch {
            Add-Remediation -Step "Start $n" -Result "FAILED" -ErrorMessage "$_"
        }
    }

    # ---- Step 7: prune old .bak-* folders (V4) ----
    Invoke-BakRetentionPrune
}

# V4 helper: clean up SoftwareDistribution.bak-* and catroot2.bak-*
# folders older than $BakRetentionDays. Runs at the end of a successful
# WU component reset so we don't accumulate stale backups indefinitely.
function Invoke-BakRetentionPrune {
    $cutoff = (Get-Date).AddDays(-$BakRetentionDays)
    $candidates = @(
        @{ Path = "$env:SystemRoot";          Pattern = "SoftwareDistribution.bak-*" },
        @{ Path = "$env:SystemRoot\System32"; Pattern = "catroot2.bak-*"             }
    )
    $removed = 0; $kept = 0
    foreach ($c in $candidates) {
        try {
            Get-ChildItem -Path $c.Path -Directory -Filter $c.Pattern -ErrorAction SilentlyContinue |
                ForEach-Object {
                    if ($_.LastWriteTime -lt $cutoff) {
                        try {
                            Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction Stop
                            $removed++
                        } catch {}
                    } else {
                        $kept++
                    }
                }
        } catch {}
    }
    if ($removed -gt 0 -or $kept -gt 0) {
        Add-Remediation -Step "Prune .bak-* folders (>$BakRetentionDays days)" -Result "OK" `
            -Detail "removed $removed, kept $kept newer"
    }
}

function Invoke-FeatureUpdateReadinessRemediation {
    Write-Log "=== Remediation: Feature Update Readiness ==="

    if (-not $Script:Results.Contains("FeatureUpdateReadiness")) {
        Write-Log "  Skipping - readiness check did not run on this host"
        return
    }
    $r = $Script:Results["FeatureUpdateReadiness"]
    if (-not $r["Applicable"]) {
        Write-Log "  Skipping - readiness check did not apply (Server SKU or already on 24H2+)"
        return
    }

    # ---- Always-on: clean stale upgrade artifacts older than 14 days ----
    $stale = @($r["StaleArtifacts"] | Where-Object { $_["AgeDays"] -ge 14 })
    if ($stale.Count -gt 0) {
        foreach ($a in $stale) {
            $label = "Clean stale artifact $($a['Name'])"
            try {
                $sizeNote = if ($a["SizeGB"]) { "~$($a['SizeGB']) GB freed" } else { "size unknown" }
                Write-Log "  Removing $($a['Path']) (age $($a['AgeDays']) days, $sizeNote)..."
                Remove-Item -LiteralPath $a["Path"] -Recurse -Force -ErrorAction Stop
                Add-Remediation -Step $label -Result "OK" -Detail "age was $($a['AgeDays']) days; $sizeNote"
            } catch {
                Add-Remediation -Step $label -Result "FAILED" -ErrorMessage "$_"
            }
        }
    } else {
        $hasAny = (@($r["StaleArtifacts"]).Count -gt 0)
        $detail = if ($hasAny) { "present but all under 14 days old" } else { "none present" }
        Add-Remediation -Step "Clean stale upgrade artifacts" -Result "INFO" -Detail $detail
    }

    # ---- Opt-in: -UnblockFeatureUpdates handles the policy/telemetry side ----
    $hasPolicyBlocker = ($r["TargetReleaseVersion"] -or $r["ProductVersion"] -or
                         $r["DeferFeatureUpdates"]  -or ($r["AllowTelemetry"] -eq 0))

    if (-not $UnblockFeatureUpdates) {
        if ($hasPolicyBlocker) {
            Add-Remediation -Step "Feature update policy unblock" -Result "SKIPPED" `
                -Detail "policy/telemetry changes require -UnblockFeatureUpdates switch (script does not touch WU policy keys by default)"
        }
        return
    }

    if (-not $hasPolicyBlocker) {
        Add-Remediation -Step "Feature update policy unblock" -Result "INFO" -Detail "no policy/telemetry blockers to unblock"
        return
    }

    # Destructive policy changes - back up first
    Ensure-WURegistryBackup
    $wuKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $dcKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"

    foreach ($val in 'TargetReleaseVersion','TargetReleaseVersionInfo','ProductVersion') {
        try {
            $existing = Get-ItemProperty -Path $wuKey -Name $val -ErrorAction SilentlyContinue
            if ($null -ne $existing) {
                Remove-ItemProperty -Path $wuKey -Name $val -ErrorAction Stop
                Add-Remediation -Step "Remove WU policy: $val" -Result "OK" -Detail "feature-update pin cleared"
            }
        } catch {
            Add-Remediation -Step "Remove WU policy: $val" -Result "FAILED" -ErrorMessage "$_"
        }
    }

    if ($r["DeferFeatureUpdates"]) {
        try {
            Set-ItemProperty -Path $wuKey -Name 'DeferFeatureUpdates'             -Value 0 -Type DWord -ErrorAction Stop
            Set-ItemProperty -Path $wuKey -Name 'DeferFeatureUpdatesPeriodInDays' -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Add-Remediation -Step "Zero DeferFeatureUpdates" -Result "OK"
        } catch {
            Add-Remediation -Step "Zero DeferFeatureUpdates" -Result "FAILED" -ErrorMessage "$_"
        }
    }

    if ($r["AllowTelemetry"] -eq 0) {
        try {
            if (-not (Test-Path $dcKey)) { New-Item -Path $dcKey -Force -ErrorAction Stop | Out-Null }
            Set-ItemProperty -Path $dcKey -Name 'AllowTelemetry' -Value 1 -Type DWord -ErrorAction Stop
            Add-Remediation -Step "Raise AllowTelemetry 0 -> 1" -Result "OK" -Detail "Required diagnostic data is the minimum for feature updates"
        } catch {
            Add-Remediation -Step "Raise AllowTelemetry 0 -> 1" -Result "FAILED" -ErrorMessage "$_"
        }
    }

    # Apply group policy so the changes take effect without a reboot
    try {
        $proc = Start-Process -FilePath "gpupdate.exe" -ArgumentList @('/force') -NoNewWindow -Wait -PassThru -ErrorAction Stop
        $rc   = $proc.ExitCode
        if ($rc -eq 0) {
            Add-Remediation -Step "Refresh group policy (gpupdate /force)" -Result "OK"
        } else {
            Add-Remediation -Step "Refresh group policy (gpupdate /force)" -Result "FAILED" -ErrorMessage "exit $rc"
        }
    } catch {
        Add-Remediation -Step "Refresh group policy (gpupdate /force)" -Result "FAILED" -ErrorMessage "$_"
    }
}

function Invoke-PendingRebootRemediation {
    Write-Log "=== Remediation: Pending reboot artefacts ==="
    $pending = Join-Path $env:SystemRoot "WinSxS\pending.xml"
    if (-not (Test-Path $pending)) {
        Add-Remediation -Step "pending.xml check" -Result "INFO" -Detail "not present"
        return
    }

    try {
        $age = (Get-Date) - (Get-Item $pending).LastWriteTime
        if ($age.TotalDays -lt $PendingXmlAgeDays) {
            Add-Remediation -Step "pending.xml age check" -Result "SKIPPED" -Detail ("present but only {0:N1} days old (< {1})" -f $age.TotalDays, $PendingXmlAgeDays)
            return
        }
        $stamp   = Get-Date -Format "yyyyMMdd-HHmmss"
        $newName = "pending.xml.bak-$stamp"
        Rename-Item -LiteralPath $pending -NewName $newName -Force -ErrorAction Stop
        Add-Remediation -Step "Rename stale pending.xml" -Result "OK" -Detail ("was {0:N1} days old -> {1}" -f $age.TotalDays, $newName)
    } catch {
        Add-Remediation -Step "Rename stale pending.xml" -Result "FAILED" -ErrorMessage "$_"
    }
}

# ----------------------------------------------------------------
#  Time sync remediation - GATED (only when Phase 1 saw drift)
# ----------------------------------------------------------------
function Invoke-TimeSyncRemediation {
    Write-Log "=== Remediation: Time synchronization ==="
    if ($Script:Environment.IsDomainController) {
        Add-Remediation -Step "Time sync (w32tm /resync)" -Result "SKIPPED" -Detail "Domain controller - skipping external resync"
        return
    }
    $tsync = $Script:Results["TimeSync"]
    if ($tsync -and ($tsync["Status"] -in @("PASS"))) {
        Add-Remediation -Step "Time sync (w32tm /resync)" -Result "SKIPPED" -Detail "Phase 1 reported time sync PASS - no resync needed"
        return
    }

    try {
        $svc = Get-Service -Name w32time -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne 'Running') {
            Start-Service -Name w32time -ErrorAction Stop
            Add-Remediation -Step "Start w32time" -Result "OK"
        }
        $r = & w32tm /resync /force 2>&1
        $exit = $LASTEXITCODE
        if ($exit -eq 0) {
            Add-Remediation -Step "w32tm /resync /force" -Result "OK" -Detail (($r | Out-String).Trim() -replace "`r?`n", " | ")
        } else {
            Add-Remediation -Step "w32tm /resync /force" -Result "FAILED" -ErrorMessage (($r | Out-String).Trim())
        }
    } catch {
        Add-Remediation -Step "w32tm /resync /force" -Result "FAILED" -ErrorMessage "$_"
    }
}

# ----------------------------------------------------------------
#  Component store repair - GATED at the ScanHealth step
# ----------------------------------------------------------------
function Invoke-ComponentStoreRepair {
    Write-Log "=== Remediation: Component store repair (DISM + SFC) ==="
    Write-Log ("  Time budget: {0}" -f (Format-Budget))

    $needRestore = $false
    $checkFlaggedDamage = $false

    # ---- DISM /CheckHealth (always - normally 1-2s, cap at 5 min) ----
    if (-not (Test-RemainingBudget -NeededSec 60)) {
        Add-Remediation -Step "DISM /CheckHealth" -Result "SKIPPED" -Detail "no remaining script budget"
    } else {
        $stepStart = Get-Date
        $r = Invoke-CapturedCommandWithTimeout -FilePath "dism.exe" `
                -ArgumentList @('/Online','/Cleanup-Image','/CheckHealth','/Quiet') `
                -Label "DISM /CheckHealth"
        if ($r.TimedOut) {
            $checkFlaggedDamage = $true
            $base = "TIMEOUT after $([int]$r.Duration)s; treating as 'damage suspected' and proceeding to ScanHealth"
            $msg  = Add-DISMTriage -Step "DISM /CheckHealth" -StepStartTime $stepStart -BaseError $base
            Add-Remediation -Step "DISM /CheckHealth" -Result "FAILED" -DurationSec $r.Duration `
                -ErrorMessage $msg
        } elseif ($r.ExitCode -eq 0) {
            if ($r.Output -match 'No component store corruption detected') {
                Add-Remediation -Step "DISM /CheckHealth" -Result "OK" -DurationSec $r.Duration -Detail "no corruption"
            } else {
                $checkFlaggedDamage = $true
                Add-Remediation -Step "DISM /CheckHealth" -Result "OK" -DurationSec $r.Duration -Detail "potential damage flagged"
            }
        } else {
            # v4.6: a non-zero CheckHealth is itself a damage signal. Escalate
            # to ScanHealth rather than silently skipping the rest of the chain.
            $checkFlaggedDamage = $true
            $exitTxt = Format-ExitCode $r
            $base = "$exitTxt; treating as 'damage suspected' - escalating to ScanHealth"
            $msg  = Add-DISMTriage -Step "DISM /CheckHealth" -StepStartTime $stepStart -BaseError $base
            Add-Remediation -Step "DISM /CheckHealth" -Result "FAILED" -DurationSec $r.Duration `
                -ErrorMessage $msg
        }
    }

    # ---- DISM /ScanHealth (only if CheckHealth saw damage OR -ForceFullDISM) ----
    if (-not ($checkFlaggedDamage -or $ForceFullDISM)) {
        Add-Remediation -Step "DISM /ScanHealth" -Result "SKIPPED" `
            -Detail "CheckHealth reported clean (use -ForceFullDISM to scan anyway)"
    } elseif (-not (Test-RemainingBudget -NeededSec 120)) {
        Add-Remediation -Step "DISM /ScanHealth" -Result "SKIPPED" -Detail "insufficient remaining script budget (need >2 min)"
    } else {
        $reason = if ($ForceFullDISM -and -not $checkFlaggedDamage) { "-ForceFullDISM specified" } else { "CheckHealth flagged damage" }
        Write-Log "  Running DISM /ScanHealth ($reason)..."
        $stepStart = Get-Date
        $r = Invoke-CapturedCommandWithTimeout -FilePath "dism.exe" `
                -ArgumentList @('/Online','/Cleanup-Image','/ScanHealth','/Quiet') `
                -Label "DISM /ScanHealth"
        if ($r.TimedOut) {
            $needRestore = $true
            $base = "TIMEOUT after $([int]$r.Duration)s; assuming damage and proceeding to RestoreHealth"
            $msg  = Add-DISMTriage -Step "DISM /ScanHealth" -StepStartTime $stepStart -BaseError $base
            Add-Remediation -Step "DISM /ScanHealth" -Result "FAILED" -DurationSec $r.Duration `
                -ErrorMessage $msg
        } elseif ($r.ExitCode -eq 0) {
            if ($r.Output -match 'No component store corruption detected') {
                Add-Remediation -Step "DISM /ScanHealth" -Result "OK" -DurationSec $r.Duration -Detail "no corruption detected"
            } else {
                $needRestore = $true
                Add-Remediation -Step "DISM /ScanHealth" -Result "OK" -DurationSec $r.Duration -Detail "damage detected - will run RestoreHealth"
            }
        } else {
            # v4.8: symmetric with CheckHealth escalation (v4.6). A non-zero
            # ScanHealth exit is itself a damage signal - escalate to
            # RestoreHealth rather than silently skipping the actual repair.
            $needRestore = $true
            $exitTxt = Format-ExitCode $r
            $base = "$exitTxt; treating as 'damage suspected' - escalating to RestoreHealth"
            $msg  = Add-DISMTriage -Step "DISM /ScanHealth" -StepStartTime $stepStart -BaseError $base
            Add-Remediation -Step "DISM /ScanHealth" -Result "FAILED" -DurationSec $r.Duration `
                -ErrorMessage $msg
        }
    }

    # ---- DISM /RestoreHealth (only if scan found damage; cap 25 min) ----
    if (-not $needRestore) {
        Add-Remediation -Step "DISM /RestoreHealth" -Result "SKIPPED" -Detail "no damage detected"
    } elseif (-not (Test-RemainingBudget -NeededSec 300)) {
        Add-Remediation -Step "DISM /RestoreHealth" -Result "SKIPPED" -Detail "insufficient remaining script budget (need >5 min)"
    } else {
        Write-Log "  Running DISM /RestoreHealth ..."
        $stepStart = Get-Date
        $r = Invoke-CapturedCommandWithTimeout -FilePath "dism.exe" `
                -ArgumentList @('/Online','/Cleanup-Image','/RestoreHealth','/Quiet') `
                -Label "DISM /RestoreHealth"
        if ($r.TimedOut) {
            $base = "TIMEOUT after $([int]$r.Duration)s; component store damage too deep for online repair - rebuild candidate"
            $msg  = Add-DISMTriage -Step "DISM /RestoreHealth" -StepStartTime $stepStart -BaseError $base
            Add-Remediation -Step "DISM /RestoreHealth" -Result "FAILED" -DurationSec $r.Duration `
                -ErrorMessage $msg
        } elseif ($r.ExitCode -eq 0) {
            Add-Remediation -Step "DISM /RestoreHealth" -Result "OK" -DurationSec $r.Duration
        } else {
            $exitTxt = Format-ExitCode $r
            $base = $exitTxt
            $msg  = Add-DISMTriage -Step "DISM /RestoreHealth" -StepStartTime $stepStart -BaseError $base
            Add-Remediation -Step "DISM /RestoreHealth" -Result "FAILED" -DurationSec $r.Duration -ErrorMessage $msg
        }
    }

    # ---- SFC /scannow (cap 15 min) ----
    $runSfc = $needRestore -or $ForceSfc
    if (-not $runSfc) {
        Add-Remediation -Step "sfc /scannow" -Result "SKIPPED" `
            -Detail "DISM reported no damage (use -ForceSfc to run anyway)"
    } elseif (-not (Test-RemainingBudget -NeededSec 180)) {
        Add-Remediation -Step "sfc /scannow" -Result "SKIPPED" -Detail "insufficient remaining script budget (need >3 min)"
    } else {
        $reason = if ($ForceSfc -and -not $needRestore) { "-ForceSfc specified" } else { "DISM detected damage" }
        Write-Log "  Running sfc /scannow ($reason)..."
        $r = Invoke-CapturedCommandWithTimeout -FilePath "$env:SystemRoot\System32\sfc.exe" `
                -ArgumentList @('/scannow') -OutputEncoding "Unicode" `
                -Label "sfc /scannow"
        if ($r.TimedOut) {
            Add-Remediation -Step "sfc /scannow" -Result "FAILED" -DurationSec $r.Duration `
                -ErrorMessage "TIMEOUT after $([int]$r.Duration)s; SFC could not finish - check CBS.log"
        } elseif ($null -eq $r.ExitCode -or "$($r.ExitCode)" -eq "") {
            # v4.10: empty exit code from a 2s 'run' means SFC bailed out
            # without scanning. Honest signal is FAILED, not INFO.
            Add-Remediation -Step "sfc /scannow" -Result "FAILED" -DurationSec $r.Duration `
                -ErrorMessage "no exit code returned after $([int]$r.Duration)s; SFC could not start scan - check CBS.log and component store integrity"
        } else {
            $detail     = "exit $($r.ExitCode)"
            $recognised = $false
            if ($r.Output -match 'did not find any integrity violations')         { $detail = "no integrity violations found"; $recognised = $true }
            elseif ($r.Output -match 'successfully repaired')                       { $detail = "found and repaired corrupt files"; $recognised = $true }
            elseif ($r.Output -match 'found corrupt files but was unable to fix')   { $detail = "found corrupt files - some unreparable; review CBS.log"; $recognised = $true }
            elseif ($r.Output -match 'could not perform the requested operation')   { $detail = "could not perform operation; check CBS.log"; $recognised = $true }

            # v4.19: non-zero SFC exit in under 60 seconds with no recognised
            # output phrase means SFC bailed out before completing a real scan
            # (typically a Trusted Installer access issue or component-store
            # integrity issue). Honest signal is FAILED. A genuine scan takes
            # several minutes; if duration >= 60s we still trust the result
            # and record as INFO so the operator can review.
            if ($r.ExitCode -eq 0) {
                $result = "OK"
            } elseif ((-not $recognised) -and ($r.Duration -lt 60)) {
                $result = "FAILED"
                $detail = "exit $($r.ExitCode) after $([int]$r.Duration)s; SFC did not complete a real scan (real scans take minutes) - check CBS.log and component store integrity"
            } else {
                $result = "INFO"
            }
            Add-Remediation -Step "sfc /scannow" -Result $result -DurationSec $r.Duration -Detail $detail
        }
    }
}

# ----------------------------------------------------------------
#  Force fresh WU detection - always runs
#  V4: optional -InstallApplicable installs whatever was found
# ----------------------------------------------------------------
function Invoke-WUDetection {
    Write-Log "=== Remediation: Force fresh Windows Update detection ==="

    $count = -1
    $usedPSWU = $false

    if ($Script:Environment.HasPSWindowsUpdate) {
        try {
            Import-Module PSWindowsUpdate -ErrorAction Stop
            Write-Log "  Querying available updates via Get-WUList ..."
            $start = Get-Date
            $list = Get-WUList -MicrosoftUpdate -ErrorAction Stop
            $count = if ($list) { @($list).Count } else { 0 }
            $dur = ((Get-Date) - $start).TotalSeconds
            $usedPSWU = $true
            Add-Remediation -Step "Force WU scan (PSWindowsUpdate Get-WUList)" -Result "OK" -DurationSec $dur -Detail "$count update(s) currently applicable"
        } catch {
            Add-Remediation -Step "Force WU scan (PSWindowsUpdate Get-WUList)" -Result "FAILED" -ErrorMessage "$_"
        }
    }

    # If PSWindowsUpdate didn't work, fall back to UsoClient or wuauclt
    if (-not $usedPSWU) {
        $uso = Join-Path $env:SystemRoot "System32\UsoClient.exe"
        if (Test-Path $uso) {
            try {
                $start = Get-Date
                $p = Start-Process -FilePath $uso -ArgumentList "StartScan" -NoNewWindow -Wait -PassThru
                $dur = ((Get-Date) - $start).TotalSeconds
                Add-Remediation -Step "Force WU scan (UsoClient StartScan)" -Result $(if ($p.ExitCode -eq 0) {"OK"} else {"INFO"}) `
                    -DurationSec $dur -Detail "exit $($p.ExitCode) (scan runs in background)"
            } catch {
                Add-Remediation -Step "Force WU scan (UsoClient StartScan)" -Result "FAILED" -ErrorMessage "$_"
            }
        } else {
            $wuauclt = Join-Path $env:SystemRoot "System32\wuauclt.exe"
            if (Test-Path $wuauclt) {
                try {
                    Start-Process -FilePath $wuauclt -ArgumentList @('/detectnow', '/updatenow') -NoNewWindow -Wait | Out-Null
                    Add-Remediation -Step "Force WU scan (wuauclt /detectnow)" -Result "OK" -Detail "legacy fallback"
                } catch {
                    Add-Remediation -Step "Force WU scan (wuauclt /detectnow)" -Result "FAILED" -ErrorMessage "$_"
                }
            } else {
                Add-Remediation -Step "Force WU scan" -Result "FAILED" -Detail "no scan trigger available on this OS"
            }
        }
    }

    # ---- V4: -InstallApplicable opt-in: install whatever WU found ----
    if ($InstallApplicable -and $usedPSWU -and $count -gt 0) {
        Write-Log "  -InstallApplicable specified and $count update(s) found; installing (no reboot) ..."
        try {
            $start = Get-Date
            # IgnoreReboot - install but never trigger reboot. Operator handles reboots.
            $installResult = Install-WindowsUpdate -AcceptAll -IgnoreReboot -MicrosoftUpdate -Confirm:$false -ErrorAction Stop
            $dur = ((Get-Date) - $start).TotalSeconds
            $installCount = if ($installResult) { @($installResult).Count } else { 0 }
            Add-Remediation -Step "Install applicable updates (-InstallApplicable)" -Result "OK" -DurationSec $dur `
                -Detail "$installCount update(s) processed via PSWindowsUpdate; reboot may be required"
        } catch {
            Add-Remediation -Step "Install applicable updates (-InstallApplicable)" -Result "FAILED" -ErrorMessage "$_"
        }
    } elseif ($InstallApplicable -and (-not $usedPSWU)) {
        Add-Remediation -Step "Install applicable updates (-InstallApplicable)" -Result "SKIPPED" `
            -Detail "PSWindowsUpdate not available; install path requires it"
    } elseif ($InstallApplicable -and $count -eq 0) {
        Add-Remediation -Step "Install applicable updates (-InstallApplicable)" -Result "INFO" `
            -Detail "no applicable updates found; nothing to install"
    }
}

# ============================================================
#  PHASE 3 - RE-CHECK
#  V4: WU scan success demotes LCU bookkeeping failures.
# ============================================================
function Invoke-PostRemediationRecheck {
    Write-Log "=== Phase 3: Re-checking previously-failing items ==="
    Write-Log ("  Time budget: {0}" -f (Format-Budget))

    # v4.3: budget gate - reserve at least 90 seconds for the report.
    if (-not (Test-RemainingBudget -NeededSec 90)) {
        Write-Log "  Insufficient remaining script budget for Phase 3 re-check; skipping to report." -Level "WARN"
        $Script:RemediationOutcome = "TRUNCATED"
        $Script:TruncatedSteps.Add("Phase 3 re-check (budget exhausted)") | Out-Null
        return
    }

    $candidates = [ordered]@{}

    $lcu = $Script:PreCheckSnapshot["LCUCheck"]
    if ($lcu -and -not $lcu["WithinThreshold"]) {
        $candidates["LCUCheck"] = { Get-LastCumulativeUpdate }
    }

    $disk = $Script:PreCheckSnapshot["DiskSpace"]
    if ($disk -and ($disk["Status"] -in @("WARN","FAIL","ERROR"))) {
        $candidates["DiskSpace"] = { Test-DiskSpace -MinFreeGB $MinFreeGB }
    }

    $wuS = $Script:PreCheckSnapshot["WUServices"]
    if ($wuS -and -not $wuS["OverallHealthy"]) {
        $candidates["WUServices"] = { Test-WindowsUpdateServices }
    }

    $reb = $Script:PreCheckSnapshot["PendingReboot"]
    if ($reb -and $reb["RebootPending"]) {
        $candidates["PendingReboot"] = { Test-PendingReboot }
    }

    $tsync = $Script:PreCheckSnapshot["TimeSync"]
    if ($tsync -and ($tsync["Status"] -in @("WARN","FAIL","ERROR"))) {
        $candidates["TimeSync"] = { Test-TimeSync -WarnOffsetSeconds $TimeSyncWarnSec -FailOffsetSeconds $TimeSyncFailSec }
    }

    # v4.17: re-check feature update readiness if the initial scan flagged it
    $fur = $Script:PreCheckSnapshot["FeatureUpdateReadiness"]
    if ($fur -and ($fur["Status"] -in @("WARN","FAIL","ERROR"))) {
        $candidates["FeatureUpdateReadiness"] = { Test-FeatureUpdateReadiness }
    }

    if ($candidates.Count -eq 0) {
        Write-Log "  No items needed re-checking; nothing was failing in the initial scan."
        $Script:RemediationOutcome = "REMEDIATED"
        return
    }

    Write-Log ("  Re-running {0} check(s): {1}" -f $candidates.Count, ($candidates.Keys -join ", "))

    $Script:OverallStatus = "PASS"

    foreach ($key in $candidates.Keys) {
        try {
            Write-Log "  -> Re-running $key"
            & $candidates[$key]
        } catch {
            Write-Log "  Re-check '$key' failed: $_" -Level "ERROR"
        }
    }

    # ---- V4: did any WU detection step succeed? If yes the WU stack is functional. ----
    $wuScanSucceeded = @($Script:Remediations | Where-Object {
        $_.Step -match 'Force WU scan' -and $_.Result -eq 'OK'
    }).Count -gt 0

    # Determine final remediation outcome
    $stillFailing = @()
    foreach ($key in $candidates.Keys) {
        $now = $Script:Results[$key]
        $isFailing = switch ($key) {
            "LCUCheck"      { $now -and -not $now["WithinThreshold"] }
            "DiskSpace"     { $now -and ($now["Status"] -in @("WARN","FAIL","ERROR")) }
            "WUServices"    { $now -and -not $now["OverallHealthy"] }
            "PendingReboot" { $now -and $now["RebootPending"] }
            "TimeSync"      { $now -and ($now["Status"] -in @("WARN","FAIL","ERROR")) }
        }

        if ($isFailing) {
            # V4 demote: LCU still failing but WU scan worked AND it's a bookkeeping issue
            # (no LCUs visible to any source) -> treat as deferred, not as failure.
            if ($key -eq "LCUCheck" -and $wuScanSucceeded -and `
                $now -and $now.Contains("BookkeepingHealthy") -and -not $now["BookkeepingHealthy"]) {
                Write-Log "  LCU re-check: still showing 0 LCUs, but WU scan succeeded. Treating as DEFERRED - history will repopulate as installs complete." -Level "INFO"
                continue
            }

            # v4.10 demote: PendingReboot still pending but the source(s) are
            # CBS-only. CBS\RebootPending and CBS\PackagesPending keys only
            # clear on actual reboot - the script never touches them and never
            # should. Marking the run FAIL for a CBS-only pending state
            # penalizes the script for doing the right thing.
            if ($key -eq "PendingReboot" -and $now -and $now["RebootPending"]) {
                $sources = if ($now.Contains("Sources")) { @($now["Sources"]) } else { @() }
                $nonCbs  = @($sources | Where-Object { $_ -notmatch '^CBS' })
                $cbsOnly = ($sources.Count -gt 0) -and ($nonCbs.Count -eq 0)
                if ($cbsOnly) {
                    Write-Log "  PendingReboot re-check: CBS-only pending state ($($sources -join ', ')). Not script-fixable - reboot during patch maintenance window will clear it. Flagging run as REBOOT_REQUIRED." -Level "INFO"
                    $Script:CBSRebootOnly = $true
                    continue
                }
            }

            $stillFailing += $key
        }
    }

    if ($stillFailing.Count -eq 0) {
        if ($Script:CBSRebootOnly) {
            $Script:RemediationOutcome = "REBOOT_REQUIRED"
            Write-Log "  Re-check complete. Remediation succeeded; reboot required to clear CBS pending state." -Level "INFO"
        } else {
            $Script:RemediationOutcome = "REMEDIATED"
            $msg = "Re-check complete. All previously-failing items are now passing"
            if ($wuScanSucceeded) { $msg += " (or deferred to next install cycle - WU stack verified functional)" }
            Write-Log "  $msg."
        }
    } elseif ($stillFailing.Count -lt $candidates.Count) {
        $Script:RemediationOutcome = "PARTIAL"
        Write-Log ("  Re-check complete. Still failing: {0}" -f ($stillFailing -join ", ")) -Level "WARN"
    } else {
        $Script:RemediationOutcome = "FAIL"
        Write-Log ("  Re-check complete. Remediation did not fix: {0}" -f ($stillFailing -join ", ")) -Level "ERROR"
    }
}

# ============================================================
#  REPORT WRITER
# ============================================================
function Write-ComplianceReport {
    param(
        [hashtable]$AllResults,
        [string]   $FinalStatus,
        [string]   $RemediationOutcome
    )

    $hostname  = $env:COMPUTERNAME
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $divider   = "=" * 72
    $subdiv    = "-" * 72

    function Row {
        param([string]$Label, $Value, [string]$Flag = "")
        $flagStr = if ($Flag) { "  [$Flag]" } else { "" }
        Write-Output ("  {0,-28}: {1}{2}" -f $Label, $Value, $flagStr)
    }
    function Header([string]$Title) {
        Write-Output ""
        Write-Output $subdiv
        Write-Output "  $Title"
        Write-Output $subdiv
    }
    function Trunc([string]$s, [int]$max) {
        if ($null -eq $s) { return "" }
        if ($s.Length -le $max) { return $s }
        return $s.Substring(0, $max - 1) + "."
    }

    $headline = switch ($RemediationOutcome) {
        "REMEDIATED"      { "REMEDIATED  (was $FinalStatus pre-remediation)" }
        "PARTIAL"         { "PARTIAL  (was $FinalStatus pre-remediation; some items still failing)" }
        "FAIL"            { "FAIL  (remediation did not resolve all issues)" }
        "TRUNCATED"       { "TRUNCATED  (script hit time budget; partial remediation - see Truncated Steps below)" }
        "REBOOT_REQUIRED" { "REBOOT_REQUIRED  (remediation succeeded; reboot during next maintenance window will clear pending CBS state)" }
        "NONE"            { $FinalStatus }
        default           { $FinalStatus }
    }
    Write-Output $divider
    Write-Output "  WINDOWS PATCH COMPLIANCE + REMEDIATION REPORT"
    Write-Output "  Overall Status : $headline"
    Write-Output "  Host           : $hostname"
    Write-Output "  Report Time    : $timestamp"
    Write-Output $divider

    # ---- Pre-flight Environment ----
    Header "PRE-FLIGHT ENVIRONMENT"
    # v4.12: render $null pre-flight booleans as "Unknown (pre-flight not run)"
    # so a Phase 1 crash doesn't stamp misleading "No" values into the report
    # (e.g. "Is Server: No" on a Server 2019 box because Phase 2 pre-flight
    # never executed). Phase 2 pre-flight functions populate these with real
    # $true/$false values; if they remained $null, pre-flight didn't run.
    Row "Is Server"                $(if ($null -eq $Script:Environment.IsServer)           {"Unknown (pre-flight not run)"} elseif ($Script:Environment.IsServer)           {"Yes"} else {"No"})
    Row "Is Domain Controller"     $(if ($null -eq $Script:Environment.IsDomainController) {"Unknown (pre-flight not run)"} elseif ($Script:Environment.IsDomainController) {"Yes"} else {"No"}) $(if ($Script:Environment.IsDomainController) {"DC - extra care taken"})
    Row "WSUS / PME Managed"       $(if ($null -eq $Script:Environment.WsusManaged)        {"Unknown (pre-flight not run)"} elseif ($Script:Environment.WsusManaged)        {"Yes - GPO preserved"} else {"No"})
    Row "PSWindowsUpdate"          $(if ($Script:Environment.HasPSWindowsUpdate)  {"Available"} else {"Not available - WUA COM fallback in use"})
    Row "WU Registry Backup"       $(if ($Script:Environment.RegBackupPath)       {$Script:Environment.RegBackupPath} else {"(not created - no destructive remediation needed)"})
    if ($Script:Environment.RemediationStartTime) {
        $duration = if ($Script:Environment.RemediationEndTime) {
            "{0:N0} sec" -f (($Script:Environment.RemediationEndTime - $Script:Environment.RemediationStartTime).TotalSeconds)
        } else { "(in progress)" }
        Row "Remediation Duration"     $duration
    }

    # ---- System Information ----
    $sys = $AllResults["SystemInfo"]
    Header "SYSTEM INFORMATION"
    if ($sys) {
        Row "Hostname"        $sys.Hostname
        Row "Domain"          $sys.Domain
        Row "Operating System" $sys.OS_Caption
        Row "OS Version"      $sys.OS_Version
        Row "Build Number"    $sys.OS_BuildNumber
        Row "Architecture"    $sys.Architecture
        Row "Last Boot Time"  $sys.LastBootTime
    } else {
        Write-Output "  [No system info collected]"
    }

    # ---- EOL Status ----
    $eol = $AllResults["EOL"]
    Header "EOL / LIFECYCLE STATUS"
    if ($eol) {
        $effective = if ($eol["IsEOL"]) { "EOL - UNSUPPORTED (no valid ESU)" }
                     elseif ($eol["RawEOL"] -and $eol["ESUOverride"]) { "SUPPORTED via ESU (expires $($eol['ESUExpiryDate']))" }
                     else { "Supported - within standard lifecycle" }
        Row "Product"              $eol["ProductName"]
        Row "Standard End of Life" $eol["EndOfSupportDate"]
        Row "Days Until/Since EOS" $eol["DaysUntilEOL"]
        Row "Past Standard EOS"    $(if ($eol["RawEOL"]) {"Yes"} else {"No"})
        Row "ESU Override Active"  $(if ($eol["ESUOverride"]) {"Yes"} else {"No"})
        Row "Effective Status"     $effective $(if ($eol["IsEOL"]) {"!! ACTION REQUIRED !!"} elseif ($eol["RawEOL"] -and $eol["ESUOverride"]) {"ATTENTION"})
    } else {
        Write-Output "  [EOL check not performed]"
    }

    # ---- ESU License ----
    $esu = $AllResults["ESU"]
    Header "EXTENDED SECURITY UPDATE (ESU) LICENSE"
    if ($esu) {
        Row "ESU-Eligible OS"       $(if ($esu["ESUCapable"])       {"Yes"} else {"No - not an ESU-eligible product"})
        Row "License Found"         $(if ($esu["ESULicenseFound"])  {"Yes"} else {"No"})           $(if ($esu["ESUCapable"] -and -not $esu["ESULicenseFound"]) {"WARNING"})
        Row "License Active"        $(if ($esu["ESULicenseActive"]) {"Yes"} else {"No"})
        Row "License Valid/Current" $(if ($esu["ESULicenseValid"])  {"Yes - not expired"} else {"No"}) $(if ($esu["ESULicenseFound"] -and -not $esu["ESULicenseValid"]) {"EXPIRED"})
        Row "ESU Year"              $esu["ESUYear"]
        Row "ESU Expiry Date"       $esu["ESUExpiryDate"]
        Row "Activation Method"     $esu["ESUActivationMethod"]
        Row "Overrides EOL Flag"    $(if ($esu["OverridesEOL"])     {"Yes - system treated as supported"} else {"No"})
        Row "Summary"               $esu["ESUDetails"]
    } else {
        Write-Output "  [ESU check not performed]"
    }

    # ---- Last Cumulative Update ----
    $lcu = $AllResults["LCUCheck"]
    Header "LAST CUMULATIVE UPDATE  (SSUs excluded)"
    if ($lcu) {
        $lcuFlag = if (-not $lcu["WithinThreshold"]) {"!! PATCH OVERDUE !!"} else {""}
        Row "Last LCU KB"          $lcu["LastLCU_KB"]            $lcuFlag
        Row "Installed Date"       $lcu["LastLCU_Date"]
        Row "Days Since Install"   $lcu["LastLCU_DaysAgo"]
        Row "Stale Threshold"      "$($lcu['ThresholdDays']) days  (cutoff: $($lcu['ThresholdDate']))"
        Row "Within Threshold"     $(if ($lcu["WithinThreshold"]) {"PASS"} else {"FAIL"}) $lcuFlag
        Row "Total LCUs Found"     $lcu["TotalLCUsFound"]
        Row "SSUs Excluded"        "Yes"
        if ($lcu.Contains("DataSource")) {
            Row "Last LCU Source"      $lcu["DataSource"]
            $bkFlag = if (-not $lcu["BookkeepingHealthy"]) { "DEGRADED - SoftwareDistribution rebuild recommended" } else { "" }
            Row "Patch Bookkeeping"    $(if ($lcu["BookkeepingHealthy"]) {"HEALTHY"} else {"DEGRADED"}) $bkFlag
            if (-not $lcu["BookkeepingHealthy"]) {
                # v4.12: -1 means the probe timed out / errored, not 'returned 0'
                $hfDispRow  = if ($lcu["HotFixCount"] -lt 0) { "Unknown (probe timed out)" } else { $lcu["HotFixCount"] }
                $wmiDispRow = if ($lcu["WMICount"]    -lt 0) { "Unknown (probe timed out)" } else { $lcu["WMICount"]    }
                Row "  Get-HotFix count"   $hfDispRow
                Row "  WMI count"          $wmiDispRow
            }
        }
    } else {
        Write-Output "  [LCU check not performed]"
    }

    # ---- Disk Space ----
    $disk = $AllResults["DiskSpace"]
    Header "SYSTEM DISK FREE SPACE"
    if ($disk) {
        $diskFlag = switch ($disk["Status"]) {
            "FAIL"  { "!! INSUFFICIENT DISK SPACE !!" }
            "WARN"  { "LOW - MONITOR CLOSELY" }
            "ERROR" { "CHECK ERROR - SEE LOG" }
            default { "" }
        }
        Row "System Drive"      $disk["DriveLetter"]
        Row "Total Capacity"    "$($disk['TotalGB']) GB"
        Row "Used Space"        "$($disk['UsedGB']) GB"
        Row "Free Space"        "$($disk['FreeGB']) GB"          $diskFlag
        Row "Free Percent"      "$($disk['PercentFree'])%"
        Row "Minimum Required"  "$($disk['MinRequiredGB']) GB"
        Row "Meets Minimum"     $(if ($disk["MeetsMinimum"]) {"Yes"} else {"No"}) $diskFlag
        Row "Status"            $disk["Status"]                  $diskFlag
    } else {
        Write-Output "  [Disk space check not performed]"
    }

    # ---- Windows Update Services ----
    $wusvc = $AllResults["WUServices"]
    Header "WINDOWS UPDATE SERVICES HEALTH"
    if ($wusvc) {
        Write-Output ("  {0,-22} {1,-38} {2,-10} {3,-12} {4}" -f "Service Name","Display Name","Status","Start Type","Note")
        Write-Output ("  " + ("-" * 68))
        foreach ($svc in $wusvc["Services"]) {
            $mandLabel = if ($svc["Mandatory"]) { "[Required]" } else { "[Advisory]" }
            $flagStr   = if (-not $svc["Healthy"]) { if ($svc["Mandatory"]) {" !! ACTION REQUIRED !!"} else {" [ATTENTION]"} } else { "" }
            Write-Output ("  {0,-22} {1,-38} {2,-10} {3,-12} {4}{5}" -f
                $svc["ServiceName"],
                ($svc["DisplayName"].Substring(0, [Math]::Min(36, $svc["DisplayName"].Length))),
                $svc["Status"], $svc["StartType"], $mandLabel, $flagStr)
        }
        Write-Output ""
        Row "All Required Services OK"  $(if ($wusvc["AllMandatoryOK"])     {"Yes"} else {"No - see table"})        $(if (-not $wusvc["AllMandatoryOK"])    {"!! ACTION REQUIRED !!"})
        Row "WUA COM Reachable"         $(if ($wusvc["WUAComReachable"])    {"Yes"} else {"No"})                    $(if (-not $wusvc["WUAComReachable"])   {"WARNING"})
        Row "WUA COM Details"           $wusvc["WUAComNote"]
        Row "Overall Service Health"    $(if ($wusvc["OverallHealthy"])     {"HEALTHY"} else {"DEGRADED"})           $(if (-not $wusvc["OverallHealthy"])    {"WARNING"})
    } else {
        Write-Output "  [Windows Update services check not performed]"
    }

    # ---- Pending Reboot ----
    $reboot = $AllResults["PendingReboot"]
    Header "PENDING REBOOT STATUS"
    if ($reboot) {
        $rebootFlag = if ($reboot["RebootPending"]) { "!! REBOOT REQUIRED BEFORE PATCHING !!" } else { "" }
        Row "Serious Reboot Pending"  $(if ($reboot["RebootPending"])    {"YES"} else {"No"}) $rebootFlag
        Row "CBS Pending"             $(if ($reboot["CBSPending"])       {"Yes"} else {"No"})
        Row "Windows Update Pending"  $(if ($reboot["WUPending"])        {"Yes"} else {"No"})
        Row "SCCM Pending"            $(if ($reboot["SCCMPending"])      {"Yes"} else {"No"})
        Row "Domain Join Pending"     $(if ($reboot["DomainJoinPending"]){"Yes"} else {"No"})
        if ($reboot["Sources"] -and $reboot["Sources"].Count -gt 0) {
            Row "Pending Sources"     ($reboot["Sources"] -join " | ") $rebootFlag
        }
        Row "Recommended Action"      $reboot["RecommendedAction"]    $rebootFlag
        Row "File Rename Ops (PFR)"   $(if ($reboot["PFRPending"]) { $reboot["PFRSources"] -join " | " } else { "None" })
        Row "PFR Note"                "PFR entries are normal OS behaviour. Remediation is paused until cleared by reboot."
    } else {
        Write-Output "  [Pending reboot check not performed]"
    }

    # ---- Uptime ----
    $uptime = $AllResults["Uptime"]
    Header "SYSTEM UPTIME"
    if ($uptime) {
        $uptimeFlag = switch ($uptime["Status"]) {
            "WARN"  { if ($uptime["UptimeDays"] -gt $uptime["FailThreshold"]) {"!! CRITICAL - REBOOT STRONGLY RECOMMENDED !!"} else {"ELEVATED - REBOOT RECOMMENDED"} }
            "ERROR" { "CHECK ERROR - SEE LOG" }
            default { "" }
        }
        Row "Last Boot Time"      $uptime["LastBootTime"]
        Row "Current Uptime"      $uptime["UptimeFormatted"] $uptimeFlag
        Row "Uptime (Days)"       $uptime["UptimeDays"]      $uptimeFlag
        Row "Warning Threshold"   "$($uptime['WarnThreshold']) days"
        Row "Critical Threshold"  "$($uptime['FailThreshold']) days"
        Row "Status"              $uptime["Status"]          $uptimeFlag
        Row "Note"                $uptime["Note"]
    } else {
        Write-Output "  [Uptime check not performed]"
    }

    # ---- Time Sync ----
    $tsync = $AllResults["TimeSync"]
    Header "TIME SYNCHRONISATION"
    if ($tsync) {
        $tsyncFlag = switch ($tsync["Status"]) {
            "FAIL"  { "!! CLOCK SKEW EXCEEDS KERBEROS LIMIT - ACTION REQUIRED !!" }
            "WARN"  { "CLOCK DRIFT DETECTED - MONITOR" }
            "ERROR" { "CHECK ERROR - SEE LOG" }
            default { "" }
        }
        Row "W32Time Service"      $(if ($tsync["W32tmServiceRunning"]) {"Running"} else {"Not Running"}) $(if (-not $tsync["W32tmServiceRunning"]) {"WARNING"})
        Row "NTP Source"           $tsync["NTPSource"]
        Row "Stratum"              $tsync["Stratum"]
        Row "Last Successful Sync" $tsync["LastSyncTime"]
        Row "Clock Offset"         $tsync["OffsetFormatted"]    $tsyncFlag
        Row "Warning Threshold"    $tsync["WarnThreshold"]
        Row "Fail Threshold"       $tsync["FailThreshold"]
        Row "Status"               $tsync["Status"]             $tsyncFlag
        Row "Note"                 $tsync["Note"]               $tsyncFlag
    } else {
        Write-Output "  [Time sync check not performed]"
    }

    # ---- TPM ----
    $tpm = $AllResults["TPM"]
    Header "TPM VERSION CHECK (Windows 10 Upgrade Readiness)"
    if ($tpm) {
        if (-not $tpm["Applicable"]) {
            Write-Output "  Not applicable - $($tpm['Note'])"
        } else {
            $tpmFlag = switch ($tpm["Status"]) {
                "WARN"  { "!! TPM PREVENTING WINDOWS 11 UPGRADE !!" }
                "ERROR" { "CHECK ERROR - SEE LOG" }
                default { "" }
            }
            Row "TPM Present"          $(if ($tpm["TPMPresent"]) {"Yes"} else {"No - not detected"})  $(if (-not $tpm["TPMPresent"]) {$tpmFlag})
            Row "TPM Version"          $tpm["TPMVersion"]                                              $tpmFlag
            Row "Spec Version (Full)"  $tpm["SpecVersion"]
            Row "Manufacturer"         $tpm["ManufacturerName"]
            Row "TPM Enabled"          $(if ($tpm["Enabled"])   {"Yes"} else {"No"})
            Row "TPM Activated"        $(if ($tpm["Activated"]) {"Yes"} else {"No"})
            Row "Meets Win11 Req"      $(if ($tpm["MeetsWin11Req"]) {"Yes - TPM 2.0 present"} else {"NO - upgrade blocked"}) $tpmFlag
            Row "Detection Method"     $tpm["DetectionMethod"]
            Row "Status"               $tpm["Status"]                                                  $tpmFlag
            Row "Note"                 $tpm["Note"]                                                    $tpmFlag
        }
    } else {
        Write-Output "  [TPM check not performed]"
    }

    # ---- Remediations Applied ----
    # ---- Feature Update Readiness (v4.17) ----
    $fur = $AllResults["FeatureUpdateReadiness"]
    Header "FEATURE UPDATE READINESS (next-version offer eligibility)"
    if ($fur -and $fur["Applicable"]) {
        Row "Current Release"        ("{0} (build {1})" -f $fur["CurrentReleaseVersion"], $fur["CurrentBuild"])

        $trv = if ($fur["TargetReleaseVersion"]) { $fur["TargetReleaseVersion"] } else { "(not set)" }
        Row "TargetReleaseVersion pin"  $trv

        $pv  = if ($fur["ProductVersion"]) { $fur["ProductVersion"] } else { "(not set)" }
        Row "ProductVersion pin"        $pv

        $df  = if ($fur["DeferFeatureUpdates"]) { "$($fur['DeferFeatureUpdates'])  (period: $($fur['DeferFeatureUpdatesDays']) days)" } else { "(not set)" }
        Row "DeferFeatureUpdates"       $df

        $at  = if ($null -eq $fur["AllowTelemetry"] -or $fur["AllowTelemetry"] -lt 0) { "(not set by policy - default)" } elseif ($fur["AllowTelemetry"] -eq 0) { "0 (Off)  [BLOCKS feature updates]" } else { "$($fur['AllowTelemetry'])" }
        Row "AllowTelemetry"            $at

        $ws  = if ($null -eq $fur["WSUSManaged"]) { "Unknown" } elseif ($fur["WSUSManaged"]) { "Yes  [upstream approval gates feature updates]" } else { "No" }
        Row "WSUS / PME managed"        $ws

        $cpu = if ($null -eq $fur["CPUSupportsSSE42"]) { "Unknown" } elseif ($fur["CPUSupportsSSE42"]) { "Yes" } else { "No  [BLOCKS 24H2]" }
        Row "CPU SSE4.2 support"        $cpu
        if ($fur["CPUName"]) { Row "  CPU model"           $fur["CPUName"] }

        if ($null -ne $fur["DiskFreeGB"]) {
            $diskOk = if ($fur["DiskSufficientForFeatureUpd"]) { "OK" } else { "INSUFFICIENT" }
            Row "Disk free vs 64 GB band"   ("{0} GB free / 64 GB needed  [{1}]" -f $fur["DiskFreeGB"], $diskOk)
        }

        if (@($fur["StaleArtifacts"]).Count -gt 0) {
            Row "Stale upgrade artifacts"  ("{0} present" -f @($fur["StaleArtifacts"]).Count)
            foreach ($a in $fur["StaleArtifacts"]) {
                $sz = if ($a["SizeGB"]) { "$($a['SizeGB']) GB" } else { "size unknown" }
                Row "  $($a['Name'])"      ("age {0} days, {1}" -f $a["AgeDays"], $sz)
            }
        } else {
            Row "Stale upgrade artifacts"  "(none)"
        }

        if (@($fur["SafeguardSignals"]).Count -gt 0) {
            Row "Safeguard signals"       ("{0} found (registry heuristic)" -f @($fur["SafeguardSignals"]).Count)
            foreach ($s in $fur["SafeguardSignals"]) { Row "  $s" "" }
        } else {
            Row "Safeguard signals"       "(none from registry heuristic)"
        }

        Row "Overall readiness"         $fur["Status"]
        if (@($fur["BlockingReasons"]).Count -gt 0) {
            Write-Output ""
            Write-Output "  Blocking reasons:"
            foreach ($b in $fur["BlockingReasons"]) {
                Write-Output ("    - {0}" -f $b)
            }
        }
    } else {
        Write-Output "  Not applicable - skipped (Server SKU, already on 24H2+, or OS detection failed)."
    }


    Header "REMEDIATIONS APPLIED"
    if ($Script:Remediations.Count -eq 0) {
        Write-Output "  (none recorded)"
    } else {
        Write-Output ("  {0,-8} {1,-9} {2,-9} {3,-46} {4}" -f "Time","Result","Duration","Step","Detail/Error")
        Write-Output ("  " + ("-" * 100))
        foreach ($r in $Script:Remediations) {
            $note = if ($r.Error) { "ERR: $($r.Error)" } else { $r.Detail }
            $stepStr = Trunc $r.Step 46
            $durStr = if ($r.Duration -and $r.Duration -gt 0) {
                if ($r.Duration -ge 60) { "{0:N0}m{1:N0}s" -f [math]::Floor($r.Duration/60), ($r.Duration%60) }
                else                     { "{0:N0}s" -f $r.Duration }
            } else { "-" }
            Write-Output ("  {0,-8} {1,-9} {2,-9} {3,-46} {4}" -f $r.Time, $r.Result, $durStr, $stepStr, $note)
        }
        # v4.1 fix re-applied: @() forces array so .Count works under StrictMode
        # even when Where-Object returns 0 or 1 results.
        $okCt   = @($Script:Remediations | Where-Object { $_.Result -eq 'OK' }).Count
        $failCt = @($Script:Remediations | Where-Object { $_.Result -eq 'FAILED' }).Count
        $skipCt = @($Script:Remediations | Where-Object { $_.Result -eq 'SKIPPED' }).Count
        $infoCt = @($Script:Remediations | Where-Object { $_.Result -eq 'INFO' }).Count
        Write-Output ""
        Row "Total Steps"      $Script:Remediations.Count
        Row "Successful"       $okCt
        Row "Failed"           $failCt $(if ($failCt -gt 0) {"REVIEW LOG"})
        Row "Skipped (gated/expected)" $skipCt
        Row "Informational"    $infoCt
    }

    # ---- Before / After comparison (V4: column trim) ----
    Header "BEFORE / AFTER COMPARISON"
    if ($Script:PreCheckSnapshot.Count -eq 0) {
        Write-Output "  No before-snapshot captured."
    } else {
        Write-Output ("  {0,-18} {1,-30} {2,-30}" -f "Check","Before","After")
        Write-Output ("  " + ("-" * 80))

        function Get-StatusOf {
            param($Result, [string]$Key)
            if ($null -eq $Result) { return "(not run)" }
            switch ($Key) {
                "LCUCheck"      {
                    if ($Result["WithinThreshold"]) { return "OK" }
                    elseif ($Result["LastLCU_DaysAgo"] -is [int] -or $Result["LastLCU_DaysAgo"] -match '^\d+$') {
                        return "OVERDUE ($($Result['LastLCU_DaysAgo'])d)"
                    } else { return "OVERDUE" }
                }
                "DiskSpace"     { return ("{0} ({1}GB free)" -f $Result["Status"], $Result["FreeGB"]) }
                "WUServices"    { return $(if ($Result["OverallHealthy"]) {"HEALTHY"} else {"DEGRADED"}) }
                "PendingReboot" { return $(if ($Result["RebootPending"])  {"PENDING"} else {"None"}) }
                "TimeSync"      { return ("{0} ({1})" -f $Result["Status"], $Result["OffsetFormatted"]) }
                default         { return "(n/a)" }
            }
        }

        foreach ($key in @("LCUCheck","DiskSpace","WUServices","PendingReboot","TimeSync")) {
            $before = $Script:PreCheckSnapshot[$key]
            $after  = $AllResults[$key]
            if ($null -eq $before) { continue }
            $b = Trunc (Get-StatusOf $before $key) 30
            $a = Trunc (Get-StatusOf $after  $key) 30
            Write-Output ("  {0,-18} {1,-30} {2,-30}" -f $key, $b, $a)
        }
    }

    # ---- DISM Log Error Summary (v4.9 + v4.10 always-on) ----
    if ($Script:DISMAttempted) {
        Header "DISM LOG ERROR SUMMARY"
        if ($Script:DISMFindings -and $Script:DISMFindings.Count -gt 0) {
            Write-Output "  HRESULTs extracted from C:\Windows\Logs\DISM\dism.log during this run."
            Write-Output "  Most informative single signal for why a DISM step failed."
            Write-Output ""
            Write-Output ("  {0,-26} {1,-12} {2}" -f "Step","HRESULT","Meaning")
            Write-Output ("  " + ("-" * 100))
            foreach ($f in $Script:DISMFindings) {
                $stepStr = Trunc $f.Step 26
                $meanStr = Trunc $f.Meaning 60
                Write-Output ("  {0,-26} {1,-12} {2}" -f $stepStr, $f.HResult, $meanStr)
            }
            Write-Output ""
            Write-Output "  For the full error text, search dism.log near the timestamp of the failed step."
        } else {
            $logPath = "$env:WINDIR\Logs\DISM\dism.log"
            if (-not (Test-Path $logPath)) {
                Write-Output "  No HRESULTs available: $logPath does not exist on this host."
                Write-Output "  DISM may not have written any log this session, or the log was cleared."
            } else {
                $sz = try { "{0:N1} MB" -f ((Get-Item $logPath).Length / 1MB) } catch { "?" }
                Write-Output "  No HRESULTs found in dism.log within the timeframe of failed DISM steps."
                Write-Output ("  Log file: {0} ({1})" -f $logPath, $sz)
                Write-Output "  This usually means DISM exited before writing an Error-level row -"
                Write-Output "  consistent with the 'no exit code returned' pattern. Pull the log"
                Write-Output "  manually and look for 'Failed' / '0x' patterns near the step timestamps."
            }
        }
    }

    # ---- Execution Log ----
    Header "EXECUTION LOG"
    foreach ($line in $Script:Log) { Write-Output "  $line" }

    # ---- Footer ----
    Write-Output ""
    Write-Output $divider
    Write-Output ("  Script  : {0}" -f $Script:ScriptName)
    Write-Output "  Phase 1/2 Status : $FinalStatus"
    Write-Output "  Phase 3 Outcome  : $RemediationOutcome"
    if ($Script:TruncatedSteps -and $Script:TruncatedSteps.Count -gt 0) {
        Write-Output ""
        Write-Output "  TRUNCATED STEPS (hit per-step or per-script time budget):"
        foreach ($t in $Script:TruncatedSteps) {
            Write-Output ("    - {0}" -f $t)
        }
    }
    if (Get-Command Format-Budget -ErrorAction SilentlyContinue) {
        Write-Output ("  Wall-clock Budget: {0}" -f (Format-Budget))
    }
    Write-Output "  Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Output $divider
    Write-Output ""
}

# ============================================================
#  MAIN EXECUTION
# ============================================================
Write-Log "############################################################"
Write-Log (" Remediate-PatchCompliance - Starting  [{0}]" -f $Script:Version)
Write-Log " Combined Check + Gated Remediation"
Write-Log "############################################################"
Write-Log (" Time budget: {0} minutes (deadline {1} UTC)" -f $MaxRuntimeMinutes, $Script:DeadlineUtc.ToString('yyyy-MM-dd HH:mm:ss'))
Write-Log " (configurable via -MaxRuntimeMinutes; default 120 matches N-central's 2-hour wall - no headroom for report writer)"
Write-Log "############################################################"

Test-SupportedOS

# Mirror everything to a transcript file (insurance against N-central
# output buffer truncation).
$transcriptPath = "C:\Windows\Temp\Remediate-PatchCompliance-$env:COMPUTERNAME-$(Get-Date -Format yyyyMMdd-HHmmss).log"
try {
    Start-Transcript -Path $transcriptPath -Force -ErrorAction Stop | Out-Null
    $Script:Environment.TranscriptPath = $transcriptPath
    Write-Log "  Transcript started: $transcriptPath"
} catch {
    Write-Log "  Could not start transcript: $_" -Level "WARN"
}

# v4.3: helper that wraps a remediation call so it self-skips when the
# script's wall-clock budget is exhausted. We still let cheap remediations
# (services, time sync) run if we have only a minute or two left.
function Invoke-IfBudget {
    param(
        [Parameter(Mandatory)] [string]$Label,
        [Parameter(Mandatory)] [scriptblock]$Block,
        [int]$NeededSec = 30
    )
    if (-not (Test-RemainingBudget -NeededSec $NeededSec)) {
        Write-Log ("  [budget] skipping {0}: only {1}s remaining" -f $Label, (Get-RemainingBudgetSec)) -Level "WARN"
        Add-Remediation -Step $Label -Result "SKIPPED" -Detail "remaining script budget under ${NeededSec}s"
        $Script:TruncatedSteps.Add("$Label (budget gate)") | Out-Null
        return
    }
    & $Block
}

try {
    # -----------------------------------------------------------------
    # PHASE 1 - CHECK
    # -----------------------------------------------------------------
    Write-Log "===== PHASE 1: CHECK ====="
    $sysInfo      = Get-SystemInfo
    $eolInfo      = Test-WindowsEOL -BuildNumber $sysInfo.OS_BuildNumber
    $lcuInfo      = Get-LastCumulativeUpdate
    $diskInfo     = Test-DiskSpace -MinFreeGB $MinFreeGB
    $wuSvcInfo    = Test-WindowsUpdateServices
    $rebootInfo   = Test-PendingReboot
    $uptimeInfo   = Test-SystemUptime -WarnDays $UptimeWarnDays -FailDays $UptimeFailDays
    $timeSyncInfo = Test-TimeSync -WarnOffsetSeconds $TimeSyncWarnSec -FailOffsetSeconds $TimeSyncFailSec
    $tpmInfo      = Test-TPMVersion
    $furInfo      = Test-FeatureUpdateReadiness

    foreach ($k in $Script:Results.Keys) {
        $v = $Script:Results[$k]
        if ($v -is [System.Collections.IDictionary] -or $v -is [hashtable] -or $v -is [System.Collections.Specialized.OrderedDictionary]) {
            $clone = [ordered]@{}
            foreach ($kk in $v.Keys) { $clone[$kk] = $v[$kk] }
            $Script:PreCheckSnapshot[$k] = $clone
        } else {
            $Script:PreCheckSnapshot[$k] = $v
        }
    }
    Write-Log ("  Phase-1 status: {0}    Budget: {1}" -f $Script:OverallStatus, (Format-Budget))

    # -----------------------------------------------------------------
    # PHASE 2 - REMEDIATE (gated; each function checks its own gate)
    # -----------------------------------------------------------------
    Write-Log "===== PHASE 2: REMEDIATE ====="
    $Script:Environment.RemediationStartTime = Get-Date

    Test-IsServer
    Test-IsWsusManaged

    # PSWindowsUpdate install can take 60-120s on a fresh box hitting PSGallery
    # for the first time. Gate it so we don't burn the budget if we're already
    # tight (we have working WUA COM fallbacks).
    Invoke-IfBudget -Label "Pre-flight: install PSWindowsUpdate" -NeededSec 180 -Block { Install-PSWindowsUpdateIfMissing }

    # Note: Backup-WindowsUpdateRegistry is no longer called unconditionally.
    # It runs lazily via Ensure-WURegistryBackup the first time a destructive
    # remediation needs it.

    $eolAndUnsupported = ($Script:Results["EOL"] -and $Script:Results["EOL"]["IsEOL"])

    # Cheap remediations - small per-step budget needed.
    Invoke-IfBudget -Label "Disk cleanup"      -NeededSec 60   -Block { Invoke-DiskCleanupRemediation }
    Invoke-IfBudget -Label "Service health"    -NeededSec 30   -Block { Invoke-ServicesRemediation }

    # WU Component Reset can take 1-3 minutes on a healthy box, longer on a broken one.
    Invoke-IfBudget -Label "WU Component Reset" -NeededSec 240 -Block { Invoke-WUComponentReset }

    Invoke-IfBudget -Label "Pending reboot remediation" -NeededSec 30 -Block { Invoke-PendingRebootRemediation }
    Invoke-IfBudget -Label "Time sync remediation"      -NeededSec 30 -Block { Invoke-TimeSyncRemediation }

    # v4.17: feature update readiness remediation. Cheap on most hosts
    # (delete a folder + maybe edit a couple of registry values).
    Invoke-IfBudget -Label "Feature update readiness remediation" -NeededSec 60 -Block { Invoke-FeatureUpdateReadinessRemediation }

    # Component store repair has its OWN per-step deadline-aware logic and
    # internal budget gates - we still gate the whole function for safety.
    Invoke-IfBudget -Label "Component store repair (DISM + SFC)" -NeededSec 300 -Block { Invoke-ComponentStoreRepair }

    if ($eolAndUnsupported) {
        Write-Log "  System is EOL with no valid ESU - skipping WU detection trigger."
        Add-Remediation -Step "Force WU scan" -Result "SKIPPED" -Detail "OS is EOL without valid ESU; no patches available from MS"
    } else {
        Invoke-IfBudget -Label "Force WU detection" -NeededSec 60 -Block { Invoke-WUDetection }
    }

    $Script:Environment.RemediationEndTime = Get-Date
    $duration = ($Script:Environment.RemediationEndTime - $Script:Environment.RemediationStartTime).TotalSeconds
    Write-Log ("  Phase-2 complete. Remediation steps: {0}, duration: {1:N0}s    Budget: {2}" -f $Script:Remediations.Count, $duration, (Format-Budget))

    # -----------------------------------------------------------------
    # PHASE 3 - RE-CHECK
    # -----------------------------------------------------------------
    if ($SkipRecheck) {
        Write-Log "===== PHASE 3: RE-CHECK SKIPPED (-SkipRecheck) ====="
        $Script:RemediationOutcome = "NONE"
    } else {
        Write-Log "===== PHASE 3: RE-CHECK ====="
        Invoke-PostRemediationRecheck
    }
}
catch {
    Write-Log "Unhandled script error: $_" -Level "ERROR"
    Set-Status "FAIL"
}
finally {
    # v4.7: if any step was truncated by a per-step deadline, demote a
    # REMEDIATED outcome to PARTIAL. The recheck phase only re-runs items
    # that failed in Phase 1; it doesn't see Phase 2 step failures that
    # killed downstream remediation work. PARTIAL is the honest signal.
    if ($Script:TruncatedSteps -and $Script:TruncatedSteps.Count -gt 0) {
        if ($Script:RemediationOutcome -eq "REMEDIATED") {
            Write-Log ("  Demoting outcome REMEDIATED -> PARTIAL: {0} step(s) truncated by per-step deadline ({1})" -f `
                $Script:TruncatedSteps.Count, ($Script:TruncatedSteps -join ", ")) -Level "WARN"
            $Script:RemediationOutcome = "PARTIAL"
        }
    }

    # v4.3: report and transcript-stop are guaranteed even on unhandled error
    # or budget exhaustion mid-Phase-2.
    Write-Log "############################################################"
    Write-Log " Final  Status      : $Script:OverallStatus"
    Write-Log " Remediation Outcome: $Script:RemediationOutcome"
    if ($Script:TruncatedSteps -and $Script:TruncatedSteps.Count -gt 0) {
        Write-Log (" Truncated steps    : {0}" -f ($Script:TruncatedSteps -join ", ")) -Level "WARN"
    }
    Write-Log (" Wall-clock budget  : {0}" -f (Format-Budget))
    Write-Log "############################################################"

    try {
        Write-ComplianceReport -AllResults $Script:Results -FinalStatus $Script:OverallStatus -RemediationOutcome $Script:RemediationOutcome
    } catch {
        Write-Host "[ERROR] Report generation failed: $_"
    }

    try {
        Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
        Write-Host ""
        Write-Host "Full transcript saved to: $($Script:Environment.TranscriptPath)"
    } catch {}
}

# Exit code mapping
$exit = 1
switch ($Script:OverallStatus) {
    "PASS" { $exit = 0 }
    "WARN" { $exit = 1 }
    "FAIL" { $exit = 2 }
}
if ($Script:RemediationOutcome -eq "REMEDIATED")      { $exit = 0 }
if ($Script:RemediationOutcome -eq "PARTIAL")         { $exit = 1 }
if ($Script:RemediationOutcome -eq "FAIL")            { $exit = 2 }
if ($Script:RemediationOutcome -eq "TRUNCATED")       { $exit = 1 }
if ($Script:RemediationOutcome -eq "REBOOT_REQUIRED") { $exit = 0 }  # v4.10: success - just needs reboot

exit $exit
