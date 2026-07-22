<#
.SYNOPSIS
    Captures N-central / PME third-party patching logs from the past 30 days and
    reports every 3rd-party patch installation with its result and, on failure,
    the reason.

.DESCRIPTION
    Read-only report script for N-central managed Windows devices. It does four
    things:

      1. LOCATES the patch log sources on the device:
           - PME (Patch Management Engine) logs:
               C:\ProgramData\MspPlatform\<component>\log        (current)
               C:\ProgramData\SolarWinds MSP\<component>\log     (legacy)
           - N-central Windows Agent patch-related logs:
               C:\Program Files (x86)\N-able Technologies\Windows Agent\log
         and reports PME / agent service health for context.

      2. CAPTURES every patch log file written in the last -DaysBack days into
         a support-ready bundle:  <CaptureRoot>\NCentral-3PP-Logs_<HOST>_<stamp>.zip
         (evidence CSVs from steps 3-5 are added to the same bundle).

      3. PARSES third-party installation results from three independent sources
         (whichever exist on the device - all are best-effort):
           - Windows Update Agent history (COM QueryHistory) - N-central
             published 3rd-party updates land here with a ResultCode + HResult
           - PME log files - install/deploy lines with results and exit codes
           - Event logs - WindowsUpdateClient 19/20 and MsiInstaller
             11707/11708/1033 events for non-Microsoft products

      4. PRINTS a formatted summary table (newest first) showing each
         3rd-party installation, whether it SUCCEEDED or FAILED, and a
         decoded failure reason (MSI exit codes / WU HRESULTs mapped to
         plain English), plus a totals block. Full detail is exported to CSV.

    Makes NO changes to patching configuration. Only writes the capture
    bundle / CSV under -CaptureRoot.

.PARAMETER DaysBack
    How many days of history to report and capture. Default 30.

.PARAMETER CaptureRoot
    Folder where the log bundle zip / CSV are written. Default C:\Temp
    (created if missing).

.PARAMETER NoCapture
    Report only - skip copying/zipping the raw log files.

.PARAMETER NoZip
    Leave the captured logs as a folder instead of compressing to a zip.

.PARAMETER NoCsv
    Skip the CSV export of the parsed results.

.PARAMETER IncludeMicrosoft
    Also list Microsoft/Windows updates in the report (default: 3rd-party
    only; Microsoft entries are counted but suppressed).

.PARAMETER MaxEvidenceLines
    Cap on matched PME log evidence lines shown in the output. Default 250.

.PARAMETER EngineErrorThreshold
    Number of in-window 3PP engine errors (catalog download / unzip / cache
    failures) that marks the engine UNHEALTHY when no 3rd-party installs
    happened in the window. Default 25.

.NOTES
    Get-NCentralThirdPartyPatchReport_V1.1.ps1
    V1.1 - 2026-07-22 - tuned against live PME logs from the fleet:
        - PME log timestamps are prefixed with a [thread] token; V1.0 missed
          them. Parser now handles '[1] 2026-07-22 17:00:29,275 DEBUG ...'.
        - Native ThirdPartyPatch.log install parsing: pairs each
          'Launching Command: <installer>' with its following
          '(Process) Exit code: N' per thread, decodes the exit code, and
          reports the product (installer filename mapped to a friendly name).
          Failed uninstall steps of an upgrade are reported too.
        - NEW: 3PP ENGINE HEALTH check. Counts in-window engine errors
          (catalog download/caching failures, unzip failures, cache service
          unreachable) and reports last catalog download OK / last install
          attempt / last detection scan result. A device whose 3PP engine is
          broken silently installs NOTHING - it now exits 2 so it gets
          flagged, instead of looking 'clean'.
        - PME self-install logs (PME_Install_*, *_install.log) are captured
          but no longer parsed - their 'Successfully installed the file'
          chatter is about PME's own components, not patches.
    V1.0 - 2026-07-22 - initial release

    Deploy via N-central (runs as SYSTEM). Windows PowerShell 5.1 compatible.
    Typical runtime 1-4 minutes; set the N-central script/task timeout to at
    least 10 minutes for devices with large PME logs.

    Exit codes (for N-central):
        0 = success: no 3rd-party install failures AND 3PP engine healthy
        1 = error:   unexpected script failure
        2 = one or more 3rd-party installs FAILED in the window, OR the 3PP
            engine is unhealthy (installing nothing) - flag / investigate

    Read-only against patching state. Writes only the capture bundle and CSV
    under -CaptureRoot. Run as SYSTEM / Administrator so all log folders and
    event logs are readable.
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 365)]
    [int]$DaysBack = 30,

    [string]$CaptureRoot = 'C:\Temp',

    [switch]$NoCapture,
    [switch]$NoZip,
    [switch]$NoCsv,
    [switch]$IncludeMicrosoft,

    [ValidateRange(10, 5000)]
    [int]$MaxEvidenceLines = 250,

    [ValidateRange(1, 100000)]
    [int]$EngineErrorThreshold = 25
)

$ErrorActionPreference = 'Stop'

# ---- Globals ----------------------------------------------------------------
$script:Cutoff    = (Get-Date).AddDays(-$DaysBack)
$script:Stamp     = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:Rows      = New-Object System.Collections.Generic.List[object]   # parsed install results
$script:Evidence  = New-Object System.Collections.Generic.List[object]   # raw PME log evidence lines
$script:Captured  = New-Object System.Collections.Generic.List[object]   # files copied to the bundle
$script:SourceNotes = New-Object System.Collections.Generic.List[string] # which sources worked/missing
$subdiv = '-' * 78
$divide = '=' * 78

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    Write-Output ('[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message)
}

function Trunc {
    param([string]$s, [int]$max)
    if ($null -eq $s) { return '' }
    $s = $s -replace '\s+', ' '
    if ($s.Length -le $max) { return $s }
    return $s.Substring(0, $max - 1) + '.'
}

# ---- Failure-reason decoding ------------------------------------------------
# Keys are UPPERCASE 8-digit hex (no 0x) for HRESULTs, or plain decimal strings
# for MSI/installer exit codes.
$script:ReasonMap = @{
    # MSI / installer exit codes
    '0'    = 'Success'
    '1'    = 'General failure (installer exit code 1) - check the application installer log'
    '2'    = 'Installer exit code 2 - file not found / prerequisite missing'
    '5'    = 'Access denied (exit code 5)'
    '1602' = 'User cancelled the installation (1602)'
    '1603' = 'Fatal error during installation (MSI 1603) - conflicting install, in-use files, or app-specific failure'
    '1618' = 'Another installation was already in progress (MSI 1618) - retry after it completes'
    '1619' = 'Install package could not be opened (MSI 1619) - corrupt/incomplete download'
    '1620' = 'Install package invalid (MSI 1620) - corrupt download or blocked by AV'
    '1625' = 'Installation blocked by system policy (MSI 1625)'
    '1633' = 'Platform not supported by this package (MSI 1633) - wrong architecture'
    '1638' = 'Another version of the product is already installed (MSI 1638)'
    '1641' = 'Success - installer initiated a reboot (1641)'
    '3010' = 'Success - reboot required to complete (3010)'
    # Windows Update Agent HRESULTs
    '00000000' = 'Success'
    '80070643' = 'Fatal error during installation (0x80070643 = MSI 1603) - app-specific installer failure'
    '80070652' = 'Another installation was already in progress (0x80070652 = MSI 1618)'
    '80070005' = 'Access denied (0x80070005) - permissions or AV/security software interference'
    '8007000E' = 'Out of memory (0x8007000E)'
    '80070070' = 'Insufficient disk space (0x80070070)'
    '800705B4' = 'Operation timed out (0x800705B4)'
    '80070490' = 'Element not found (0x80070490) - component store / servicing corruption'
    '8024001E' = 'Update service stopped mid-operation (0x8024001E)'
    '80240020' = 'No interactive user logged on; install requires a user session (0x80240020)'
    '80240022' = 'All updates in the batch failed (0x80240022)'
    '8024000B' = 'Operation was cancelled (0x8024000B)'
    '80240017' = 'Update not applicable / superseded (0x80240017)'
    '8024200D' = 'Update needs to be re-downloaded (0x8024200D) - content changed or corrupt'
    '80242007' = 'Update in an invalid state on this device (0x80242007)'
    '80246007' = 'Update was not downloaded (0x80246007) - download never completed'
    '80248007' = 'Update metadata/EULA missing (0x80248007)'
    '8024402C' = 'DNS/proxy name resolution failure reaching download source (0x8024402C)'
    '80072EE2' = 'Network timeout reaching download source (0x80072EE2)'
    '80072EE7' = 'Cannot resolve download host (0x80072EE7) - DNS/proxy/firewall'
    '80072EFD' = 'Cannot connect to download source (0x80072EFD) - firewall/proxy'
    '80072F8F' = 'TLS/certificate or system-clock error during download (0x80072F8F)'
}

function Get-FailureReason {
    param($Code)   # int, or string like '0x80070643' / '1603'
    if ($null -eq $Code -or $Code -eq '') { return 'No error code recorded - see PME evidence lines / captured logs' }
    $key = "$Code" -replace '^0[xX]', ''
    $key = $key.Trim().ToUpper()
    # normalise negative int HRESULTs passed as decimal
    if ($key -match '^-\d+$') {
        try { $key = ([int]$key).ToString('X8') } catch { }
    }
    if ($script:ReasonMap.ContainsKey($key)) { return $script:ReasonMap[$key] }
    if ($key -match '^[0-9A-F]{8}$') { return "Unrecognised HRESULT 0x$key - look up with: certutil -error 0x$key" }
    return "Unrecognised installer exit code $Code"
}

# ---- Third-party vs Microsoft classification --------------------------------
# Known 3rd-party vendors/products seen in N-central 3PP catalogs (plus the
# stack this operation manages). Checked BEFORE the Microsoft patterns so that
# e.g. 'Cisco Webex' never gets mis-bucketed.
$script:VendorRegex = '(?i)\b(Adobe|Acrobat|Chrome|Google|Firefox|Mozilla|Thunderbird|Zoom|7-?Zip|Notepad\+\+|VLC|Oracle|Java(?: |$)|JRE|JDK|Corretto|Zulu|TeamViewer|AnyDesk|Dropbox|Slack|Cisco|AnyConnect|Secure Client|Webex|FortiClient|Fortinet|SonicWall|NetExtender|Global ?VPN|VMware|PuTTY|WinRAR|WinZip|iTunes|Apple|Foxit|KeePass|FileZilla|Git(?:Hub)?|Python|Node\.?js|Postman|Splashtop|ScreenConnect|ConnectWise|Citrix|Wireshark|OpenVPN|Dell Command|SupportAssist|Lenovo|HP Support|LogMeIn|GoTo|RealVNC|TightVNC|UltraVNC|Opera|Brave|Vivaldi|LibreOffice|OpenOffice|PDFCreator|PDF-XChange|CutePDF|Greenshot|Paint\.NET|IrfanView|GIMP|Inkscape|Audacity|OBS Studio|Evernote|Box(?:Drive| Tools)?|Egnyte)\b'

$script:MicrosoftRegex = '(?i)(\bKB\d{6,7}\b|Microsoft|Windows(?! Agent)|Office\b|\.NET|Defender|Security Intelligence|Servicing Stack|Malicious Software Removal|SQL Server|Visual Studio|Visual C\+\+|SharePoint|Exchange Server|Silverlight|OneDrive|Edge\b)'

function Get-PatchClass {
    # Returns 'ThirdParty', 'Microsoft' or 'Unclassified'
    param([string]$Title, [string]$SupportUrl = '', [string]$Manufacturer = '')
    if ($SupportUrl   -match '(?i)n-able|solarwinds|logicnow|mspplatform') { return 'ThirdParty' }
    if ($Manufacturer -match '(?i)^Microsoft')                            { return 'Microsoft'  }
    if ($Manufacturer -and $Manufacturer -notmatch '(?i)Microsoft')       { return 'ThirdParty' }
    if ($Title -match $script:VendorRegex)    { return 'ThirdParty' }
    if ($Title -match $script:MicrosoftRegex) { return 'Microsoft'  }
    return 'Unclassified'
}

function Add-Row {
    param(
        [datetime]$Date,
        [string]$Product,
        [string]$Source,      # 'WU history' | 'WU event' | 'MSI event' | 'PME log'
        [string]$Result,      # 'SUCCESS' | 'SUCCESS-REBOOT' | 'FAILED' | 'ABORTED' | 'IN PROGRESS' | 'UNKNOWN'
        [string]$Code = '',
        [string]$Reason = '',
        [string]$Class = 'ThirdParty'
    )
    $script:Rows.Add([pscustomobject]@{
        Date    = $Date
        Product = $Product
        Source  = $Source
        Result  = $Result
        Code    = $Code
        Reason  = $Reason
        Class   = $Class
    })
}

# ---- Locked-file-safe readers (PME keeps its logs open for writing) ---------
function Read-LogLines {
    # Streams a (possibly write-locked) log file; returns string[] (may be empty)
    param([string]$Path)
    $lines = New-Object System.Collections.Generic.List[string]
    $fs = $null; $sr = $null
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open,
              [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $sr = New-Object System.IO.StreamReader($fs)
        while ($null -ne ($l = $sr.ReadLine())) { $lines.Add($l) }
    }
    catch {
        Write-Log ("Could not read '{0}': {1}" -f $Path, $_.Exception.Message) 'WARN'
    }
    finally {
        if ($sr) { $sr.Dispose() } elseif ($fs) { $fs.Dispose() }
    }
    return ,$lines
}

function Copy-LogFileSafe {
    # Copy-Item first; falls back to a shared-read stream copy for locked files
    param([string]$Path, [string]$Destination)
    try {
        Copy-Item -LiteralPath $Path -Destination $Destination -Force
        return $true
    }
    catch {
        try {
            $src = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open,
                   [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            try {
                $dst = [System.IO.File]::Create($Destination)
                try     { $src.CopyTo($dst) }
                finally { $dst.Dispose() }
            }
            finally { $src.Dispose() }
            return $true
        }
        catch {
            Write-Log ("Could not capture '{0}': {1}" -f $Path, $_.Exception.Message) 'WARN'
            return $false
        }
    }
}

function Get-LineTimestamp {
    # Extracts a leading timestamp from a PME/agent log line; $null if none.
    # PME lines carry a thread prefix: '[1] 2026-07-22 17:00:29,275 DEBUG ...'
    # or '[PatchDeltaApproval-49] 2026-07-22 ...' - the optional group eats it.
    param([string]$Line)
    if ($Line -match '^\s*(?:\[[^\]]{1,60}\]\s+)?(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})') {
        $t = [datetime]::MinValue
        $raw = $Matches[1] -replace 'T', ' '
        if ([datetime]::TryParseExact($raw, 'yyyy-MM-dd HH:mm:ss',
                [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::None, [ref]$t)) { return $t }
    }
    if ($Line -match '^\s*(?:\[[^\]]{1,60}\]\s+)?(\d{1,2}[/.-]\d{1,2}[/.-]\d{4}\s+\d{1,2}:\d{2}:\d{2})') {
        $t = [datetime]::MinValue
        if ([datetime]::TryParse($Matches[1], [ref]$t)) { return $t }
    }
    return $null
}

function Get-ProductFromCommand {
    # Turns a PME 'Launching Command:' line's command into a friendly product
    # name, e.g. 'msiexec /i Wireshark-4.6.5-x64.msi ...' -> 'Wireshark 4.6.5'
    param([string]$Command)
    $file = $null
    if     ($Command -match '(?i)msiexec.*?/i\s+"?([^"\s]+\.msi)') { $file = $Matches[1] }
    elseif ($Command -match '(?i)msiexec.*?/x\s*"?(\{[0-9A-Fa-f-]+\})') { return ('MSI product {0}' -f $Matches[1]) }
    elseif ($Command -match '(?i)"([^"]+\.(exe|msi))"')            { $file = $Matches[1] }
    elseif ($Command -match '(?i)^(.+?\.(exe|msi))(\s|$)')         { $file = $Matches[1] }   # unquoted path, may contain spaces
    elseif ($Command -match '(?i)(\S+\.(exe|msi))')                { $file = $Matches[1] }
    if (-not $file) { return (Trunc $Command 60) }
    $base = [System.IO.Path]::GetFileNameWithoutExtension(($file -replace '.*[\\/]', ''))

    if ($base -match '(?i)uninstall-wireshark')                    { return 'Wireshark (old-version uninstaller)' }
    if ($base -match '(?i)^wireshark[-_ ]?([\d\.]+)?')             { return ('Wireshark {0}' -f $Matches[1]).Trim() }
    if ($base -match '(?i)googlechromestandaloneenterprise')       { return 'Google Chrome (Enterprise MSI)' }
    if ($base -match '(?i)^npp\.([\d\.]+)')                        { return ('Notepad++ {0}' -f $Matches[1].TrimEnd('.')) }
    if ($base -match '(?i)^7z(\d{2})(\d{2})')                      { return ('7-Zip {0}.{1}' -f $Matches[1], $Matches[2]) }
    if ($base -match '(?i)^firefox setup ([\d\.]+)')               { return ('Mozilla Firefox {0}' -f $Matches[1].TrimEnd('.')) }
    if ($base -match '(?i)^(jre|jdk)-(\d+)u(\d+)')                 { return ('Java {0} Update {1} ({2})' -f $Matches[2], $Matches[3], $Matches[1].ToUpper()) }
    if ($base -match '(?i)^winscp[-_ ]?([\d\.]+)?')                { return ('WinSCP {0}' -f $Matches[1]).Trim() }
    if ($base -match '(?i)keepass')                                { return 'KeePass Password Safe' }
    return $base
}

# === MAIN =====================================================================
try {
    Write-Log $divide
    Write-Log 'N-central 3rd-Party Patch Installation Report (V1.0)'
    Write-Log $divide

    $os = $null
    try { $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue } catch { }
    if ($os) {
        Write-Log ("Host: {0} | OS: {1} (build {2}) | Last boot: {3}" -f `
            $env:COMPUTERNAME, $os.Caption, $os.BuildNumber, $os.LastBootUpTime)
    } else {
        Write-Log ("Host: {0}" -f $env:COMPUTERNAME)
    }
    Write-Log ("Reporting window: last {0} days ({1:yyyy-MM-dd HH:mm} -> now)" -f $DaysBack, $script:Cutoff)

    $isAdmin = $true
    try {
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
                   ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { }
    if (-not $isAdmin) {
        Write-Log 'Not running elevated - some log folders/event data may be unreadable. Run as SYSTEM/Administrator for full results.' 'WARN'
    }

    # --- Step 1: Locate patch log sources & service health -------------------
    Write-Log $subdiv
    Write-Log '--- Step 1: Locating N-central / PME patch log sources ---'

    $pd  = $env:ProgramData
    $pf  = $env:ProgramFiles
    $pfx = ${env:ProgramFiles(x86)}

    # PME component log folders (current + legacy branding). Everything under
    # these trees is patch-engine specific, so whole 'log' folders qualify.
    $pmeLogDirs = New-Object System.Collections.Generic.List[object]
    foreach ($root in @("$pd\MspPlatform", "$pd\SolarWinds MSP")) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($comp in (Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue)) {
            foreach ($sub in @('log', 'logs', 'Diagnostic Logs')) {
                $cand = Join-Path $comp.FullName $sub
                if (Test-Path -LiteralPath $cand) {
                    $pmeLogDirs.Add([pscustomobject]@{ Label = ('PME-{0}' -f $comp.Name); Path = $cand; NameFilter = $null })
                }
            }
        }
    }

    # N-central Windows Agent log folder - large and mostly unrelated to
    # patching, so only patch-relevant file names are considered from here.
    $agentNameFilter = '(?i)patch|pme|third|3pp|msp|install|softwareupdate'
    foreach ($base in @($pfx, $pf)) {
        if (-not $base) { continue }
        $cand = Join-Path $base 'N-able Technologies\Windows Agent\log'
        if (Test-Path -LiteralPath $cand) {
            $pmeLogDirs.Add([pscustomobject]@{ Label = 'NC-Agent'; Path = $cand; NameFilter = $agentNameFilter })
        }
    }

    if ($pmeLogDirs.Count -eq 0) {
        Write-Log 'No PME / N-central agent log folders found on this device. Is this an N-central patch-managed endpoint?' 'WARN'
        $script:SourceNotes.Add('PME/agent log folders: NOT FOUND')
    } else {
        foreach ($d in $pmeLogDirs) { Write-Log ("Found source [{0}]: {1}" -f $d.Label, $d.Path) }
        $script:SourceNotes.Add(('PME/agent log folders: {0} found' -f $pmeLogDirs.Count))
    }

    # Service health (context only - presence differs by PME version)
    $svcNames = @(
        'Windows Agent Service', 'Windows Agent Maintenance Service',
        'PME.Agent.PmeService', 'SolarWinds.MSP.PME.Agent.PmeService',
        'PatchManagementService', 'SolarWinds.MSP.RpcServerService',
        'RequestHandlerAgent', 'FileCacheServiceAgent', 'SolarWinds.MSP.CacheService'
    )
    foreach ($sn in $svcNames) {
        try {
            $svc = Get-Service -Name $sn -ErrorAction SilentlyContinue
            if ($svc) { Write-Log ("Service '{0}': {1}" -f $svc.Name, $svc.Status) }
        } catch { }
    }

    # Collect the log FILES in the window once; reused by capture + parsing
    $logFiles = New-Object System.Collections.Generic.List[object]
    foreach ($d in $pmeLogDirs) {
        $files = Get-ChildItem -LiteralPath $d.Path -File -Recurse -ErrorAction SilentlyContinue |
                 Where-Object { $_.Extension -match '(?i)^\.(log|txt|\d+)$' -or $_.Name -match '(?i)\.log(\.\d+)?$' }
        if ($d.NameFilter) { $files = $files | Where-Object { $_.Name -match $d.NameFilter } }
        foreach ($f in ($files | Where-Object { $_.LastWriteTime -ge $script:Cutoff })) {
            $logFiles.Add([pscustomobject]@{ Label = $d.Label; File = $f })
        }
    }
    Write-Log ("{0} patch log file(s) written within the window." -f $logFiles.Count)

    # --- Step 2: Capture the raw log files -----------------------------------
    Write-Log $subdiv
    Write-Log ("--- Step 2: Capturing log files from the last {0} days ---" -f $DaysBack)

    $captureDir = $null
    if ($NoCapture) {
        Write-Log 'Capture skipped (-NoCapture).'
    }
    else {
        if (-not (Test-Path -LiteralPath $CaptureRoot)) {
            New-Item -Path $CaptureRoot -ItemType Directory -Force | Out-Null
        }
        $captureDir = Join-Path $CaptureRoot ("NCentral-3PP-Logs_{0}_{1}" -f $env:COMPUTERNAME, $script:Stamp)
        New-Item -Path $captureDir -ItemType Directory -Force | Out-Null

        foreach ($lf in $logFiles) {
            $destDir = Join-Path $captureDir $lf.Label
            if (-not (Test-Path -LiteralPath $destDir)) { New-Item -Path $destDir -ItemType Directory -Force | Out-Null }
            $dest = Join-Path $destDir $lf.File.Name
            if (Copy-LogFileSafe -Path $lf.File.FullName -Destination $dest) {
                $script:Captured.Add([pscustomobject]@{
                    Source = $lf.Label; Name = $lf.File.Name
                    SizeKB = [math]::Round($lf.File.Length / 1KB, 1)
                    LastWrite = $lf.File.LastWriteTime; OriginalPath = $lf.File.FullName
                })
            }
        }
        Write-Log ("Captured {0} of {1} log file(s) -> {2}" -f $script:Captured.Count, $logFiles.Count, $captureDir)
        Write-Log '(evidence CSVs are added and the bundle is zipped after parsing)'
    }

    # --- Step 3: Windows Update Agent history --------------------------------
    Write-Log $subdiv
    Write-Log '--- Step 3: Windows Update history (N-central published 3rd-party updates) ---'

    try {
        $session  = New-Object -ComObject 'Microsoft.Update.Session'
        $searcher = $session.CreateUpdateSearcher()
        $total    = $searcher.GetTotalHistoryCount()
        Write-Log ("WU history contains {0} total entr{1}." -f $total, $(if ($total -eq 1) { 'y' } else { 'ies' }))

        $inWindow = 0
        $page = 100
        for ($i = 0; $i -lt $total; $i += $page) {
            $count   = [math]::Min($page, $total - $i)
            $entries = $searcher.QueryHistory($i, $count)
            $olderThanWindow = $false
            foreach ($e in $entries) {
                if ($null -eq $e -or $null -eq $e.Date) { continue }
                # IUpdateHistoryEntry.Date is UTC - convert for local reporting
                $edate = [datetime]$e.Date
                if ($edate.Kind -ne [System.DateTimeKind]::Local) {
                    $edate = [datetime]::SpecifyKind($edate, [System.DateTimeKind]::Utc).ToLocalTime()
                }
                if ($edate -lt $script:Cutoff) { $olderThanWindow = $true; continue }
                if ($e.Operation -ne 1) { continue }              # 1 = Installation
                $title = if ($e.Title) { "$($e.Title)" } else { '(untitled update)' }
                $sup   = if ($e.SupportUrl) { "$($e.SupportUrl)" } else { '' }
                $class = Get-PatchClass -Title $title -SupportUrl $sup
                $inWindow++

                $hrHex = ''
                if ($null -ne $e.HResult -and $e.HResult -ne 0) { $hrHex = '0x' + ([int]$e.HResult).ToString('X8') }
                switch ([int]$e.ResultCode) {
                    2 { Add-Row -Date $edate -Product $title -Source 'WU history' -Result 'SUCCESS' -Class $class }
                    3 { Add-Row -Date $edate -Product $title -Source 'WU history' -Result 'SUCCESS-REBOOT' -Code $hrHex `
                              -Reason 'Succeeded with errors / pending reboot' -Class $class }
                    4 { Add-Row -Date $edate -Product $title -Source 'WU history' -Result 'FAILED' -Code $hrHex `
                              -Reason (Get-FailureReason $hrHex) -Class $class }
                    5 { Add-Row -Date $edate -Product $title -Source 'WU history' -Result 'ABORTED' -Code $hrHex `
                              -Reason 'Installation aborted (device shutdown/cancelled mid-install)' -Class $class }
                    default { Add-Row -Date $edate -Product $title -Source 'WU history' -Result 'IN PROGRESS' -Class $class }
                }
            }
            # QueryHistory returns newest-first: once a whole page is older than
            # the window we can stop paging.
            if ($olderThanWindow -and $entries.Count -gt 0) { break }
        }
        Write-Log ("{0} install entr{1} in the window (all publishers)." -f $inWindow, $(if ($inWindow -eq 1) { 'y' } else { 'ies' }))
        $script:SourceNotes.Add('WU history: OK')
    }
    catch {
        Write-Log ("WU history unavailable: {0}" -f $_.Exception.Message) 'WARN'
        $script:SourceNotes.Add('WU history: UNAVAILABLE')
    }

    # --- Step 4: Parse PME / agent log files ---------------------------------
    Write-Log $subdiv
    Write-Log '--- Step 4: Scanning PME / agent logs for install activity ---'

    $interestRegex   = '(?i)(install|deploy|patch)'
    $resultRegex     = '(?i)(fail|error|success|succe|completed|exit\s*code|result|reboot)'
    $noiseRegex      = '(?i)(heartbeat|polling|GET\s+/|POST\s+/|keep.?alive|Successfully installed the file|downloadInfoDetails)'
    $selfInstallLogs = '(?i)(^PME_Install_|_install\.log$)'   # PME installing ITSELF - captured but not parsed
    $configCmdRegex  = '(?i)(cmd\.exe|reg(\.exe)?\s+add)'
    $uninstallRegex  = '(?i)(uninstall|msiexec[^|]*?/x\s*\{)'
    $evTruncated     = 0

    # 3PP engine health trackers (dates tracked across the WHOLE log, so the
    # report can say when the engine last worked even if outside the window)
    $engineErrors   = @{}      # label -> pscustomobject(N, First, Last) - in-window only
    $lastCatalogOk  = $null    # last successful catalog xml download
    $lastInstallCmd = $null    # last install command PME ever launched
    $lastDetection  = $null    # last 'Applications matching filter: N' scan

    function Add-EngineError {
        param([string]$Label, [datetime]$Time)
        if (-not $engineErrors.ContainsKey($Label)) {
            $engineErrors[$Label] = [pscustomobject]@{ N = 0; First = $Time; Last = $Time }
        }
        $e = $engineErrors[$Label]
        $e.N++
        if ($Time -lt $e.First) { $e.First = $Time }
        if ($Time -gt $e.Last)  { $e.Last  = $Time }
    }

    foreach ($lf in $logFiles) {
        if ($lf.File.Name -match $selfInstallLogs) { continue }
        $isTpp       = ($lf.File.Name -match '(?i)thirdparty')          # PME 3PP engine logs
        $isPatchFile = ($lf.File.Name -match '(?i)thirdparty|patch')    # patch-related logs
        $isCacheFile = ($lf.File.Name -match '(?i)FileCacheService|CacheService|SendManager')  # download/cache agent
        $pendingCmd  = @{}                                              # thread -> launched command awaiting exit code
        $lines  = Read-LogLines -Path $lf.File.FullName
        $lastTs = $null
        foreach ($line in $lines) {
            $ts = Get-LineTimestamp -Line $line
            if ($ts) { $lastTs = $ts }
            $effTs = if ($ts) { $ts } else { $lastTs }
            if ($null -eq $effTs) { continue }
            $inWindow = ($effTs -ge $script:Cutoff)

            # ---- ThirdPartyPatch engine: pair 'Launching Command' -> 'Exit code'
            if ($isTpp) {
                if ($line -match '(?i)Launching Command:\s*(.+)$') {
                    $cmd = $Matches[1].Trim()
                    # config helper commands (REG ADD via cmd.exe etc.) run
                    # interleaved with the installer - ignore them completely
                    # so the installer's exit code still pairs correctly
                    if ($cmd -match $configCmdRegex) { continue }
                    $thread = if ($line -match '^\s*\[([^\]]{1,60})\]') { $Matches[1] } else { '_' }
                    $type   = if ($cmd -match $uninstallRegex) { 'Uninstall' } else { 'Install' }
                    if ($pendingCmd.ContainsKey($thread)) {
                        # previous launch on this thread never logged an exit code
                        $old = $pendingCmd[$thread]
                        if ($old.Type -eq 'Install' -and $old.Time -ge $script:Cutoff) {
                            Add-Row -Date $old.Time -Product $old.Product -Source 'PME 3PP' -Result 'UNKNOWN' `
                                    -Reason 'No exit code found in log after launch' -Class 'ThirdParty'
                        }
                    }
                    $pendingCmd[$thread] = @{ Time = $effTs; Product = (Get-ProductFromCommand $cmd); Type = $type }
                    if ($type -eq 'Install') { $lastInstallCmd = @{ Time = $effTs; Product = $pendingCmd[$thread].Product } }
                    continue
                }
                # exit lines: 'Process Exit code: 0' / 'Exit code: 1619' /
                # 'Uninstall After is enabled and Exit code: [0]'
                if ($line -match '(?i)Exit code:\s*\[?(-?\d+)\]?') {
                    $code   = $Matches[1]
                    $thread = if ($line -match '^\s*\[([^\]]{1,60})\]') { $Matches[1] } else { '_' }
                    if ($pendingCmd.ContainsKey($thread)) {
                        $p = $pendingCmd[$thread]; $pendingCmd.Remove($thread)
                        if ($inWindow) {
                            $ok = (@('0', '1641', '3010') -contains $code)
                            # install steps always reported; uninstall steps only when they fail
                            if ($p.Type -eq 'Install' -or -not $ok) {
                                $label  = if ($p.Type -eq 'Uninstall') { $p.Product + ' (uninstall step of upgrade)' } else { $p.Product }
                                $result = if (-not $ok) { 'FAILED' } elseif ($code -ne '0') { 'SUCCESS-REBOOT' } else { 'SUCCESS' }
                                $reason = if (-not $ok) { Get-FailureReason $code } else { '' }
                                Add-Row -Date $p.Time -Product $label -Source 'PME 3PP' -Result $result -Code $code `
                                        -Reason $reason -Class 'ThirdParty'
                            }
                        }
                    }
                    continue
                }
                if ($line -match '(?i)Applications matching filter:\s*(\d+)') {
                    $lastDetection = @{ Time = $effTs; Matched = [int]$Matches[1] }
                    continue
                }
                if ($line -match '(?i)was downloaded as .*(ThirdPartySoftware|Vendors|Repository)\.xml.*"Complete"') {
                    if ($null -eq $lastCatalogOk -or $effTs -gt $lastCatalogOk) { $lastCatalogOk = $effTs }
                    continue
                }
                if ($inWindow -and $line -match '(?i)version installed:.*latest version:' -and
                    $script:Evidence.Count -lt $MaxEvidenceLines) {
                    $script:Evidence.Add([pscustomobject]@{ Time = $effTs; Level = 'INFO'
                        File = ('{0}\{1}' -f $lf.Label, $lf.File.Name); Text = (Trunc $line.Trim() 300) })
                    continue
                }
            }

            # ---- 3PP engine error counting (in-window, patch/cache files) ----
            if ($inWindow -and ($isPatchFile -or $isCacheFile) -and $line -match '\bERROR\b') {
                $lbl = $null
                if     ($line -match '(?i)UnzipFile')                                  { $lbl = 'Catalog/package unzip failed' }
                elseif ($line -match '(?i)Caching failed|Error when downloading file') { $lbl = 'Catalog/package download failed (FileCache/CacheService)' }
                elseif ($line -match '(?i)CacheService is not available')              { $lbl = 'Cache service unreachable (IPC)' }
                elseif ($line -match '(?i)Download error|Failed to download')          { $lbl = 'Patch content download failed (cache/download agent)' }
                elseif ($isTpp)                                                        { $lbl = 'Other 3PP engine error' }
                if ($lbl) {
                    # counted in the engine-health summary; a sample also goes
                    # to the evidence file until the cap is reached
                    Add-EngineError -Label $lbl -Time $effTs
                    if ($script:Evidence.Count -lt $MaxEvidenceLines) {
                        $script:Evidence.Add([pscustomobject]@{ Time = $effTs; Level = 'ERROR'
                            File = ('{0}\{1}' -f $lf.Label, $lf.File.Name); Text = (Trunc $line.Trim() 300) })
                    }
                    continue
                }
            }

            # ---- generic evidence (in-window; INFO chatter from 3PP engine
            #      files is handled above, so skip it here) --------------------
            if (-not $inWindow) { continue }
            if ($isTpp -or $isCacheFile) { continue }   # summarized via engine health instead
            if ($line -match $noiseRegex) { continue }
            $is3ppTag = ($line -match '(?i)third.?party|\b3pp\b')
            if (-not $is3ppTag) {
                if ($line -notmatch $interestRegex -or $line -notmatch $resultRegex) { continue }
            }
            if ($script:Evidence.Count -ge $MaxEvidenceLines) { $evTruncated++; continue }
            $level = 'INFO'
            if ($line -match '(?i)\b(FATAL|ERROR)\b') { $level = 'ERROR' }
            elseif ($line -match '(?i)\bWARN(ING)?\b') { $level = 'WARN' }
            $script:Evidence.Add([pscustomobject]@{
                Time  = $effTs
                Level = $level
                File  = ('{0}\{1}' -f $lf.Label, $lf.File.Name)
                Text  = (Trunc $line.Trim() 300)
            })

            # Structured extraction for OTHER patch log dialects (this fleet's
            # 3PP engine is handled precisely above; this is a safety net for
            # differently-phrased agent/PME logs) - only unambiguous lines:
            # an explicit exit code, or an explicit succeeded/failed phrase.
            $code = ''
            if ($line -match '(?i)exit\s*code[:=\s]+\[?(-?\d+)\]?') { $code = $Matches[1] }
            $hasVerdict = ($line -match '(?i)\b(succeeded|installed successfully|completed successfully|failed|failure)\b')
            if ($code -ne '' -or $hasVerdict) {
                $prod = $null
                if     ($line -match "(?i)(?:patch|product|package|application|title)\s*[:=]\s*['`"]?([^'`";,\|]{3,90})") { $prod = $Matches[1].Trim() }
                elseif ($line -match "'([^']{3,90})'") { $prod = $Matches[1].Trim() }
                if ($prod -and $prod -notmatch '^[\d\.\s]+$') {
                    $failed = $false
                    if ($code -ne '' -and (@('0','1641','3010') -notcontains $code)) { $failed = $true }
                    if ($line -match '(?i)\b(failed|failure)\b') { $failed = $true }
                    $result = if ($failed) { 'FAILED' } elseif ($code -eq '3010' -or $code -eq '1641') { 'SUCCESS-REBOOT' } else { 'SUCCESS' }
                    $reason = if ($failed) { Get-FailureReason $code } else { '' }
                    Add-Row -Date $effTs -Product $prod -Source 'PME log' -Result $result -Code $code `
                            -Reason $reason -Class (Get-PatchClass -Title $prod)
                }
            }
        }

        # a launched install with no exit code logged (crash / still running)
        foreach ($p in $pendingCmd.Values) {
            if ($p.Type -eq 'Install' -and $p.Time -ge $script:Cutoff) {
                Add-Row -Date $p.Time -Product $p.Product -Source 'PME 3PP' -Result 'UNKNOWN' `
                        -Reason 'No exit code found in log after launch (crashed or still running?)' -Class 'ThirdParty'
            }
        }
    }
    $evErr = @($script:Evidence | Where-Object { $_.Level -eq 'ERROR' }).Count
    $evWrn = @($script:Evidence | Where-Object { $_.Level -eq 'WARN' }).Count
    Write-Log ("Matched {0} evidence line(s) ({1} error, {2} warning){3}." -f `
        $script:Evidence.Count, $evErr, $evWrn, $(if ($evTruncated) { ", $evTruncated more truncated (raise -MaxEvidenceLines)" } else { '' }))
    $engineErrTotal = 0
    foreach ($v in $engineErrors.Values) { $engineErrTotal += $v.N }
    if ($engineErrTotal -gt 0) {
        Write-Log ("{0} 3PP engine error(s) counted in the window." -f $engineErrTotal) 'WARN'
    }
    if ($logFiles.Count -gt 0) { $script:SourceNotes.Add('PME/agent log scan: OK') }

    # --- Step 5: Event log evidence ------------------------------------------
    Write-Log $subdiv
    Write-Log '--- Step 5: Event logs (WindowsUpdateClient / MsiInstaller) ---'

    # 5a. WU client events 19 (install success) / 20 (install failure)
    try {
        $wuEvents = @(Get-WinEvent -FilterHashtable @{
            LogName = 'System'; ProviderName = 'Microsoft-Windows-WindowsUpdateClient'
            Id = @(19, 20); StartTime = $script:Cutoff } -ErrorAction Stop)
        Write-Log ("WindowsUpdateClient: {0} install event(s) in window." -f $wuEvents.Count)
        foreach ($ev in $wuEvents) {
            $msg  = if ($ev.Message) { $ev.Message } else { '' }
            $code = if ($msg -match '(0x[0-9A-Fa-f]{8})') { $Matches[1] } else { '' }
            # Id 19: '...successfully installed the following update: <title>'
            # Id 20: '...failed to install the following update with error 0x...: <title>'
            $title = $null
            if     ($msg -match '(?i)error\s+0x[0-9A-Fa-f]{8}:\s*(.+?)\.?\s*$') { $title = $Matches[1].Trim() }
            elseif ($msg -match '(?i)following update:\s*(.+?)\.?\s*$')          { $title = $Matches[1].Trim() }
            if (-not $title -and $ev.Properties) {
                # EventData fallback: 19 = (updateTitle,...), 20 = (errorCode, updateTitle,...)
                $pIdx = if ($ev.Id -eq 20) { 1 } else { 0 }
                if ($ev.Properties.Count -gt $pIdx -and $ev.Properties[$pIdx].Value) {
                    $title = "$($ev.Properties[$pIdx].Value)"
                }
            }
            if (-not $title) { $title = '(title unavailable)' }
            $class = Get-PatchClass -Title $title
            if ($ev.Id -eq 19) {
                Add-Row -Date $ev.TimeCreated -Product $title -Source 'WU event' -Result 'SUCCESS' -Class $class
            } else {
                Add-Row -Date $ev.TimeCreated -Product $title -Source 'WU event' -Result 'FAILED' -Code $code `
                        -Reason (Get-FailureReason $code) -Class $class
            }
        }
        $script:SourceNotes.Add('WU client events: OK')
    }
    catch {
        if ($_.Exception.Message -match 'No events were found') {
            Write-Log 'WindowsUpdateClient: no install events in window.'
            $script:SourceNotes.Add('WU client events: none in window')
        } else {
            Write-Log ("WindowsUpdateClient events unavailable: {0}" -f $_.Exception.Message) 'WARN'
            $script:SourceNotes.Add('WU client events: UNAVAILABLE')
        }
    }

    # 5b. MSI events (note: MSI events cover installs from ANY source on the
    #     device, not only N-central - they mainly add the 'why' for failures)
    try {
        $msiEvents = @(Get-WinEvent -FilterHashtable @{
            LogName = 'Application'; ProviderName = 'MsiInstaller'
            Id = @(11707, 11708, 1033); StartTime = $script:Cutoff } -ErrorAction Stop)
        Write-Log ("MsiInstaller: {0} install event(s) in window (all sources)." -f $msiEvents.Count)
        foreach ($ev in $msiEvents) {
            $msg = if ($ev.Message) { $ev.Message } else { '' }
            $prod = $null; $manu = ''; $status = ''
            if ($ev.Id -eq 1033) {
                if     ($msg -match '(?i)Product Name:\s*(.+?)\.\s*Product Version:') { $prod = $Matches[1].Trim() }
                elseif ($msg -match '(?i)Product Name:\s*(.+?)\.(\s|$)')              { $prod = $Matches[1].Trim() }
                if     ($msg -match '(?i)Manufacturer:\s*(.+?)\.\s*Installation')     { $manu = $Matches[1].Trim() }
                elseif ($msg -match '(?i)Manufacturer:\s*(.+?)\.(\s|$)')              { $manu = $Matches[1].Trim() }
                if     ($msg -match '(?i)status:\s*(\d+)')                            { $status = $Matches[1] }
            } else {
                if ($msg -match '(?i)^Product:\s*(.+?)\s*--') { $prod = $Matches[1].Trim() }
            }
            if (-not $prod) { continue }
            $class = Get-PatchClass -Title $prod -Manufacturer $manu
            $failed = ($ev.Id -eq 11708 -or ($status -ne '' -and (@('0','3010','1641') -notcontains $status)))
            if ($ev.Id -eq 1033 -and -not $failed) { continue }  # 1033 successes duplicate 11707
            if ($failed) {
                $why = if ($status) { Get-FailureReason $status }
                       else { 'MSI installation failed - status code in the paired MsiInstaller 1033 event / app installer log' }
                Add-Row -Date $ev.TimeCreated -Product $prod -Source 'MSI event' -Result 'FAILED' -Code $status `
                        -Reason $why -Class $class
            } else {
                Add-Row -Date $ev.TimeCreated -Product $prod -Source 'MSI event' -Result 'SUCCESS' -Class $class
            }
        }
        $script:SourceNotes.Add('MSI events: OK')
    }
    catch {
        if ($_.Exception.Message -match 'No events were found') {
            Write-Log 'MsiInstaller: no install events in window.'
            $script:SourceNotes.Add('MSI events: none in window')
        } else {
            Write-Log ("MsiInstaller events unavailable: {0}" -f $_.Exception.Message) 'WARN'
            $script:SourceNotes.Add('MSI events: UNAVAILABLE')
        }
    }

    # --- Step 6: De-duplicate across sources ---------------------------------
    # The same install can surface in WU history, WU events and MSI events.
    # Preference order keeps the richest source; failure codes are merged in.
    $srcPref = @{ 'WU history' = 0; 'WU event' = 1; 'MSI event' = 2; 'PME log' = 3 }
    $seen    = @{}
    $kept    = New-Object System.Collections.Generic.List[object]
    foreach ($r in ($script:Rows | Sort-Object { $srcPref[$_.Source] }, Date)) {
        $normProd = (($r.Product -replace '[^a-zA-Z0-9]', '').ToLower())
        if ($normProd.Length -gt 40) { $normProd = $normProd.Substring(0, 40) }
        $bucket   = [math]::Floor($r.Date.Ticks / (600 * [timespan]::TicksPerSecond))   # 10-min bucket
        $key      = '{0}|{1}|{2}' -f $bucket, $normProd, $r.Result
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true

        # fuzzy merge: same result within 60 min where one product name
        # contains the other (e.g. WU title 'Google Chrome 138.x' vs MSI
        # product 'Google Chrome') -> keep first, merge missing code/reason
        $dupe = $null
        foreach ($k in $kept) {
            if ($k.Result -ne $r.Result) { continue }
            if ([math]::Abs(($k.Date - $r.Date).TotalMinutes) -gt 60) { continue }
            $a = ($k.Product -replace '[^a-zA-Z0-9]', '').ToLower()
            $b = $normProd
            if ($a.Length -lt 6 -or $b.Length -lt 6) { continue }
            if ($a.Contains($b) -or $b.Contains($a)) { $dupe = $k; break }
        }
        if ($dupe) {
            if (-not $dupe.Code -and $r.Code)     { $dupe.Code = $r.Code; $dupe.Reason = $r.Reason }
            if ($dupe.Class -eq 'Unclassified' -and $r.Class -ne 'Unclassified') { $dupe.Class = $r.Class }
            continue
        }
        $kept.Add($r)
    }

    # --- Step 7: Summary ------------------------------------------------------
    $thirdParty = @($kept | Where-Object { $_.Class -ne 'Microsoft' } | Sort-Object Date -Descending)
    $microsoft  = @($kept | Where-Object { $_.Class -eq 'Microsoft' } | Sort-Object Date -Descending)
    $reportRows = if ($IncludeMicrosoft) { @($thirdParty + $microsoft | Sort-Object Date -Descending) } else { $thirdParty }

    $tpOk      = @($thirdParty | Where-Object { $_.Result -like 'SUCCESS*' })
    $tpFail    = @($thirdParty | Where-Object { $_.Result -eq 'FAILED' })
    $tpAbort   = @($thirdParty | Where-Object { $_.Result -eq 'ABORTED' })
    $tpOther   = @($thirdParty | Where-Object { $_.Result -notlike 'SUCCESS*' -and $_.Result -ne 'FAILED' -and $_.Result -ne 'ABORTED' })

    Write-Output ''
    Write-Output $divide
    Write-Output ("  SUMMARY: 3rd-party patch installations - last {0} days - {1}" -f $DaysBack, $env:COMPUTERNAME)
    Write-Output $divide

    if ($reportRows.Count -eq 0) {
        Write-Output '  No 3rd-party patch installation activity found in the window.'
        Write-Output '  Possible causes: no 3rd-party patches were approved/scheduled for this'
        Write-Output '  device, 3rd-party patching is not enabled in its Patch Management'
        Write-Output '  profile, or the sources below were unavailable.'
    }
    else {
        Write-Output ('  {0,-16} {1,-15} {2,-11} {3,-4} {4}' -f 'Date', 'Result', 'Source', 'Cls', 'Patch / Product')
        Write-Output "  $subdiv"
        foreach ($r in $reportRows) {
            $cls = switch ($r.Class) { 'ThirdParty' { '3P' } 'Microsoft' { 'MS' } default { '?' } }
            Write-Output ('  {0:yyyy-MM-dd HH:mm} {1,-15} {2,-11} {3,-4} {4}' -f `
                $r.Date, $r.Result, $r.Source, $cls, (Trunc $r.Product 55))
            if ($r.Result -eq 'FAILED' -or ($r.Reason -and $r.Result -ne 'SUCCESS')) {
                $codeStr = if ($r.Code) { ' [' + $r.Code + ']' } else { '' }
                Write-Output ('       -> {0}{1}' -f (Trunc $r.Reason 90), $codeStr)
            }
        }
    }

    Write-Output "  $subdiv"
    Write-Output ('  3rd-party installs: {0} total | {1} succeeded | {2} FAILED | {3} aborted | {4} other' -f `
        $thirdParty.Count, $tpOk.Count, $tpFail.Count, $tpAbort.Count, $tpOther.Count)
    if (-not $IncludeMicrosoft -and $microsoft.Count -gt 0) {
        Write-Output ('  ({0} Microsoft update entr{1} suppressed - re-run with -IncludeMicrosoft to list)' -f `
            $microsoft.Count, $(if ($microsoft.Count -eq 1) { 'y' } else { 'ies' }))
    }
    Write-Output ('  Sources: ' + ($script:SourceNotes -join ' | '))

    # ---- 3PP engine health block --------------------------------------------
    # Unhealthy = errors at/over threshold AND no successful 3rd-party install
    # recently (none in window, or the errors clearly post-date the last one)
    $lastOkInstall = $null
    if ($tpOk.Count -gt 0) { $lastOkInstall = ($tpOk | Sort-Object Date -Descending | Select-Object -First 1).Date }
    $newestErr = $null
    foreach ($v in $engineErrors.Values) { if ($null -eq $newestErr -or $v.Last -gt $newestErr) { $newestErr = $v.Last } }
    $engineUnhealthy = $false
    if ($engineErrTotal -ge $EngineErrorThreshold) {
        if ($null -eq $lastOkInstall) { $engineUnhealthy = $true }
        elseif ($newestErr -and ($newestErr - $lastOkInstall).TotalDays -gt 7) { $engineUnhealthy = $true }
    }
    Write-Output ''
    Write-Output '  3PP ENGINE HEALTH:'
    $healthLabel = if ($engineUnhealthy) {
                       $since = if ($lastOkInstall) { 'since {0:yyyy-MM-dd}' -f $lastOkInstall } else { 'in the window' }
                       "UNHEALTHY - engine is failing and no successful 3rd-party install $since"
                   }
                   elseif ($engineErrTotal -gt 0) { "DEGRADED - $engineErrTotal engine error(s) in window, but installs are still succeeding" }
                   elseif ($logFiles.Count -eq 0) { 'UNKNOWN - no PME logs found' }
                   else { 'OK - no engine errors seen in window' }
    Write-Output ('   Status                  : {0}' -f $healthLabel)
    Write-Output ('   Last catalog download OK: {0}' -f $(if ($lastCatalogOk)  { '{0:yyyy-MM-dd HH:mm}' -f $lastCatalogOk } else { 'never seen in retained logs' }))
    Write-Output ('   Last install launched   : {0}' -f $(if ($lastInstallCmd) { '{0:yyyy-MM-dd HH:mm} - {1}' -f $lastInstallCmd.Time, $lastInstallCmd.Product } else { 'never seen in retained logs' }))
    Write-Output ('   Last detection scan     : {0}' -f $(if ($lastDetection)  { '{0:yyyy-MM-dd HH:mm} - {1} application(s) matched the patch filter' -f $lastDetection.Time, $lastDetection.Matched } else { 'never seen in retained logs' }))
    if ($engineErrTotal -gt 0) {
        Write-Output ('   Engine errors in window : {0} total' -f $engineErrTotal)
        foreach ($k in ($engineErrors.Keys | Sort-Object { $engineErrors[$_].N } -Descending)) {
            $v = $engineErrors[$k]
            Write-Output ('     - {0}: {1}x  ({2:yyyy-MM-dd} .. {3:yyyy-MM-dd})' -f $k, $v.N, $v.First, $v.Last)
        }
    }
    if ($engineUnhealthy) {
        Write-Output '   ACTION: 3rd-party patching is silently dead on this device - the'
        Write-Output '   engine cannot download/unpack its software catalog, so every scan'
        Write-Output '   matches 0 applications and nothing is ever installed. Check the'
        Write-Output '   FileCacheServiceAgent / CacheService logs in the capture bundle,'
        Write-Output '   verify access to sis.n-able.com, and repair/reinstall PME on the'
        Write-Output '   device (N-central: re-run PME setup, or the community Repair-PME script).'
    }

    if ($tpFail.Count -gt 0) {
        Write-Output ''
        Write-Output '  FAILED 3RD-PARTY INSTALLS (most recent first):'
        foreach ($f in $tpFail) {
            Write-Output ('   - {0:yyyy-MM-dd HH:mm}  {1}' -f $f.Date, (Trunc $f.Product 70))
            Write-Output ('       why: {0}{1}  (source: {2})' -f $f.Reason, $(if ($f.Code) { ' [' + $f.Code + ']' } else { '' }), $f.Source)
        }
    }

    # Error-level PME evidence - printed to task output (full set goes to the bundle)
    $evErrors = @($script:Evidence | Where-Object { $_.Level -ne 'INFO' } | Sort-Object Time -Descending)
    if ($evErrors.Count -gt 0) {
        Write-Output ''
        Write-Output ('  PME LOG ERRORS/WARNINGS in window ({0} line(s), showing up to 40):' -f $evErrors.Count)
        foreach ($e in ($evErrors | Select-Object -First 40)) {
            Write-Output ('   [{0:yyyy-MM-dd HH:mm}] [{1}] [{2}] {3}' -f $e.Time, $e.Level, $e.File, (Trunc $e.Text 160))
        }
        if ($evErrors.Count -gt 40) { Write-Output ('   ... {0} more - see PME-Evidence file in the capture bundle.' -f ($evErrors.Count - 40)) }
    }
    Write-Output $divide
    Write-Output ''

    # --- Step 8: Write CSV / evidence into the bundle, then zip ---------------
    $csvDir = if ($captureDir) { $captureDir } else { $CaptureRoot }
    if (-not $NoCsv) {
        if (-not (Test-Path -LiteralPath $csvDir)) { New-Item -Path $csvDir -ItemType Directory -Force | Out-Null }
        if ($kept.Count -gt 0) {
            $csvPath = Join-Path $csvDir ("ThirdParty-Install-Report_{0}_{1}.csv" -f $env:COMPUTERNAME, $script:Stamp)
            $kept | Sort-Object Date -Descending |
                Select-Object @{n='Date';e={$_.Date.ToString('yyyy-MM-dd HH:mm:ss')}}, Result, Source, Class, Product, Code, Reason |
                Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-Log ("Result CSV written: {0} ({1} row(s))" -f $csvPath, $kept.Count)
        }
        else {
            Write-Log 'No parsed install rows - result CSV skipped.'
        }

        if ($script:Evidence.Count -gt 0) {
            $evPath = Join-Path $csvDir ("PME-Evidence_{0}_{1}.txt" -f $env:COMPUTERNAME, $script:Stamp)
            $script:Evidence | Sort-Object Time | ForEach-Object {
                '[{0:yyyy-MM-dd HH:mm:ss}] [{1}] [{2}] {3}' -f $_.Time, $_.Level, $_.File, $_.Text
            } | Set-Content -Path $evPath -Encoding UTF8
            Write-Log ("PME evidence file written: {0}" -f $evPath)
        }
    }

    if ($captureDir -and -not $NoZip) {
        $zipPath = "$captureDir.zip"
        $content = @(Get-ChildItem -LiteralPath $captureDir -Recurse -File -ErrorAction SilentlyContinue)
        if ($content.Count -gt 0) {
            try {
                if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
                Compress-Archive -Path (Join-Path $captureDir '*') -DestinationPath $zipPath -Force
                $zipKB = [math]::Round((Get-Item -LiteralPath $zipPath).Length / 1KB, 1)
                Remove-Item -LiteralPath $captureDir -Recurse -Force
                Write-Log ("Capture bundle: {0} ({1} KB, {2} file(s))" -f $zipPath, $zipKB, $content.Count)
            }
            catch {
                Write-Log ("Zip failed ({0}) - captured files left in {1}" -f $_.Exception.Message, $captureDir) 'WARN'
            }
        }
        else {
            Remove-Item -LiteralPath $captureDir -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log 'Nothing captured - no bundle created.'
        }
    }
    elseif ($captureDir) {
        Write-Log ("Captured files left unzipped in: {0}" -f $captureDir)
    }

    # --- Exit ----------------------------------------------------------------
    $flagReasons = @()
    if ($tpFail.Count -gt 0) { $flagReasons += ('{0} 3rd-party install failure(s)' -f $tpFail.Count) }
    if ($engineUnhealthy)    { $flagReasons += ('3PP engine unhealthy ({0} engine error(s), nothing installed)' -f $engineErrTotal) }
    if ($flagReasons.Count -gt 0) {
        Write-Log ("RESULT: {0} in the last {1} days - exiting 2 so N-central flags this device." -f ($flagReasons -join ' and '), $DaysBack)
        exit 2
    }
    Write-Log ("RESULT: no 3rd-party install failures and no engine problems in the last {0} days." -f $DaysBack)
    exit 0
}
catch {
    Write-Log ("ERROR: {0}" -f $_.Exception.Message) 'ERROR'
    if ($_.ScriptStackTrace) { Write-Log $_.ScriptStackTrace 'ERROR' }
    exit 1
}
