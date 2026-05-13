#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Microsoft Entra Connect Sync version + prerequisite compliance check.
    Designed for N-central "Run a Script" deployment.

.DESCRIPTION
    Read-only compliance check. No state changes are made. Four checks
    run in sequence:

    1. DETECTION
       Looks for Microsoft Entra Connect Sync (formerly Azure AD Connect)
       on the host using three methods:
         - the ADSync Windows service
         - uninstall registry entries (32- and 64-bit views)
         - the ADSync service binary's FileVersion as a fallback

    2. VERSION COMPLIANCE
       Compares the installed version against a configurable minimum.
       Default minimum is 2.5.79.0. Anything below records FAIL.

    3. PREREQUISITES (only when Entra Connect Sync is detected)
       - .NET Framework 4.7.2 or later (registry Release >= 461808)
       - TLS 1.2 enabled in SCHANNEL Client and Server
       - .NET 4.x SchUseStrongCrypto = 1 in both 64-bit and 32-bit
         (WOW6432Node) registry paths

    4. ROLLING END-OF-SUPPORT (only when Entra Connect Sync is detected
       and -SkipEOLCheck is not passed)
       Looks up the installed version in an embedded End-of-Support
       table sourced from the published Microsoft Entra Connect version
       history. Microsoft retires each version 12 months after its
       successor is released; the table records the explicit EOL date
       per version. The check:
         - WARN if EOL is within -EOLWarnDays (default 30) days
         - FAIL if EOL is already in the past
         - INFO if "newer than embedded table" (refresh hint emitted)
         - INFO if the installed version is the current latest with no
           EOL date set yet
       The embedded table carries a -VersionDataAsOf date so operators
       can see how fresh the data is and refresh it from Microsoft docs
       periodically.

    Outcome shapes:
      PASS   - Entra Connect Sync installed, version meets minimum,
               all prerequisites met, EOL is more than -EOLWarnDays
               days away (or version is the current latest).
      WARN   - Entra Connect Sync is not installed (expected on most
               hosts), OR installed and supported today but the rolling
               EOL is within -EOLWarnDays days.
      FAIL   - Entra Connect Sync is installed but the version is below
               the minimum, OR any prerequisite is not met, OR the
               installed version is past its rolling End-of-Support
               date per Microsoft's published table.

.PARAMETER MinimumVersion
    The minimum acceptable Entra Connect Sync version. Default: 2.5.79.0.

.PARAMETER MinNetRelease
    The minimum acceptable .NET Framework registry Release value.
    Default: 461808 (= .NET Framework 4.7.2).

.PARAMETER EOLWarnDays
    Number of days before End-of-Support at which the rolling EOL check
    raises WARN. Default: 30.

.PARAMETER SkipEOLCheck
    Skip the rolling End-of-Support lookup against the embedded table.
    The minimum-version check still runs and the prerequisites are still
    validated.

.NOTES
    Exit codes (for N-central):
        0 = PASS
        1 = WARN  (Entra Connect Sync not installed, OR EOL within
                   -EOLWarnDays days)
        2 = FAIL  (installed below minimum, prerequisites not met, OR
                   installed version past EOL date per Microsoft docs)

    Version : v1.1 (Embedded End-of-Support table for rolling EOL
                    detection. Adds -EOLWarnDays / -SkipEOLCheck params,
                    new ROLLING END-OF-SUPPORT report section, and a
                    -VersionDataAsOf timestamp so operators can see how
                    fresh the embedded table is. Sourced from the
                    published Microsoft Entra Connect version history.)
              v1.0 (initial)
#>

param(
    [string] $MinimumVersion = "2.5.79.0",
    [int]    $MinNetRelease  = 461808,

    # v1.1: rolling End-of-Support
    [int]    $EOLWarnDays    = 30,
    [switch] $SkipEOLCheck
)

# ============================================================
#  EXECUTION POLICY BYPASS
# ============================================================
try {
    $cur = Get-ExecutionPolicy -Scope Process
    if ($cur -ne 'Bypass' -and $cur -ne 'Unrestricted') {
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
$Script:Version       = "v1.1"
$Script:ScriptName    = "Check-EntraConnectSyncCompliance$Script:Version.ps1"
$Script:OverallStatus = "PASS"
$Script:Log           = [System.Collections.Generic.List[string]]::new()

# ============================================================
#  EMBEDDED END-OF-SUPPORT TABLE (v1.1)
#  Source: https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-version-history
#  Refresh this table whenever Microsoft publishes new versions, and
#  bump $Script:VersionDataAsOf to reflect the refresh date so the
#  N-central report surfaces staleness to operators.
# ============================================================
$Script:VersionDataAsOf = '2026-05-13'

$Script:VersionEOLTable = @(
    [PSCustomObject]@{ Version = '2.3.2.0';   EOLDate = (Get-Date '2025-04-30'); Note = 'Aligned with security change released in 2.4.18.0' }
    [PSCustomObject]@{ Version = '2.3.6.0';   EOLDate = (Get-Date '2025-04-30'); Note = 'Aligned with security change released in 2.4.18.0' }
    [PSCustomObject]@{ Version = '2.3.8.0';   EOLDate = (Get-Date '2025-04-30'); Note = 'Aligned with security change released in 2.4.18.0' }
    [PSCustomObject]@{ Version = '2.3.20.0';  EOLDate = (Get-Date '2025-04-30'); Note = 'Aligned with security change released in 2.4.18.0' }
    [PSCustomObject]@{ Version = '2.4.18.0';  EOLDate = (Get-Date '2025-10-09'); Note = '12 months after release of 2.4.21.0' }
    [PSCustomObject]@{ Version = '2.4.21.0';  EOLDate = (Get-Date '2025-11-15'); Note = '12 months after release of 2.4.27.0' }
    [PSCustomObject]@{ Version = '2.4.27.0';  EOLDate = (Get-Date '2026-01-15'); Note = '12 months after release of 2.4.129.0' }
    [PSCustomObject]@{ Version = '2.4.129.0'; EOLDate = (Get-Date '2026-03-27'); Note = '12 months after release of 2.4.131.0' }
    [PSCustomObject]@{ Version = '2.4.131.0'; EOLDate = (Get-Date '2026-05-26'); Note = '12 months after release of 2.5.3.0' }
    [PSCustomObject]@{ Version = '2.5.3.0';   EOLDate = (Get-Date '2026-07-31'); Note = '12 months after release of 2.5.76.0' }
    [PSCustomObject]@{ Version = '2.5.76.0';  EOLDate = (Get-Date '2026-09-01'); Note = '12 months after release of 2.5.79.0' }
    [PSCustomObject]@{ Version = '2.5.79.0';  EOLDate = (Get-Date '2026-10-23'); Note = '12 months after release of 2.5.190.0' }
    [PSCustomObject]@{ Version = '2.5.190.0'; EOLDate = (Get-Date '2027-02-02'); Note = '12 months after release of 2.6.1.0' }
    [PSCustomObject]@{ Version = '2.6.1.0';   EOLDate = (Get-Date '2027-03-10'); Note = '12 months after release of 2.6.3.0' }
    [PSCustomObject]@{ Version = '2.6.3.0';   EOLDate = $null;                    Note = 'Current latest version - no End-of-Support date set yet' }
)

# ============================================================
#  HELPER: logging + status
# ============================================================
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Level] $Message"
    $Script:Log.Add($line) | Out-Null
    Write-Output $line
}

function Set-Status {
    param([string]$NewStatus)
    $rank = @{ 'PASS' = 0; 'WARN' = 1; 'FAIL' = 2 }
    if ($rank.ContainsKey($NewStatus) -and ($rank[$NewStatus] -gt $rank[$Script:OverallStatus])) {
        $Script:OverallStatus = $NewStatus
    }
}

function Test-HasProperty {
    param($Object, [string]$Name)
    return ($Object -and ($Object.PSObject.Properties.Name -contains $Name))
}

# ============================================================
#  CHECK 1 - Entra Connect Sync detection + version
# ============================================================
function Get-EntraConnectSyncInfo {
    Write-Log "=== Detecting Microsoft Entra Connect Sync ==="

    $r = [ordered]@{
        Found            = $false
        Version          = $null
        DisplayName      = $null
        InstallPath      = $null
        ServiceState     = $null
        ServiceStartMode = $null
        DetectionMethod  = $null
        MinimumRequired  = $MinimumVersion
        MeetsMinimum     = $false
        StatusNote       = ""
    }

    # ---- Method 1: ADSync service ----
    try {
        $svc = Get-Service -Name 'ADSync' -ErrorAction SilentlyContinue
        if ($svc) {
            $r.Found        = $true
            $r.ServiceState = "$($svc.Status)"
            $r.DetectionMethod = "ADSync service"
            try {
                $cim = Get-CimInstance -ClassName Win32_Service -Filter "Name='ADSync'" -ErrorAction SilentlyContinue
                if ($cim -and (Test-HasProperty $cim 'StartMode')) { $r.ServiceStartMode = "$($cim.StartMode)" }
            } catch {}
        }
    } catch {}

    # ---- Method 2: Uninstall registry (32-bit and 64-bit views) ----
    $namePatterns = @(
        'Microsoft Azure AD Connect',
        'Microsoft Entra Connect Sync',
        'Microsoft Azure Active Directory Connect',
        'Azure AD Connect Sync'
    )
    $uninstallBases = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    foreach ($base in $uninstallBases) {
        if (-not (Test-Path -LiteralPath $base)) { continue }
        try {
            $keys = Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue
            foreach ($k in $keys) {
                $prop = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
                if (-not (Test-HasProperty $prop 'DisplayName')) { continue }
                if (-not $prop.DisplayName) { continue }
                $matched = $false
                foreach ($pat in $namePatterns) {
                    if ($prop.DisplayName -like "*$pat*") { $matched = $true; break }
                }
                if (-not $matched) { continue }

                $r.Found       = $true
                $r.DisplayName = "$($prop.DisplayName)"
                if (Test-HasProperty $prop 'DisplayVersion' -and $prop.DisplayVersion) {
                    $r.Version = "$($prop.DisplayVersion)"
                }
                if (Test-HasProperty $prop 'InstallLocation' -and $prop.InstallLocation) {
                    $r.InstallPath = ("$($prop.InstallLocation)").TrimEnd('\')
                }
                $r.DetectionMethod = if ($r.DetectionMethod) {
                    "$($r.DetectionMethod) + uninstall registry"
                } else { "uninstall registry" }
                break
            }
        } catch {}
        if ($r.Version) { break }
    }

    # ---- Method 3: ADSync service binary FileVersion (cross-check / fallback) ----
    if ($r.Found -and -not $r.Version) {
        try {
            $cim = Get-CimInstance -ClassName Win32_Service -Filter "Name='ADSync'" -ErrorAction SilentlyContinue
            if ($cim -and (Test-HasProperty $cim 'PathName') -and $cim.PathName) {
                # PathName: "C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync.exe" -args...
                $exe = ($cim.PathName -replace '^"', '' -split '"\s+')[0] -replace '"', ''
                if (Test-Path -LiteralPath $exe) {
                    $fv = (Get-Item -LiteralPath $exe -ErrorAction Stop).VersionInfo.FileVersion
                    if ($fv) {
                        $r.Version = "$fv"
                        if (-not $r.InstallPath) {
                            $r.InstallPath = (Split-Path -Parent (Split-Path -Parent $exe)).TrimEnd('\')
                        }
                        $r.DetectionMethod = if ($r.DetectionMethod) {
                            "$($r.DetectionMethod) + service binary"
                        } else { "service binary" }
                    }
                }
            }
        } catch {}
    }

    # ---- Outcome ----
    if (-not $r.Found) {
        $r.StatusNote = "Entra Connect Sync not installed (no ADSync service or matching uninstall registry entry)"
        Write-Log "  WARN - Microsoft Entra Connect Sync NOT detected on this host" -Level "WARN"
        Set-Status "WARN"
        return $r
    }

    if (-not $r.Version) {
        $r.StatusNote = "Detected but version could not be determined from any source"
        Write-Log "  WARN - Entra Connect Sync detected but no version available" -Level "WARN"
        Set-Status "WARN"
        return $r
    }

    # Strip any suffix after a space (some installs include build metadata)
    $cleanVer = ($r.Version -split '\s+')[0]
    try {
        $installed = [Version]$cleanVer
        $minimum   = [Version]$MinimumVersion
        $r.MeetsMinimum = ($installed -ge $minimum)
        if ($r.MeetsMinimum) {
            Write-Log "  PASS - Entra Connect Sync $installed installed (minimum $minimum)"
            $r.StatusNote = "Version $installed meets minimum $minimum"
        } else {
            Write-Log "  FAIL - Entra Connect Sync $installed is BELOW minimum $minimum" -Level "ERROR"
            $r.StatusNote = "Version $installed is BELOW minimum $minimum"
            Set-Status "FAIL"
        }
    } catch {
        Write-Log "  WARN - Could not parse installed version '$($r.Version)': $_" -Level "WARN"
        $r.StatusNote = "Detected; version '$($r.Version)' could not be parsed against minimum"
        Set-Status "WARN"
    }

    return $r
}

# ============================================================
#  CHECK 2 - .NET Framework 4.7.2 prerequisite
# ============================================================
function Get-NetFrameworkInfo {
    Write-Log "=== Checking .NET Framework 4.7.2 prerequisite ==="

    $r = [ordered]@{
        Release        = 0
        VersionApprox  = "Unknown"
        MinRequired    = $MinNetRelease
        MinVersionName = "4.7.2"
        MeetsMinimum   = $false
        Note           = ""
    }

    try {
        $k = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction Stop
        if (Test-HasProperty $k 'Release') {
            $r.Release = [int]$k.Release
        } else {
            $r.Note = "Release value not present under NDP\v4\Full"
        }
    } catch {
        Write-Log "  Could not read .NET Framework registry: $_" -Level "ERROR"
        $r.Note = "Registry read failed: $_"
        return $r
    }

    $r.VersionApprox = switch ($r.Release) {
        { $_ -ge 533320 } { "4.8.1 or later"; break }
        { $_ -ge 528040 } { "4.8";            break }
        { $_ -ge 461808 } { "4.7.2";          break }
        { $_ -ge 461308 } { "4.7.1";          break }
        { $_ -ge 460798 } { "4.7";            break }
        { $_ -ge 394802 } { "4.6.2";          break }
        { $_ -ge 393295 } { "4.6";            break }
        default           { "below 4.6";      break }
    }
    $r.MeetsMinimum = ($r.Release -ge $MinNetRelease)
    if ($r.MeetsMinimum) {
        Write-Log "  PASS - .NET Framework $($r.VersionApprox) (Release=$($r.Release)) meets 4.7.2 minimum"
    } else {
        Write-Log "  FAIL - .NET Framework $($r.VersionApprox) (Release=$($r.Release)) is below 4.7.2 minimum (461808)" -Level "ERROR"
    }
    return $r
}

# ============================================================
#  CHECK 3 - TLS 1.2 prerequisite
# ============================================================
function Get-TLS12Info {
    Write-Log "=== Checking TLS 1.2 prerequisite ==="

    $r = [ordered]@{
        ServerEnabled            = $null
        ServerDisabledByDefault  = $null
        ClientEnabled            = $null
        ClientDisabledByDefault  = $null
        NetFwStrongCrypto64      = $null
        NetFwStrongCrypto32      = $null
        AllOK                    = $false
        Issues                   = @()
    }

    $tlsBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2'

    foreach ($side in @('Server','Client')) {
        $p = Join-Path $tlsBase $side
        try {
            $k = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
            if ($k) {
                $en  = if (Test-HasProperty $k 'Enabled')           { [int]$k.Enabled }           else { $null }
                $dis = if (Test-HasProperty $k 'DisabledByDefault') { [int]$k.DisabledByDefault } else { $null }
                if ($side -eq 'Server') {
                    $r.ServerEnabled = $en
                    $r.ServerDisabledByDefault = $dis
                } else {
                    $r.ClientEnabled = $en
                    $r.ClientDisabledByDefault = $dis
                }
            }
        } catch {}
    }

    # On supported modern Windows, TLS 1.2 is enabled by default. We only flag
    # explicit disables: Enabled=0 or DisabledByDefault=1.
    if (($null -ne $r.ServerEnabled)           -and ($r.ServerEnabled           -eq 0)) { $r.Issues += "SCHANNEL Server\Enabled = 0 (TLS 1.2 disabled for server role)" }
    if (($null -ne $r.ServerDisabledByDefault) -and ($r.ServerDisabledByDefault -eq 1)) { $r.Issues += "SCHANNEL Server\DisabledByDefault = 1 (TLS 1.2 off-by-default for server)" }
    if (($null -ne $r.ClientEnabled)           -and ($r.ClientEnabled           -eq 0)) { $r.Issues += "SCHANNEL Client\Enabled = 0 (TLS 1.2 disabled for client role)" }
    if (($null -ne $r.ClientDisabledByDefault) -and ($r.ClientDisabledByDefault -eq 1)) { $r.Issues += "SCHANNEL Client\DisabledByDefault = 1 (TLS 1.2 off-by-default for client)" }

    # .NET 4.x SchUseStrongCrypto - required = 1 in BOTH 64-bit and 32-bit paths
    foreach ($p in @(
        @{ Side = '64-bit'; Path = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' },
        @{ Side = '32-bit'; Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' }
    )) {
        try {
            $k = Get-ItemProperty -Path $p.Path -ErrorAction SilentlyContinue
            if ($k -and (Test-HasProperty $k 'SchUseStrongCrypto')) {
                if ($p.Side -eq '64-bit') { $r.NetFwStrongCrypto64 = [int]$k.SchUseStrongCrypto }
                else                       { $r.NetFwStrongCrypto32 = [int]$k.SchUseStrongCrypto }
            }
        } catch {}
    }
    if ($r.NetFwStrongCrypto64 -ne 1) { $r.Issues += ".NET 4.x SchUseStrongCrypto (64-bit) is $($r.NetFwStrongCrypto64) - required = 1" }
    if ($r.NetFwStrongCrypto32 -ne 1) { $r.Issues += ".NET 4.x SchUseStrongCrypto (32-bit WOW6432Node) is $($r.NetFwStrongCrypto32) - required = 1" }

    $r.AllOK = ($r.Issues.Count -eq 0)
    if ($r.AllOK) {
        Write-Log "  PASS - TLS 1.2 enabled in SCHANNEL (Server/Client) and .NET 4.x SchUseStrongCrypto = 1 (both paths)"
    } else {
        Write-Log "  FAIL - TLS 1.2 prerequisite has $($r.Issues.Count) issue(s):" -Level "ERROR"
        foreach ($iss in $r.Issues) { Write-Log "    - $iss" -Level "ERROR" }
    }
    return $r
}

# ============================================================
#  CHECK 4 - Rolling End-of-Support (v1.1)
#  Looks up the installed version in $Script:VersionEOLTable. Returns
#  a result hashtable with Status, EOLDate, DaysUntilEOL, and a Note.
#  Status values:
#    NOT_APPLICABLE   - no installed version to evaluate, or check skipped
#    NOT_IN_TABLE     - parsed version not present in embedded table
#                       (older than oldest tracked or unrecognised);
#                       caller treats as INFO with a refresh hint
#    NEWER_THAN_TABLE - parsed version is higher than the newest table
#                       entry; caller treats as INFO with a refresh hint
#    CURRENT_LATEST   - row found but no EOL date set (the table's
#                       newest known version, e.g. 2.6.3.0)
#    WITHIN_SUPPORT   - EOL is more than $EOLWarnDays days away
#    APPROACHING_EOL  - EOL is within $EOLWarnDays days; caller raises WARN
#    PAST_EOL         - EOL is in the past; caller raises FAIL
# ============================================================
function Get-EntraConnectSyncEOL {
    param(
        [string] $InstalledVersion,
        [int]    $WarnDays = 30
    )

    $r = [ordered]@{
        Applicable     = $false
        Status         = 'NOT_APPLICABLE'
        InstalledClean = $null
        EOLDate        = $null
        EOLDateText    = 'N/A'
        DaysUntilEOL   = $null
        TableNote      = ''
        Note           = ''
    }

    if (-not $InstalledVersion) {
        $r.Note = 'No installed version available to evaluate'
        return $r
    }

    $cleanVer = ($InstalledVersion -split '\s+')[0]
    try {
        $iv = [Version]$cleanVer
        $r.InstalledClean = $iv.ToString()
    } catch {
        $r.Status = 'NOT_IN_TABLE'
        $r.Applicable = $true
        $r.Note = "Installed version '$InstalledVersion' could not be parsed against the embedded table"
        return $r
    }

    $r.Applicable = $true

    # Try to find the exact row in the table (compare as System.Version
    # to handle padding differences like 2.5.79 vs 2.5.79.0).
    $match = $null
    foreach ($row in $Script:VersionEOLTable) {
        try {
            $rowVer = [Version]$row.Version
            if ($rowVer -eq $iv) { $match = $row; break }
        } catch {}
    }

    if (-not $match) {
        # Determine whether the installed version is newer than the newest
        # tracked entry (NEWER_THAN_TABLE) or just absent for some other
        # reason (NOT_IN_TABLE - rare; should only happen for very old
        # builds outside the published 2.x history).
        $tableVersions = foreach ($row in $Script:VersionEOLTable) {
            try { [Version]$row.Version } catch { $null }
        }
        $newest = $tableVersions | Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1
        if ($newest -and ($iv -gt $newest)) {
            $r.Status = 'NEWER_THAN_TABLE'
            $r.Note   = "Installed version $iv is newer than the embedded table's newest entry ($newest). Refresh the embedded `$Script:VersionEOLTable from the Microsoft docs page and bump `$Script:VersionDataAsOf."
        } else {
            $r.Status = 'NOT_IN_TABLE'
            $r.Note   = "Installed version $iv is not in the embedded table (table covers $($Script:VersionEOLTable.Count) version(s); refresh from Microsoft docs if this is unexpected)."
        }
        return $r
    }

    $r.TableNote = "$($match.Note)"
    if ($null -eq $match.EOLDate) {
        $r.Status = 'CURRENT_LATEST'
        $r.Note   = "Version $iv is the table's newest entry; no End-of-Support date set yet"
        return $r
    }

    $r.EOLDate     = $match.EOLDate
    $r.EOLDateText = $match.EOLDate.ToString('yyyy-MM-dd')

    $now           = Get-Date
    $days          = [int][Math]::Floor(($match.EOLDate - $now).TotalDays)
    $r.DaysUntilEOL = $days

    if ($days -lt 0) {
        $r.Status = 'PAST_EOL'
        $r.Note   = "Version $iv passed End-of-Support on $($r.EOLDateText) ($([Math]::Abs($days)) day(s) ago)"
    } elseif ($days -le $WarnDays) {
        $r.Status = 'APPROACHING_EOL'
        $r.Note   = "Version $iv reaches End-of-Support on $($r.EOLDateText) ($days day(s) from now)"
    } else {
        $r.Status = 'WITHIN_SUPPORT'
        $r.Note   = "Version $iv is supported through $($r.EOLDateText) ($days day(s) remaining)"
    }
    return $r
}

# ============================================================
#  MAIN
# ============================================================
Write-Log "############################################################"
Write-Log " Check-EntraConnectSyncCompliance - Starting  [$Script:Version]"
Write-Log "############################################################"
Write-Log " Host       : $env:COMPUTERNAME"
Write-Log " MinVersion : $MinimumVersion"
Write-Log "############################################################"

$entra = Get-EntraConnectSyncInfo

$netfw = $null
$tls12 = $null
if ($entra.Found) {
    $netfw = Get-NetFrameworkInfo
    $tls12 = Get-TLS12Info

    if (-not $netfw.MeetsMinimum) {
        Write-Log "  FAIL - Entra Connect Sync detected but .NET Framework prerequisite is NOT met" -Level "ERROR"
        Set-Status "FAIL"
    }
    if (-not $tls12.AllOK) {
        Write-Log "  FAIL - Entra Connect Sync detected but TLS 1.2 prerequisite is NOT met" -Level "ERROR"
        Set-Status "FAIL"
    }
} else {
    Write-Log "  Skipping .NET Framework + TLS 1.2 prerequisite checks (Entra Connect Sync not installed)"
}

# ============================================================
#  CHECK 4 - Rolling End-of-Support
# ============================================================
$eol = [ordered]@{ Applicable = $false; Status = 'NOT_APPLICABLE'; EOLDateText = 'N/A'; DaysUntilEOL = $null; Note = '' }
if ($entra.Found -and $entra.Version -and -not $SkipEOLCheck) {
    Write-Log "=== Checking rolling End-of-Support (table as of $Script:VersionDataAsOf) ==="
    $eol = Get-EntraConnectSyncEOL -InstalledVersion $entra.Version -WarnDays $EOLWarnDays
    switch ($eol.Status) {
        'PAST_EOL'         {
            Write-Log "  FAIL - $($eol.Note)" -Level "ERROR"
            Set-Status "FAIL"
        }
        'APPROACHING_EOL'  {
            Write-Log "  WARN - $($eol.Note) (threshold = $EOLWarnDays days)" -Level "WARN"
            Set-Status "WARN"
        }
        'WITHIN_SUPPORT'   {
            Write-Log "  PASS - $($eol.Note)"
        }
        'CURRENT_LATEST'   {
            Write-Log "  INFO - $($eol.Note)"
        }
        'NEWER_THAN_TABLE' {
            Write-Log "  INFO - $($eol.Note)"
        }
        'NOT_IN_TABLE'     {
            Write-Log "  INFO - $($eol.Note)"
        }
        default            {
            Write-Log "  INFO - End-of-Support status: $($eol.Status); $($eol.Note)"
        }
    }
} elseif ($SkipEOLCheck) {
    Write-Log "=== Skipping rolling End-of-Support check (-SkipEOLCheck specified) ==="
} else {
    Write-Log "=== Skipping rolling End-of-Support check (Entra Connect Sync not installed or no version available) ==="
}

# ============================================================
#  REPORT
# ============================================================
$hostname  = $env:COMPUTERNAME
$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$divider   = "=" * 72
$rule      = "-" * 72

$fmtKey = { param($v) if ($null -eq $v) { '(not set - OS default applies)' } else { "$v" } }
$fmtYN  = { param($b) if ($b) { 'Yes' } else { 'No' } }

Write-Output ""
Write-Output $divider
Write-Output "  MICROSOFT ENTRA CONNECT SYNC COMPLIANCE REPORT"
Write-Output "  Status     : $Script:OverallStatus"
Write-Output "  Script     : $Script:ScriptName"
Write-Output "  Host       : $hostname"
Write-Output "  Report Time: $timestamp"
Write-Output $divider

Write-Output $rule
Write-Output "  ENTRA CONNECT SYNC"
Write-Output $rule
Write-Output ("  Detected            : {0}" -f (& $fmtYN $entra.Found))
Write-Output ("  Detection Method    : {0}" -f $(if ($entra.DetectionMethod) { $entra.DetectionMethod } else { 'N/A' }))
Write-Output ("  Display Name        : {0}" -f $(if ($entra.DisplayName)     { $entra.DisplayName }     else { 'N/A' }))
Write-Output ("  Installed Version   : {0}" -f $(if ($entra.Version)         { $entra.Version }         else { 'N/A' }))
Write-Output ("  Minimum Required    : {0}" -f $entra.MinimumRequired)
Write-Output ("  Meets Minimum       : {0}" -f $(
    if ($entra.Found) {
        if ($entra.MeetsMinimum) { 'Yes' } else { 'No  [BELOW MINIMUM]' }
    } else { 'N/A (not installed)' }
))
Write-Output ("  Service State       : {0}" -f $(if ($entra.ServiceState)     { $entra.ServiceState }     else { 'N/A' }))
Write-Output ("  Service Start Mode  : {0}" -f $(if ($entra.ServiceStartMode) { $entra.ServiceStartMode } else { 'N/A' }))
Write-Output ("  Install Path        : {0}" -f $(if ($entra.InstallPath)      { $entra.InstallPath }      else { 'N/A' }))
Write-Output ("  Note                : {0}" -f $(if ($entra.StatusNote)       { $entra.StatusNote }       else { 'N/A' }))

if ($entra.Found) {
    Write-Output $rule
    Write-Output "  .NET FRAMEWORK 4.7.2 PREREQUISITE"
    Write-Output $rule
    Write-Output ("  Registry Release    : {0}" -f $netfw.Release)
    Write-Output ("  Approx Version      : {0}" -f $netfw.VersionApprox)
    Write-Output ("  Minimum Required    : {0} ({1})" -f $netfw.MinRequired, $netfw.MinVersionName)
    Write-Output ("  Meets Minimum       : {0}" -f $(if ($netfw.MeetsMinimum) { 'Yes' } else { 'No  [PREREQ FAIL]' }))
    if ($netfw.Note) { Write-Output ("  Note                : {0}" -f $netfw.Note) }

    Write-Output $rule
    Write-Output "  TLS 1.2 PREREQUISITE"
    Write-Output $rule
    Write-Output ("  SCHANNEL Server  Enabled            : {0}" -f (& $fmtKey $tls12.ServerEnabled))
    Write-Output ("  SCHANNEL Server  DisabledByDefault  : {0}" -f (& $fmtKey $tls12.ServerDisabledByDefault))
    Write-Output ("  SCHANNEL Client  Enabled            : {0}" -f (& $fmtKey $tls12.ClientEnabled))
    Write-Output ("  SCHANNEL Client  DisabledByDefault  : {0}" -f (& $fmtKey $tls12.ClientDisabledByDefault))
    Write-Output ("  .NET 4.x SchUseStrongCrypto (64-bit): {0}" -f (& $fmtKey $tls12.NetFwStrongCrypto64))
    Write-Output ("  .NET 4.x SchUseStrongCrypto (32-bit): {0}" -f (& $fmtKey $tls12.NetFwStrongCrypto32))
    Write-Output ("  Overall TLS 1.2 OK  : {0}" -f $(if ($tls12.AllOK) { 'Yes' } else { 'No  [PREREQ FAIL]' }))
    if ($tls12.Issues.Count -gt 0) {
        Write-Output ""
        Write-Output "  TLS 1.2 issues:"
        foreach ($iss in $tls12.Issues) { Write-Output "    - $iss" }
    }
}

if ($entra.Found -and -not $SkipEOLCheck) {
    Write-Output $rule
    Write-Output "  ROLLING END-OF-SUPPORT (per Microsoft Entra Connect version history)"
    Write-Output $rule
    Write-Output ("  Version Data As Of  : {0}" -f $Script:VersionDataAsOf)
    Write-Output ("  Installed Version   : {0}" -f $(if ($eol.InstalledClean) { $eol.InstalledClean } elseif ($entra.Version) { $entra.Version } else { 'N/A' }))
    Write-Output ("  EOL Date            : {0}" -f $eol.EOLDateText)
    Write-Output ("  Days Until EOL      : {0}" -f $(if ($null -eq $eol.DaysUntilEOL) { 'N/A' } else { "$($eol.DaysUntilEOL)" }))
    Write-Output ("  WARN Threshold      : {0} day(s)" -f $EOLWarnDays)
    $statusLabel = switch ($eol.Status) {
        'PAST_EOL'         { 'PAST END-OF-SUPPORT  [FAIL]' }
        'APPROACHING_EOL'  { 'APPROACHING END-OF-SUPPORT  [WARN]' }
        'WITHIN_SUPPORT'   { 'WITHIN SUPPORT' }
        'CURRENT_LATEST'   { 'CURRENT LATEST (no EOL date set)' }
        'NEWER_THAN_TABLE' { 'NEWER THAN EMBEDDED TABLE (refresh needed)' }
        'NOT_IN_TABLE'     { 'NOT IN EMBEDDED TABLE' }
        default            { "$($eol.Status)" }
    }
    Write-Output ("  Status              : {0}" -f $statusLabel)
    if ($eol.TableNote) { Write-Output ("  Table Note          : {0}" -f $eol.TableNote) }
    if ($eol.Note)      { Write-Output ("  Detail              : {0}" -f $eol.Note) }
} elseif ($entra.Found -and $SkipEOLCheck) {
    Write-Output $rule
    Write-Output "  ROLLING END-OF-SUPPORT"
    Write-Output $rule
    Write-Output "  Skipped (-SkipEOLCheck specified). Version: $($entra.Version)"
}

Write-Output $rule
Write-Output "  EXECUTION LOG"
Write-Output $rule
foreach ($line in $Script:Log) { Write-Output "  $line" }
Write-Output ""
Write-Output $divider
Write-Output "  Overall Status : $Script:OverallStatus"
Write-Output "  Completed      : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output $divider

# ============================================================
#  EXIT CODE MAPPING (for N-central)
# ============================================================
$exit = switch ($Script:OverallStatus) {
    "PASS" { 0 }
    "WARN" { 1 }
    "FAIL" { 2 }
    default { 2 }
}
exit $exit
