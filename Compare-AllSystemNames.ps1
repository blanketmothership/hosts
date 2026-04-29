<#
.SYNOPSIS
    Gathers every device-name value from the local OS and the N-central /
    N-able Windows Agent, compares them, and PASSes only if they all agree.

.DESCRIPTION
    Collects names from:
      - $env:COMPUTERNAME
      - [System.Net.Dns]::GetHostName()
      - Win32_ComputerSystem.Name / .DNSHostName
      - Active Directory machine name (if domain joined)
      - The N-central / N-able Windows Agent: every config file (.xml,
        .config, .ini, .json, .cfg, .txt) and every registry value under
        the agent's known hives whose field name looks like a device name
        (ApplianceName, DeviceName, AgentName, ComputerName, HostName,
        DisplayName).

    Normalizes (Trim, OrdinalIgnoreCase). If every collected name reduces
    to the same value, the script reports PASS. If any source disagrees,
    it reports FAIL and lists which source held which name.

    Designed for N-central's Run-a-Script / AMP runner:
      * Non-interactive, no prompts, no params.
      * SYSTEM-context safe (writes to C:\Windows\Temp).
      * Concise PASS/FAIL header at the top of STDOUT (N-central capture).
      * Exit codes: 0 PASS, 1 FAIL, 2 ERROR (no agent name found at all).

.NOTES
    Author : commander
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

$reportPath = 'C:\Windows\Temp\Ncentral-NameCompare.txt'

# Field names that should hold the *device's* name.
# Excludes CustomerName/SiteName/*ID variants (those are not the device name).
$deviceNameField = '(?i)^(appliance ?name|device ?name|agent ?name|computer ?name|host ?name|display ?name)$'

$samples = New-Object System.Collections.Generic.List[object]
function Add-Sample {
    param([string]$Source, [string]$Path, [string]$Field, $Value)
    if ($null -eq $Value) { return }
    $v = ([string]$Value).Trim()
    if ([string]::IsNullOrWhiteSpace($v)) { return }
    $samples.Add([pscustomobject]@{
        Source = $Source
        Path   = $Path
        Field  = $Field
        Value  = $v
    }) | Out-Null
}

# ---------- 1. Local OS names ----------
Add-Sample 'OS' 'env'                        'COMPUTERNAME'                $env:COMPUTERNAME
try { Add-Sample 'OS' 'System.Net.Dns'       'HostName'                    ([System.Net.Dns]::GetHostName()) } catch {}
try {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    Add-Sample 'OS' 'Win32_ComputerSystem'   'Name'                        $cs.Name
    Add-Sample 'OS' 'Win32_ComputerSystem'   'DNSHostName'                 $cs.DNSHostName
    if ($cs.PartOfDomain -and $cs.Domain) {
        Add-Sample 'OS' 'Win32_ComputerSystem' 'FQDN' ("{0}.{1}" -f $cs.DNSHostName, $cs.Domain)
    }
} catch {}
try {
    $kerb = & "$env:SystemRoot\System32\nltest.exe" /dsgetdc:$env:USERDNSDOMAIN 2>$null
    # We don't parse this; presence is enough to know AD is reachable.
} catch {}

# ---------- 2. N-central / N-able agent: discover install dirs via services ----------
$serviceDirs = New-Object System.Collections.Generic.HashSet[string]
try {
    Get-CimInstance Win32_Service -ErrorAction Stop |
        Where-Object {
            $_.Name        -match '(?i)n[-_ ]?able|n[-_ ]?central|windows ?agent|mspplatform|getsupport' -or
            $_.DisplayName -match '(?i)n[-_ ]?able|n[-_ ]?central|windows ?agent|mspplatform|getsupport'
        } |
        ForEach-Object {
            if ($_.PathName) {
                $exe = ($_.PathName -replace '^"([^"]+)".*','$1') -replace '\s+(/|-).*$',''
                if (Test-Path -LiteralPath $exe) {
                    [void]$serviceDirs.Add((Split-Path -Parent $exe))
                }
            }
        }
} catch {}

# ---------- 3. N-central / N-able agent: filesystem sweep ----------
$fsRoots = @(
    'C:\Program Files\N-able Technologies',
    'C:\Program Files (x86)\N-able Technologies',
    'C:\Program Files\MspPlatform',
    'C:\Program Files (x86)\MspPlatform',
    'C:\Program Files\N-central',
    'C:\Program Files (x86)\N-central',
    'C:\ProgramData\N-able Technologies',
    'C:\ProgramData\MspPlatform',
    'C:\ProgramData\GetSupportService_N-Central',
    'C:\ProgramData\SolarWinds MSP'
) + @($serviceDirs)

$fsRoots = $fsRoots |
    Where-Object { $_ -and (Test-Path -LiteralPath $_) } |
    Select-Object -Unique

foreach ($root in $fsRoots) {
    Get-ChildItem -LiteralPath $root -Recurse -File -Force `
                  -Include *.xml,*.config,*.ini,*.json,*.cfg,*.txt `
                  -ErrorAction SilentlyContinue |
        ForEach-Object {
            if ($_.Length -gt 2MB) { return }
            $file = $_.FullName
            $content = $null
            try { $content = Get-Content -LiteralPath $file -Raw -ErrorAction Stop } catch { return }
            if (-not $content) { return }

            # XML <Field>value</Field>
            foreach ($m in [regex]::Matches($content, '(?im)<\s*([A-Za-z0-9_:\-]+)[^>]*>([^<]+)</\s*\1\s*>')) {
                if ($m.Groups[1].Value -match $deviceNameField) {
                    Add-Sample 'Agent-File' $file $m.Groups[1].Value $m.Groups[2].Value
                }
            }
            # XML attribute Field="value"
            foreach ($m in [regex]::Matches($content, '(?im)\b([A-Za-z0-9_:\-]+)\s*=\s*"([^"]+)"')) {
                if ($m.Groups[1].Value -match $deviceNameField) {
                    Add-Sample 'Agent-File' $file $m.Groups[1].Value $m.Groups[2].Value
                }
            }
            # JSON "Field": "value"
            foreach ($m in [regex]::Matches($content, '(?im)"([A-Za-z0-9_]+)"\s*:\s*"([^"]+)"')) {
                if ($m.Groups[1].Value -match $deviceNameField) {
                    Add-Sample 'Agent-File' $file $m.Groups[1].Value $m.Groups[2].Value
                }
            }
            # INI Field=value
            foreach ($m in [regex]::Matches($content, '(?im)^\s*([A-Za-z0-9_]+)\s*=\s*([^\r\n]+)')) {
                if ($m.Groups[1].Value -match $deviceNameField) {
                    Add-Sample 'Agent-File' $file $m.Groups[1].Value $m.Groups[2].Value
                }
            }
        }
}

# ---------- 4. N-central / N-able agent: registry sweep ----------
$regRoots = @(
    'HKLM:\SOFTWARE\N-able Technologies',
    'HKLM:\SOFTWARE\WOW6432Node\N-able Technologies',
    'HKLM:\SOFTWARE\N-central',
    'HKLM:\SOFTWARE\WOW6432Node\N-central',
    'HKLM:\SOFTWARE\SolarWinds MSP',
    'HKLM:\SOFTWARE\WOW6432Node\SolarWinds MSP',
    'HKLM:\SOFTWARE\MspPlatform',
    'HKLM:\SOFTWARE\WOW6432Node\MspPlatform'
)
foreach ($root in $regRoots) {
    if (-not (Test-Path -LiteralPath $root)) { continue }
    Get-ChildItem -LiteralPath $root -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object {
            $key = $_
            $props = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
            if (-not $props) { return }
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -like 'PS*') { continue }
                if ($p.Name -match $deviceNameField) {
                    Add-Sample 'Agent-Reg' $key.PSPath $p.Name $p.Value
                }
            }
        }
}

# ---------- 5. Compare ----------
# Use a short-name view (strip any FQDN suffix) to compare apples to apples,
# but keep the original value in the report so mismatches are obvious.
function Get-ShortName([string]$s) {
    if ([string]::IsNullOrWhiteSpace($s)) { return $s }
    return ($s -split '\.')[0]
}

foreach ($s in $samples) {
    $s | Add-Member -NotePropertyName ShortName -NotePropertyValue (Get-ShortName $s.Value) -Force
}

$agentSamples = $samples | Where-Object { $_.Source -like 'Agent-*' }
$osSamples    = $samples | Where-Object { $_.Source -eq  'OS' }

# Distinct device names across ALL sources, case-insensitive.
$distinctNames = $samples |
    Select-Object -ExpandProperty ShortName |
    Sort-Object -Unique -CaseSensitive:$false

# ---------- 6. Render report ----------
$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("N-central system-name consistency check")
[void]$sb.AppendLine("Computer : $env:COMPUTERNAME")
[void]$sb.AppendLine("RunAs    : $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)")
[void]$sb.AppendLine("RunAt    : $(Get-Date -Format s)")
[void]$sb.AppendLine(("=" * 72))

if ($agentSamples.Count -eq 0) {
    [void]$sb.AppendLine("RESULT: ERROR -- no N-central / N-able agent name was located on this endpoint.")
    [void]$sb.AppendLine("Cannot compare without an agent-side name. The agent may not be installed,")
    [void]$sb.AppendLine("or it stores its name in a location this script does not yet know about.")
    $exitCode = 2
} elseif ($distinctNames.Count -le 1) {
    [void]$sb.AppendLine("RESULT: PASS -- every name source agrees.")
    [void]$sb.AppendLine("Agreed name: $($distinctNames[0])")
    $exitCode = 0
} else {
    [void]$sb.AppendLine("RESULT: FAIL -- name sources DISAGREE.")
    [void]$sb.AppendLine("Distinct names found ($($distinctNames.Count)):")
    foreach ($n in $distinctNames) { [void]$sb.AppendLine("  - $n") }
    $exitCode = 1
}

[void]$sb.AppendLine("")
[void]$sb.AppendLine("Detail:")
[void]$sb.AppendLine(("-" * 72))
[void]$sb.AppendLine(("{0,-12} {1,-18} {2,-50} {3}" -f 'Source','Field','Path','Value'))
foreach ($s in ($samples | Sort-Object Source, Field, Path)) {
    $pathDisp = if ($s.Path.Length -gt 50) { '...' + $s.Path.Substring($s.Path.Length - 47) } else { $s.Path }
    [void]$sb.AppendLine(("{0,-12} {1,-18} {2,-50} {3}" -f $s.Source, $s.Field, $pathDisp, $s.Value))
}

# Mismatch breakdown when we failed.
if ($exitCode -eq 1) {
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("Mismatch breakdown:")
    foreach ($g in ($samples | Group-Object ShortName | Sort-Object Count -Descending)) {
        [void]$sb.AppendLine("  '$($g.Name)' x$($g.Count):")
        foreach ($row in $g.Group) {
            [void]$sb.AppendLine(("    {0,-12} {1,-18} {2}" -f $row.Source, $row.Field, $row.Path))
        }
    }
}

$report = $sb.ToString()
try { $report | Out-File -LiteralPath $reportPath -Encoding UTF8 -Force } catch {}
Write-Output $report
Write-Output ""
Write-Output "Full report saved to: $reportPath"
exit $exitCode
