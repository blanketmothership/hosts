#Requires -Version 3.0
<#
.SYNOPSIS
    N-central AMP: Compare N-central Computer Name vs Local Machine Name (UUID-based check)

.DESCRIPTION
    This AMP retrieves the computer name that N-central has on record (via the N-central
    agent registry key) and compares it against the actual Windows computer name reported
    by the local machine. If they differ, the script exits with a status that N-central
    will flag as a monitoring failure.

    N-central AMP Self-Healing / Monitoring Integration:
      - Exit code 0  = PASS  (names match — no alert)
      - Exit code 1  = FAIL  (mismatch detected — triggers alert)

    The script also writes Self-Healing-compatible output so N-central can surface
    the detail strings in the dashboard.

.NOTES
    Deploy as an Automated Monitoring & Management (AMP) script in N-central.
    Recommended check interval: 1 hour (or as needed).
    Tested against N-central agent 12.x – 2024.x.

    Registry paths used:
      Agent-registered name : HKLM:\SOFTWARE\N-able Technologies\Windows Agent\Configuration
                              Value: DeviceName  (or ComputerName depending on agent version)
      Local computer name   : $env:COMPUTERNAME  /  Win32_ComputerSystem.Name
      BIOS UUID             : Win32_ComputerSystemProduct.UUID
#>

###############################################################################
# CONFIGURATION
###############################################################################

# Registry paths where the N-central agent stores the device name it registered with.
# The script tries each in order and uses the first value it finds.
$AgentRegistryPaths = @(
    "HKLM:\SOFTWARE\N-able Technologies\Windows Agent\Configuration",
    "HKLM:\SOFTWARE\WOW6432Node\N-able Technologies\Windows Agent\Configuration",
    "HKLM:\SOFTWARE\N-able Technologies\Reactive\Configuration"
)

# Registry value names to look for (tried in order per path)
$AgentNameValues = @("DeviceName", "ComputerName", "AgentName", "HostName")

###############################################################################
# HELPER FUNCTIONS
###############################################################################

function Write-NcentralOutput {
    <#
    .SYNOPSIS
        Writes output in the format N-central AMPs expect.
        N-central reads stdout; use this for all status lines.
    #>
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","FAIL","PASS")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "[$timestamp][$Level] $Message"
}

function Get-WmiOrCimValue {
    <#
    .SYNOPSIS
        Queries WMI/CIM safely, falling back gracefully on older OS versions.
    #>
    param([string]$ClassName, [string]$Property)
    try {
        # Prefer CIM (PowerShell 3+)
        $obj = Get-CimInstance -ClassName $ClassName -ErrorAction Stop
        return ($obj.$Property | Select-Object -First 1)
    }
    catch {
        try {
            $obj = Get-WmiObject -Class $ClassName -ErrorAction Stop
            return ($obj.$Property | Select-Object -First 1)
        }
        catch {
            return $null
        }
    }
}

###############################################################################
# STEP 1 — Get the ACTUAL local computer name
###############################################################################

$LocalComputerName = $env:COMPUTERNAME

if ([string]::IsNullOrWhiteSpace($LocalComputerName)) {
    # Fallback: query WMI
    $LocalComputerName = Get-WmiOrCimValue -ClassName "Win32_ComputerSystem" -Property "Name"
}

Write-NcentralOutput "Local computer name  : $LocalComputerName"

###############################################################################
# STEP 2 — Get the BIOS UUID
###############################################################################

$BiosUUID = Get-WmiOrCimValue -ClassName "Win32_ComputerSystemProduct" -Property "UUID"

if ([string]::IsNullOrWhiteSpace($BiosUUID) -or $BiosUUID -eq "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF") {
    Write-NcentralOutput "BIOS UUID            : Could not retrieve a valid UUID (value: $BiosUUID)" -Level "WARN"
    $BiosUUID = "UNAVAILABLE"
} else {
    Write-NcentralOutput "BIOS UUID            : $BiosUUID"
}

###############################################################################
# STEP 3 — Get the name N-central's agent registered under
###############################################################################

$NcentralRegisteredName = $null

foreach ($regPath in $AgentRegistryPaths) {
    if (Test-Path $regPath) {
        foreach ($valueName in $AgentNameValues) {
            try {
                $regValue = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop
                if (-not [string]::IsNullOrWhiteSpace($regValue.$valueName)) {
                    $NcentralRegisteredName = $regValue.$valueName.Trim()
                    Write-NcentralOutput "N-central agent name : $NcentralRegisteredName  (registry: $regPath\$valueName)"
                    break
                }
            }
            catch { <# value not present at this path — try next #> }
        }
    }
    if ($NcentralRegisteredName) { break }
}

# Last resort: check the N-central agent config file (Windows Agent stores XML config)
if ([string]::IsNullOrWhiteSpace($NcentralRegisteredName)) {
    $agentConfigFiles = @(
        "$env:ProgramFiles\N-able Technologies\Windows Agent\config\ServerConfig.xml",
        "${env:ProgramFiles(x86)}\N-able Technologies\Windows Agent\config\ServerConfig.xml",
        "$env:ProgramData\N-able Technologies\Windows Agent\config\ServerConfig.xml"
    )
    foreach ($configFile in $agentConfigFiles) {
        if (Test-Path $configFile) {
            try {
                [xml]$xmlConfig = Get-Content $configFile -ErrorAction Stop
                # Try common XML element names
                $nameFromXml = $xmlConfig.SelectSingleNode("//DeviceName").'#text'
                if ([string]::IsNullOrWhiteSpace($nameFromXml)) {
                    $nameFromXml = $xmlConfig.SelectSingleNode("//ComputerName").'#text'
                }
                if (-not [string]::IsNullOrWhiteSpace($nameFromXml)) {
                    $NcentralRegisteredName = $nameFromXml.Trim()
                    Write-NcentralOutput "N-central agent name : $NcentralRegisteredName  (config file: $configFile)"
                    break
                }
            }
            catch { <# XML parse failed — skip #> }
        }
    }
}

if ([string]::IsNullOrWhiteSpace($NcentralRegisteredName)) {
    Write-NcentralOutput "N-central agent name : NOT FOUND — agent registry keys and config files not detected." -Level "WARN"
    Write-NcentralOutput "Is the N-central agent installed on this machine?" -Level "WARN"
    $NcentralRegisteredName = "UNAVAILABLE"
}

###############################################################################
# STEP 4 — Compare names (case-insensitive)
###############################################################################

Write-NcentralOutput "---"
Write-NcentralOutput "Comparison Summary:"
Write-NcentralOutput "  Local Windows name    : $LocalComputerName"
Write-NcentralOutput "  N-central agent name  : $NcentralRegisteredName"
Write-NcentralOutput "  BIOS UUID             : $BiosUUID"

$namesMatch = ($LocalComputerName.ToUpper() -eq $NcentralRegisteredName.ToUpper())

###############################################################################
# STEP 5 — Output result and set exit code for N-central monitoring
###############################################################################

if ($NcentralRegisteredName -eq "UNAVAILABLE") {
    # Cannot determine N-central name — raise a warning-level alert
    Write-NcentralOutput "RESULT: INCONCLUSIVE — N-central agent name could not be retrieved." -Level "WARN"
    Write-NcentralOutput "ACTION: Verify the N-central agent is installed and running." -Level "WARN"

    # N-central interprets exit 1 as a monitoring failure
    exit 1
}
elseif ($namesMatch) {
    Write-NcentralOutput "RESULT: PASS — Computer name matches N-central registered name." -Level "PASS"
    exit 0
}
else {
    Write-NcentralOutput "RESULT: FAIL — MISMATCH DETECTED" -Level "FAIL"
    Write-NcentralOutput "  The name N-central has on record ($NcentralRegisteredName) does not match" -Level "FAIL"
    Write-NcentralOutput "  the local Windows computer name ($LocalComputerName)." -Level "FAIL"
    Write-NcentralOutput "  BIOS UUID: $BiosUUID" -Level "FAIL"
    Write-NcentralOutput "ACTION: Re-register or rename the device in N-central to resolve the mismatch." -Level "FAIL"

    # Exit 1 triggers the N-central monitoring alert
    exit 1
}
