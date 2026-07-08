# =============================================================================
# Set-Win11-TargetRelease.ps1
# Pins Windows 11 devices to a specific feature release via the Windows Update
# for Business "Select target feature update version" policy keys, then runs a
# SEARCH-ONLY Windows Update scan (nothing is downloaded or installed).
#
# Deploy via N-central (runs as SYSTEM). Windows PowerShell 5.1 compatible.
# NOTE: the scan can take several minutes - set the N-central script/task
#       timeout to at least 15 minutes.
#
# Logic:
#   1. Verify OS is Windows 11 (client SKU, build >= 22000). If not, exit 0.
#   2. If ProductVersion exists           -> set to "Windows 11"
#   3. If TargetReleaseVersionInfo exists -> set to "25H2"
#      (missing values are reported, NOT created)
#   4. If both values are in place        -> set TargetReleaseVersion (DWORD)=1
#      (required, or Windows ignores the two values above)
#   5. Scan Windows Update for applicable updates (search only) and list them,
#      flagging the 25H2 feature update if offered.
#
# Exit codes: 0 = success/skipped, 1 = unexpected error,
#             2 = value(s) missing (only when $FailIfMissing = $true)
# =============================================================================

# ---- Configuration ----------------------------------------------------------
$TargetProductVersion = 'Windows 11'
$TargetReleaseInfo    = '25H2'
$FailIfMissing        = $false   # $true = exit 2 when a value is absent, so the device is flagged in N-central job results
$RunUpdateScan        = $true    # $false = skip the Windows Update scan
$PolicyPath           = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'

$script:ExitCode = 0

function Write-Log {
    param([string]$Message)
    Write-Output ("[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message)
}

try {
    # ---- 1. Windows 11 check -------------------------------------------------
    $os    = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $build = [int]$os.BuildNumber

    # ProductType 1 = workstation; build 22000+ = Windows 11 era.
    # (ProductType check matters: Server 2025 is also build 26100+.)
    if ($os.ProductType -ne 1 -or $build -lt 22000) {
        Write-Log "OS is '$($os.Caption)' (build $build) - not Windows 11. No changes made."
        exit 0
    }
    Write-Log "Detected '$($os.Caption)' (build $build). Proceeding."

    # Current feature release (e.g. 24H2) - used to explain scan results
    $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
    $currentRelease = if ($cv.DisplayVersion) { $cv.DisplayVersion } else { $cv.ReleaseId }
    Write-Log "Current feature release: $currentRelease (target: $TargetReleaseInfo)"

    # ---- 2/3. Update values only if they already exist ------------------------
    $allSet = $true

    if (Test-Path -Path $PolicyPath) {
        $existingValues = (Get-Item -Path $PolicyPath).GetValueNames()

        $targets = @(
            @{ Name = 'ProductVersion';           Value = $TargetProductVersion },
            @{ Name = 'TargetReleaseVersionInfo'; Value = $TargetReleaseInfo }
        )

        foreach ($t in $targets) {
            if ($existingValues -contains $t.Name) {
                $before = (Get-ItemProperty -Path $PolicyPath -Name $t.Name).($t.Name)
                # New-ItemProperty -Force overwrites and enforces REG_SZ type
                New-ItemProperty -Path $PolicyPath -Name $t.Name -Value $t.Value -PropertyType String -Force | Out-Null
                Write-Log "$($t.Name): '$before' -> '$($t.Value)'"
            }
            else {
                Write-Log "WARNING: $($t.Name) not present - skipped (not created by design)."
                $allSet = $false
                if ($FailIfMissing) { $script:ExitCode = 2 }
            }
        }

        # ---- 4. Enable flag ----------------------------------------------------
        if ($allSet) {
            New-ItemProperty -Path $PolicyPath -Name 'TargetReleaseVersion' -Value 1 -PropertyType DWord -Force | Out-Null
            Write-Log "TargetReleaseVersion (enable flag) = 1. Device pinned to $TargetProductVersion $TargetReleaseInfo."
        }
        else {
            Write-Log "Enable flag NOT set - target values incomplete; pin left inactive."
        }
    }
    else {
        Write-Log "WARNING: Policy key not found: $PolicyPath - skipping registry updates."
        $allSet = $false
        if ($FailIfMissing) { $script:ExitCode = 2 }
    }

    # ---- 5. Windows Update scan (SEARCH ONLY - no download, no install) -------
    if ($RunUpdateScan) {
        Write-Log "Starting Windows Update scan (search only, may take several minutes)..."
        try {
            $session  = New-Object -ComObject 'Microsoft.Update.Session'
            $searcher = $session.CreateUpdateSearcher()

            # Applicable, not yet installed, not hidden. Search() only queries -
            # it never downloads or installs anything.
            $result = $searcher.Search('IsInstalled=0 and IsHidden=0')

            $featureOffered = $false

            if ($result.Updates.Count -eq 0) {
                Write-Log "Scan complete: no applicable updates found."
            }
            else {
                Write-Log "Scan complete: $($result.Updates.Count) applicable update(s) found:"
                foreach ($u in $result.Updates) {
                    $kb = ''
                    if ($u.KBArticleIDs.Count -gt 0) { $kb = " (KB$(@($u.KBArticleIDs)[0]))" }
                    Write-Log "  - $($u.Title)$kb"
                    if ($u.Title -match [regex]::Escape($TargetReleaseInfo)) { $featureOffered = $true }
                }
            }

            # Explicit feature-update status, logged on every scan outcome
            if ($featureOffered) {
                Write-Log "FEATURE UPDATE STATUS: $TargetProductVersion $TargetReleaseInfo IS OFFERED to this device."
            }
            elseif ($currentRelease -eq $TargetReleaseInfo) {
                Write-Log "FEATURE UPDATE STATUS: device is already on $TargetReleaseInfo - nothing to offer."
            }
            else {
                Write-Log "FEATURE UPDATE STATUS: $TargetReleaseInfo NOT offered in this scan (device on $currentRelease; not yet released to this device or blocked by a safeguard hold)."
            }
        }
        catch {
            Write-Log "WARNING: Update scan failed: $($_.Exception.Message)"
        }
    }

    exit $script:ExitCode
}
catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    exit 1
}
