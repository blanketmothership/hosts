<#
.SYNOPSIS
    Removes the Windows Update "TargetReleaseVersionInfo" feature-update pin on Windows 11.

.DESCRIPTION
    1. Confirms the device is Windows 11 (build 22000 or higher, client OS).
       If it is NOT Windows 11, the script exits 0 and makes no changes.
    2. Looks for the TargetReleaseVersionInfo value under
       HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate.
    3. If that value exists, deletes ONLY that value. All other values are left intact.

    Built for N-central deployment:
        Exit 0 = ran successfully (deleted, nothing to delete, or not Windows 11)
        Exit 1 = failure (registry error or insufficient rights)

.NOTES
    Run as SYSTEM / Administrator (default when deployed via N-central).
    Note: the correct Windows Update value name is "TargetReleaseVersionInfo".
#>

$ErrorActionPreference = 'Stop'

$RegPath   = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$ValueName = 'TargetReleaseVersionInfo'

function Write-Log {
    param([string]$Message)
    Write-Output ('[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message)
}

try {
    # --- Step 1: Confirm the OS is Windows 11 -------------------------------
    $cv          = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build       = [int]$cv.CurrentBuildNumber
    $installType = $cv.InstallationType   # 'Client' on workstations, 'Server' on servers
    $displayVer  = $cv.DisplayVersion
    $productName = $cv.ProductName

    Write-Log ("Detected OS: {0} | Build {1} | Version {2} | InstallationType {3}" -f `
        $productName, $build, $displayVer, $installType)

    # Windows 11 = client OS with build 22000 or higher.
    if ($installType -ne 'Client' -or $build -lt 22000) {
        Write-Log 'Device is not Windows 11. No action taken.'
        exit 0
    }
    Write-Log 'Confirmed Windows 11.'

    # --- Step 2: Check for the registry value ------------------------------
    if (-not (Test-Path -Path $RegPath)) {
        Write-Log ("Registry key not found: {0}. Nothing to remove." -f $RegPath)
        exit 0
    }

    $existingValues = (Get-Item -Path $RegPath).Property
    if ($existingValues -notcontains $ValueName) {
        Write-Log ("Value '{0}' is not present. Nothing to remove." -f $ValueName)
        exit 0
    }

    $currentData = (Get-ItemProperty -Path $RegPath -Name $ValueName).$ValueName
    Write-Log ("Found '{0}' = '{1}'." -f $ValueName, $currentData)

    # Deleting under HKLM:\SOFTWARE\Policies requires admin / SYSTEM rights.
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Log 'ERROR: Administrator / SYSTEM rights are required to delete this value.'
        exit 1
    }

    # --- Step 3: Delete only that value ------------------------------------
    Remove-ItemProperty -Path $RegPath -Name $ValueName -Force
    Write-Log ("Deleted value '{0}'." -f $ValueName)

    # Verify removal
    if ((Get-Item -Path $RegPath).Property -contains $ValueName) {
        Write-Log ("ERROR: '{0}' is still present after the delete attempt." -f $ValueName)
        exit 1
    }

    Write-Log ("Successfully removed '{0}'." -f $ValueName)
    exit 0
}
catch {
    Write-Log ("ERROR: {0}" -f $_.Exception.Message)
    exit 1
}
