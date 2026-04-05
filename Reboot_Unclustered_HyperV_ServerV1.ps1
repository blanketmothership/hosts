<#
.SYNOPSIS
    Gracefully shuts down all Hyper-V guest VMs, then reboots the host.

.NOTES
    - Requires Hyper-V Integration Services installed on each guest VM
    - Run with elevated privileges
    - Designed for N-Central "Run a Script" deployment
    - Will not run on clustered Hyper-V hosts
#>

# Configuration
$TimeoutSeconds = 300  # Max wait time for VMs to shut down (5 minutes)
$PollInterval   = 10   # How often to check VM state (seconds)

# ------------------------------------------------------------------
# Cluster check — abort if this host is a cluster node
# ------------------------------------------------------------------
$ClusterService = Get-Service -Name "ClusSvc" -ErrorAction SilentlyContinue

if ($ClusterService -and $ClusterService.Status -eq 'Running') {
    Write-Output "ABORTED: This host is a member of a Windows Failover Cluster."
    Write-Output "Use Cluster Manager to properly migrate roles before rebooting."
    Exit 1
}

# ------------------------------------------------------------------
# Get all running VMs
# ------------------------------------------------------------------
$RunningVMs = Get-VM | Where-Object { $_.State -eq 'Running' }

if ($RunningVMs.Count -eq 0) {
    Write-Output "No running VMs found. Proceeding to reboot host."
} else {
    Write-Output "Found $($RunningVMs.Count) running VM(s). Sending graceful shutdown..."

    foreach ($VM in $RunningVMs) {
        Write-Output "  Shutting down: $($VM.Name)"
        Stop-VM -Name $VM.Name
    }

    # Wait for all VMs to reach 'Off' state
    $Elapsed = 0
    while ($Elapsed -lt $TimeoutSeconds) {
        $StillRunning = Get-VM | Where-Object { $_.State -ne 'Off' }

        if ($StillRunning.Count -eq 0) {
            Write-Output "All VMs have shut down successfully."
            break
        }

        Write-Output "Waiting on $($StillRunning.Count) VM(s)... ($Elapsed seconds elapsed)"
        Start-Sleep -Seconds $PollInterval
        $Elapsed += $PollInterval
    }

    # Check if any VMs are still running after timeout
    $StillRunning = Get-VM | Where-Object { $_.State -ne 'Off' }
    if ($StillRunning.Count -gt 0) {
        Write-Output "WARNING: The following VMs did not shut down within $TimeoutSeconds seconds:"
        $StillRunning | ForEach-Object { Write-Output "  - $($_.Name) [$($_.State)]" }
        Write-Output "Aborting reboot to prevent data loss. Please investigate."
        Exit 1
    }
}

# ------------------------------------------------------------------
# Reboot the host
# ------------------------------------------------------------------
Write-Output "All VMs are off. Rebooting Hyper-V host now..."
Restart-Computer