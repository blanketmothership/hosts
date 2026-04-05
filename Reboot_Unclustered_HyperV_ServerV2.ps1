<#
.SYNOPSIS
    Gracefully shuts down all Hyper-V guest VMs, then reboots the host.
    VMs that were running at shutdown time will be automatically started
    after the host comes back online via a scheduled startup task.

.NOTES
    - Requires Hyper-V Integration Services installed on each guest VM
    - Run with elevated privileges
    - Designed for N-Central "Run a Script" deployment
    - Will not run on clustered Hyper-V hosts
#>

# Configuration
$TimeoutSeconds  = 300   # Max wait time for VMs to shut down (5 minutes)
$PollInterval    = 10    # How often to check VM state (seconds)
$VMListFile      = "C:\Windows\Temp\HyperV_PreReboot_VMs.txt"
$StartupTaskName = "HyperV-RestoreVMs"

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
# Save list of currently running VMs to disk
# ------------------------------------------------------------------
$RunningVMs = Get-VM | Where-Object { $_.State -eq 'Running' }

if ($RunningVMs.Count -eq 0) {
    Write-Output "No running VMs found. Proceeding to reboot host."
} else {
    Write-Output "Found $($RunningVMs.Count) running VM(s). Saving list for post-reboot restore..."
    $RunningVMs | Select-Object -ExpandProperty Name | Out-File -FilePath $VMListFile -Force
    Write-Output "VM list saved to $VMListFile"

    # ------------------------------------------------------------------
    # Register a one-time scheduled task to start VMs after reboot
    # ------------------------------------------------------------------
    $TaskScript = @"
`$VMList = Get-Content -Path '$VMListFile'
foreach (`$VMName in `$VMList) {
    Start-Sleep -Seconds 30
    `$VM = Get-VM -Name `$VMName -ErrorAction SilentlyContinue
    if (`$VM -and `$VM.State -eq 'Off') {
        Start-VM -Name `$VMName
        Write-EventLog -LogName Application -Source 'HyperV-RestoreVMs' -EntryType Information -EventId 1 -Message "Started VM: `$VMName"
    }
}
# Remove the task and VM list file after running
Remove-Item -Path '$VMListFile' -Force -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName '$StartupTaskName' -Confirm:`$false
"@

    $Action    = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NonInteractive -WindowStyle Hidden -Command `"$TaskScript`""
    $Trigger   = New-ScheduledTaskTrigger -AtStartup
    $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
    $Settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 30)

    # Remove any previously registered version of this task
    Unregister-ScheduledTask -TaskName $StartupTaskName -Confirm:$false -ErrorAction SilentlyContinue

    Register-ScheduledTask -TaskName $StartupTaskName `
                           -Action $Action `
                           -Trigger $Trigger `
                           -Principal $Principal `
                           -Settings $Settings `
                           -Description "One-time task to restore VMs after planned reboot." | Out-Null

    Write-Output "Startup task '$StartupTaskName' registered successfully."

    # ------------------------------------------------------------------
    # Send graceful shutdown to each VM
    # ------------------------------------------------------------------
    Write-Output "Sending graceful shutdown to all running VMs..."
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

        # Clean up task and file since we are not rebooting
        Unregister-ScheduledTask -TaskName $StartupTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -Path $VMListFile -Force -ErrorAction SilentlyContinue
        Exit 1
    }
}

# ------------------------------------------------------------------
# Reboot the host
# ------------------------------------------------------------------
Write-Output "All VMs are off. Rebooting Hyper-V host now..."
Restart-Computer