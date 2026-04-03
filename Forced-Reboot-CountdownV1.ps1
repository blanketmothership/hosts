# ============================================================
#  Forced Reboot with 15-Minute Countdown
#  N-central: Run a Script (Run As: Local System)
# ============================================================

$CountdownMinutes = 15
$CompanyName      = "IT Support"
$Reason           = "A required maintenance restart has been scheduled by your IT team."

# ── Notify users and start shutdown timer ────────────────────
$RebootAt      = (Get-Date).AddMinutes($CountdownMinutes)
$RebootAtStr   = $RebootAt.ToString("h:mm tt")
$TotalSeconds  = $CountdownMinutes * 60

$InitialMsg = "$Reason`n`nYour computer will RESTART at $RebootAtStr ($CountdownMinutes minutes).`n`nPlease SAVE ALL OPEN WORK now.`n`n— $CompanyName"

# Show message to all logged-in users
& msg.exe * /TIME:60 "$InitialMsg" 2>$null

# Register the shutdown timer (also shows tray balloon on modern Windows)
& shutdown.exe /r /f /t $TotalSeconds /c "Maintenance restart by $CompanyName. Rebooting at $RebootAtStr. Please save your work." 2>$null

Write-Host "Reboot scheduled for $RebootAtStr. Countdown started."

# ── Send reminders at key intervals ─────────────────────────
$Reminders = @(10, 5, 2, 1)   # Minutes before reboot to send a reminder

foreach ($Reminder in $Reminders) {
    $WaitUntil = $RebootAt.AddMinutes(-$Reminder)
    $SecondsToWait = ($WaitUntil - (Get-Date)).TotalSeconds

    if ($SecondsToWait -gt 0) {
        Start-Sleep -Seconds $SecondsToWait
        $Label = if ($Reminder -eq 1) { "1 MINUTE" } else { "$Reminder MINUTES" }
        $ReminderMsg = "RESTART REMINDER: Your computer will reboot in $Label (at $RebootAtStr).`n`nSAVE YOUR WORK NOW.`n`n— $CompanyName"
        & msg.exe * /TIME:55 "$ReminderMsg" 2>$null
        Write-Host "Reminder sent: $Reminder minute(s) remaining."
    }
}

# ── Wait for reboot time, then force immediately ─────────────
$FinalWait = ($RebootAt - (Get-Date)).TotalSeconds
if ($FinalWait -gt 0) { Start-Sleep -Seconds $FinalWait }

& msg.exe * /TIME:10 "RESTARTING NOW. Your computer is rebooting immediately." 2>$null
Start-Sleep -Seconds 5

# Abort the scheduled shutdown and force reboot now
& shutdown.exe /a 2>$null
Start-Sleep -Seconds 2
& shutdown.exe /r /f /t 0 /c "Forced maintenance restart by $CompanyName."

Write-Host "Reboot command issued."
