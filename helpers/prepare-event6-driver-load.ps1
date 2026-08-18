Write-Host "Event 6 helper: driver load guidance" -ForegroundColor Green
Write-Host ""
Write-Host "This helper tries to mirror the old SysmonSimulator guidance by toggling Defender real-time protection." -ForegroundColor Yellow
Write-Host "Requirements: Administrator rights, Defender present, and Tamper Protection not blocking the change." -ForegroundColor Yellow
Write-Host ""
try {
    $preference = Get-MpPreference -ErrorAction Stop
    Write-Host ("Current DisableRealtimeMonitoring: {0}" -f $preference.DisableRealtimeMonitoring)
    Write-Host "Disabling real-time monitoring for 5 seconds..."
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
    Start-Sleep -Seconds 5
    Write-Host "Re-enabling real-time monitoring..."
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
    Write-Host "Helper completed. Check Sysmon Event ID 6 for WdNisDrv.sys or related Defender driver loads." -ForegroundColor Green
} catch {
    Write-Host "Helper could not toggle Defender settings." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""
    Write-Host "Manual fallback:" -ForegroundColor Yellow
    Write-Host "  1. Open Windows Security > Virus & threat protection > Manage settings"
    Write-Host "  2. Disable Real-time protection"
    Write-Host "  3. Re-enable Real-time protection"
}
