Write-Host "Event 25 helper: process tampering guidance" -ForegroundColor Green
Write-Host ""
Write-Host "The original SysmonSimulator used a real process-image tampering routine." -ForegroundColor Yellow
Write-Host "This Go port does not execute that tampering path by default because it is invasive and brittle across hosts." -ForegroundColor Yellow
Write-Host ""
Write-Host "Recommended lab prerequisites:" -ForegroundColor Yellow
Write-Host "  1. Run in an isolated lab VM."
Write-Host "  2. Use Administrator rights."
Write-Host "  3. Ensure Sysmon Event ID 25 is enabled in your configuration."
Write-Host "  4. Use disposable target/source binaries only."
Write-Host ""
Write-Host "Suggested defaults from sysmonsim-go:" -ForegroundColor Green
Write-Host "  Source image : C:\Windows\System32\cmd.exe"
Write-Host "  Target image : C:\Windows\System32\svchost.exe"
Write-Host ""
Write-Host "Next step for this project is to add an explicit --dangerous implementation for event 25 once the operator is ready to test it in a lab." -ForegroundColor Yellow
