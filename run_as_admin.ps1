# Run Adaptive Firewall with Administrator privileges for Windows Defender Firewall Kernel packet drops
Write-Host "Elevating Adaptive Firewall to Administrator for Windows Defender Firewall enforcement..." -ForegroundColor Green
Start-Process powershell -Verb RunAs -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot'; python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000"
