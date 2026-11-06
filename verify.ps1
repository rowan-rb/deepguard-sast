Write-Host "Starting DeepGuard Verification..." -ForegroundColor Cyan

Write-Host "`n[1] Running Unit Tests (pytest)..." -ForegroundColor Yellow
pytest tests/ -v

Write-Host "`n[2] Running Precision/Recall Benchmark..." -ForegroundColor Yellow
python benchmark.py

Write-Host "`n[3] Running CLI against vulnerable example..." -ForegroundColor Yellow
deepguard scan examples/vulnerable_code.py

if ($LASTEXITCODE -eq 1) {
    Write-Host "`nNOTE: Exit code 1 is expected for the CLI scan because it found vulnerabilities." -ForegroundColor DarkGray
}

Write-Host "`nDeepGuard Verification Complete." -ForegroundColor Cyan