# Stop-Proxy.ps1 — stop the Tor and Privoxy processes started by Start-Proxy.ps1.
# Windows PowerShell 5.1 compatible. Stops only processes tracked in PID files.
$ErrorActionPreference = 'Stop'

$Root = Join-Path $env:LOCALAPPDATA 'Programs\TorPrivoxy'

function Stop-Tracked($PidFile, $Name) {
    if (-not (Test-Path -LiteralPath $PidFile)) {
        Write-Host "$Name: no PID file; nothing tracked to stop"
        return
    }
    $id = (Get-Content -LiteralPath $PidFile | Select-Object -First 1).Trim()
    Remove-Item -LiteralPath $PidFile -ErrorAction SilentlyContinue
    if ($id -match '^\d+$') {
        $proc = Get-Process -Id ([int]$id) -ErrorAction SilentlyContinue
        if ($null -ne $proc) {
            Stop-Process -Id ([int]$id) -Force
            Write-Host "$Name (PID $id): stopped"
        } else {
            Write-Host "$Name (PID $id): already gone"
        }
    } else {
        Write-Host "$Name: PID file did not contain a process ID; nothing stopped"
    }
}

Stop-Tracked (Join-Path $Root 'privoxy.pid') 'Privoxy'
Stop-Tracked (Join-Path $Root 'tor.pid') 'Tor'
