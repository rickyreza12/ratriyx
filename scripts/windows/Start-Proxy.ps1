# Start-Proxy.ps1 — start native Windows Tor and Privoxy for Ratriyx.
# Windows PowerShell 5.1 compatible. No WSL, Python, or extra modules needed.
# Run in Windows PowerShell (not WSL): powershell.exe -File Start-Proxy.ps1
$ErrorActionPreference = 'Stop'

$Root = Join-Path $env:LOCALAPPDATA 'Programs\TorPrivoxy'
$TorExe = Join-Path $Root 'tor.exe'
$Torrc = Join-Path $Root 'torrc'
$TorData = Join-Path $Root 'TorData'
$PrivoxyExe = Join-Path $Root 'privoxy.exe'
$PrivoxyConf = Join-Path $Root 'privoxy.conf'
$TorPidFile = Join-Path $Root 'tor.pid'
$PrivoxyPidFile = Join-Path $Root 'privoxy.pid'

function Test-PortFree($Port) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        $connected = $iar.AsyncWaitHandle.WaitOne(1000)
        if ($connected -and $client.Connected) { return $false }
        return $true
    } catch { return $true } finally { $client.Close() }
}

foreach ($f in @($TorExe, $Torrc, $PrivoxyExe, $PrivoxyConf)) {
    if (-not (Test-Path -LiteralPath $f)) { throw "missing required file: $f" }
}
if (-not (Test-Path -LiteralPath $TorData)) {
    New-Item -ItemType Directory -Path $TorData | Out-Null
}
if (-not (Test-PortFree 9050)) { throw 'port 9050 is already in use; stop the owner first (never kill by port blindly)' }
if (-not (Test-PortFree 8118)) { throw 'port 8118 is already in use; stop the owner first (never kill by port blindly)' }

$tor = Start-Process -FilePath $TorExe -ArgumentList @('-f', $Torrc) -PassThru -WindowStyle Hidden
$tor.Id | Set-Content -LiteralPath $TorPidFile
$privoxy = Start-Process -FilePath $PrivoxyExe -ArgumentList @($PrivoxyConf) -PassThru -WindowStyle Hidden
$privoxy.Id | Set-Content -LiteralPath $PrivoxyPidFile

Start-Sleep -Seconds 3
& (Join-Path $Root 'Status-Proxy.ps1')
