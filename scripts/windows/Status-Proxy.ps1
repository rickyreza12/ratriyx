# Status-Proxy.ps1 — report native Windows Tor/Privoxy state for Ratriyx.
# Windows PowerShell 5.1 compatible. Read-only: starts, stops, or edits nothing.
$ErrorActionPreference = 'Stop'

$TorSocks = 9050
$PrivoxyHttp = 8118

function Test-Port($Port) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        $connected = $iar.AsyncWaitHandle.WaitOne(2000)
        return ($connected -and $client.Connected)
    } catch { return $false } finally { $client.Close() }
}

$torUp = Test-Port $TorSocks
$privoxyUp = Test-Port $PrivoxyHttp
Write-Host "tor SOCKS 127.0.0.1:$TorSocks listening: $torUp"
Write-Host "privoxy HTTP 127.0.0.1:$PrivoxyHttp listening: $privoxyUp"

if ($privoxyUp) {
    try {
        $direct = & curl.exe --noproxy '*' -s -m 15 https://api.ipify.org
        Write-Host "direct: $direct"
    } catch { Write-Host 'direct check failed' }
    try {
        $proxied = & curl.exe --proxy "http://127.0.0.1:$PrivoxyHttp" -s -m 30 https://check.torproject.org/api/ip
        Write-Host "proxied: $proxied"
    } catch { Write-Host 'proxied check failed' }
} else {
    Write-Host 'proxied check skipped: Privoxy is not listening'
}

if (-not ($torUp -and $privoxyUp)) { exit 1 }
