# Rotate-Tor.ps1 — request fresh Tor circuits through the native ControlPort.
# Windows PowerShell 5.1 compatible. No WSL, Python, or extra modules needed.
# Never prints the authentication cookie. A new exit IP is not promised, and
# rotating never relieves a provider quota: HTTP 429 stays a provider limit.
$ErrorActionPreference = 'Stop'

$Root = Join-Path $env:LOCALAPPDATA 'Programs\TorPrivoxy'
$CookiePath = Join-Path $Root 'TorData\control_auth_cookie'
$ControlPort = 9051
$PrivoxyHttp = 8118
$CooldownSecs = 10
$StateFile = Join-Path $Root 'rotate.last'

function Get-ExitIp() {
    & curl.exe --proxy "http://127.0.0.1:$PrivoxyHttp" -s -m 30 https://check.torproject.org/api/ip
}

if (-not (Test-Path -LiteralPath $CookiePath)) { throw "cookie not found: $CookiePath" }
$cookie = [System.IO.File]::ReadAllBytes($CookiePath)
if ($cookie.Length -ne 32) { throw 'cookie must be exactly 32 bytes' }
$hex = [System.BitConverter]::ToString($cookie).Replace('-', '').ToLower()

if (Test-Path -LiteralPath $StateFile) {
    $last = [long]((Get-Content -LiteralPath $StateFile | Select-Object -First 1).Trim())
    $now = [long]([System.DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
    $wait = $CooldownSecs - ($now - $last)
    if ($wait -gt 0) { throw "NEWNYM cooldown: wait $wait more seconds" }
}

$before = Get-ExitIp
Write-Host "exit before: $before"

$client = New-Object System.Net.Sockets.TcpClient
try {
    $client.SendTimeout = 10000
    $client.ReceiveTimeout = 10000
    $iar = $client.BeginConnect('127.0.0.1', $ControlPort, $null, $null)
    if (-not $iar.AsyncWaitHandle.WaitOne(5000)) { throw "cannot reach Tor control port 127.0.0.1:$ControlPort" }
    $client.EndConnect($iar)
    $stream = $client.GetStream()
    $writer = New-Object System.IO.StreamWriter($stream)
    $writer.AutoFlush = $true
    $reader = New-Object System.IO.StreamReader($stream)
    try {
        $writer.Write("AUTHENTICATE $hex`r`n")
        $auth = $reader.ReadLine()
        if ($auth -notlike '250 *') { throw 'Tor replied to AUTHENTICATE with a non-250 code' }
        $writer.Write("SIGNAL NEWNYM`r`n")
        $sig = $reader.ReadLine()
        if ($sig -notlike '250 *') { throw 'Tor replied to NEWNYM with a non-250 code' }
        $writer.Write("QUIT`r`n")
    } finally {
        $reader.Close()
        $writer.Close()
    }
} finally { $client.Close() }

[long]([System.DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) | Set-Content -LiteralPath $StateFile
Write-Host 'NEWNYM accepted.'
Start-Sleep -Seconds 6
$after = Get-ExitIp
Write-Host "exit after:  $after"
if ($after -eq $before) {
    Write-Host 'exit unchanged: expected sometimes; existing connections keep older circuits'
} else {
    Write-Host 'exit changed'
}
