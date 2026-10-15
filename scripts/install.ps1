<#
.SYNOPSIS
  Installs Ratriyx from a precompiled GitHub release archive.
.DESCRIPTION
  Downloads the matching Windows archive, verifies SHA-256, installs to a
  user-writable directory, and adds it to the user PATH. Rerunning is safe.
  PowerShell 5.1 compatible. Test hooks: RATRIYX_VERSION, RATRIYX_BASE_URL,
  RATRIYX_INSTALL_DIR (all optional overrides).
#>
[CmdletBinding()]
param(
  [string]$Version = $env:RATRIYX_VERSION,
  [string]$BaseUrl = $env:RATRIYX_BASE_URL,
  [string]$InstallDir = $env:RATRIYX_INSTALL_DIR
)

$ErrorActionPreference = 'Stop'

function Fail($msg) { throw "ratriyx-install: $msg" }

if ([string]::IsNullOrWhiteSpace($Version)) {
  Fail "set -Version, e.g. Install-Ratriyx -Version 0.2.0 (or `$env:RATRIYX_VERSION)"
}
if ([string]::IsNullOrWhiteSpace($BaseUrl)) {
  $BaseUrl = "https://github.com/rickyreza12/ratriyx/releases/download/v$Version"
}
if ([string]::IsNullOrWhiteSpace($InstallDir)) {
  $local = $env:LOCALAPPDATA
  if ([string]::IsNullOrWhiteSpace($local)) { Fail "LOCALAPPDATA is not set" }
  $InstallDir = Join-Path $local "Programs\Ratriyx"
}

switch ($env:PROCESSOR_ARCHITECTURE) {
  'AMD64' { $arch = 'x86_64' }
  'ARM64' { $arch = 'ARM64'; Fail "ARM64 Windows has no Ratriyx binary yet" }
  default { Fail "unsupported architecture: $env:PROCESSOR_ARCHITECTURE" }
}
$asset = "ratriyx-$Version-x86_64-pc-windows-msvc.zip"
$url = "$BaseUrl/$asset"

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ratriyx-install-" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force $tmp | Out-Null
try {
  $zip = Join-Path $tmp $asset
  if ($BaseUrl.StartsWith('file://')) {
    $src = (New-Object System.Uri($url)).LocalPath
    if (-not (Test-Path $src)) { Fail "local archive not found: $src" }
    Copy-Item $src $zip
  } else {
    try {
      Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
    } catch {
      Fail "download failed: $url ($($_.Exception.Message))"
    }
  }
  $sum = Join-Path $tmp 'check.sha256'
  if ($BaseUrl.StartsWith('file://')) {
    $sumSrc = (New-Object System.Uri("$url.sha256")).LocalPath
    if (-not (Test-Path $sumSrc)) { Fail "local checksum not found: $sumSrc" }
    Copy-Item $sumSrc $sum
  } else {
    try {
      Invoke-WebRequest -Uri "$url.sha256" -OutFile $sum -UseBasicParsing
    } catch {
      Fail "checksum download failed: $url.sha256 ($($_.Exception.Message))"
    }
  }
  $expected = (Get-Content $sum -Raw).Split()[0]
  $actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
  if ($actual -ne $expected.ToLower()) { Fail "checksum mismatch for $asset; nothing installed" }
  New-Item -ItemType Directory -Force $InstallDir | Out-Null
  Expand-Archive -Path $zip -DestinationPath $tmp\out -Force
  $exe = Get-ChildItem -Path $tmp\out -Recurse -Filter ratriyx.exe | Select-Object -First 1
  if (-not $exe) { Fail "archive has no ratriyx.exe" }
  Copy-Item $exe.FullName (Join-Path $InstallDir 'ratriyx.exe') -Force
  $path = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (($path -split ';') -notcontains $InstallDir) {
    [Environment]::SetEnvironmentVariable('Path', "$path;$InstallDir", 'User')
    Write-Output "added to user PATH: $InstallDir (reopen the terminal)"
  } else {
    Write-Output "already on user PATH: $InstallDir"
  }
  Write-Output "installed: $InstallDir\ratriyx.exe"
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
