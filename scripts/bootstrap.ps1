<#
.SYNOPSIS
  Bootstraps Ratriyx: resolves the latest release, then hands off to install.ps1.
.DESCRIPTION
  Downloads scripts/install.ps1 from the repository at the resolved version
  and invokes it. Test hooks: RATRIYX_VERSION (skips resolve), RATRIYX_RAW_BASE.
  PowerShell 5.1 compatible. Never auto-runs dependency installation.
#>
[CmdletBinding()]
param(
  [string]$Version = $env:RATRIYX_VERSION,
  [string]$InstallDir = $env:RATRIYX_INSTALL_DIR
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($Version)) {
  try {
    $rel = Invoke-RestMethod -Uri 'https://api.github.com/rickyreza12/ratriyx/releases/latest' -UseBasicParsing
    $Version = ([string]$rel.tag_name).TrimStart('v')
  } catch {
    throw "ratriyx-bootstrap: cannot resolve latest release ($($_.Exception.Message)); pass -Version explicitly"
  }
}
if ([string]::IsNullOrWhiteSpace($Version)) { throw 'ratriyx-bootstrap: empty version' }
$rawBase = $env:RATRIYX_RAW_BASE
if ([string]::IsNullOrWhiteSpace($rawBase)) {
  $rawBase = 'https://raw.githubusercontent.com/rickyreza12/ratriyx/main/scripts'
}
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('ratriyx-boot-' + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force $tmp | Out-Null
try {
  $installer = Join-Path $tmp 'install.ps1'
  try {
    Invoke-WebRequest -Uri "$rawBase/install.ps1" -OutFile $installer -UseBasicParsing
  } catch {
    throw "ratriyx-bootstrap: cannot download installer ($($_.Exception.Message))"
  }
  $env:RATRIYX_VERSION = $Version
  if (-not [string]::IsNullOrWhiteSpace($InstallDir)) { $env:RATRIYX_INSTALL_DIR = $InstallDir }
  & $installer
  Write-Output "next: ratriyx setup --install --yes"
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
