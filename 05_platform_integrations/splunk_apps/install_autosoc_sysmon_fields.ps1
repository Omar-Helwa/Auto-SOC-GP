<#
.SYNOPSIS
  Install the AutoSOC Sysmon search-time field extractions into a local Splunk.

.DESCRIPTION
  Copies splunk_apps\autosoc_sysmon_fields to <SplunkHome>\etc\apps and,
  with -Restart, restarts Splunk. The app has no inputs and no index-time
  settings. An existing copy is moved to autosoc_sysmon_fields.bak-<timestamp>
  under etc\apps\.. (outside the apps folder, so Splunk does not load it).

  Run from an elevated (Administrator) PowerShell:
    powershell -ExecutionPolicy Bypass -File 05_platform_integrations\splunk_apps\install_autosoc_sysmon_fields.ps1 -Restart
#>
[CmdletBinding()]
param(
    [string]$SplunkHome = "C:\Program Files\Splunk",
    [switch]$Restart
)

$ErrorActionPreference = "Stop"
$source = Join-Path $PSScriptRoot "autosoc_sysmon_fields"
$apps = Join-Path $SplunkHome "etc\apps"
$target = Join-Path $apps "autosoc_sysmon_fields"
$splunkExe = Join-Path $SplunkHome "bin\splunk.exe"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this from an elevated (Administrator) PowerShell: Splunk's folders are under Program Files."
}
if (-not (Test-Path -LiteralPath $apps)) { throw "Splunk apps folder not found: $apps" }
foreach ($official in @("Splunk_TA_microsoft_sysmon")) {
    if (Test-Path -LiteralPath (Join-Path $apps $official)) {
        throw "$official is installed; it already provides these fields. Do not install both."
    }
}

if (Test-Path -LiteralPath $target) {
    $backup = Join-Path (Split-Path -Parent $apps) ("autosoc_sysmon_fields.bak-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
    Move-Item -LiteralPath $target -Destination $backup
    Write-Host "Moved the previous copy to $backup"
}
Copy-Item -LiteralPath $source -Destination $target -Recurse
Write-Host "Installed $target"

if ($Restart) {
    & $splunkExe restart
    if ($LASTEXITCODE -ne 0) { throw "splunk restart failed (exit $LASTEXITCODE)." }
} else {
    Write-Host "Restart Splunk to load it: Splunk Web -> Settings -> Server controls -> Restart Splunk (or rerun with -Restart)."
}
