# Installs, upgrades and uninstalls Signalith's .msi on this machine (a CI
# runner, as Administrator), checking the service and signing in each time.
#   test-msi.ps1 -Previous prev.msi -New new.msi -Version 0.1.1-ci.42
param(
  [Parameter(Mandatory)][string]$Previous,
  [Parameter(Mandatory)][string]$New,
  [Parameter(Mandatory)][string]$Version
)
$ErrorActionPreference = "Stop"
$exe = "$env:ProgramFiles\Signalith\signalith.exe"
$config = "$env:ProgramData\Signalith\signalith.yaml"

function Invoke-Msi([string]$Action, [string]$Msi, [string]$Log) {
  $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @($Action, "`"$((Resolve-Path $Msi).Path)`"", "/qn", "/l*v", "`"$Log`"")
  if ($p.ExitCode -ne 0) {
    Get-Content $Log -Tail 80
    if (Test-Path "$env:windir\Temp\signalith-install.log") { Get-Content "$env:windir\Temp\signalith-install.log" }
    throw "msiexec $Action $Msi failed with exit code $($p.ExitCode)"
  }
}
function Wait-Up {
  if ((Get-Service Signalith).Status -ne "Running") { throw "the Signalith service is $((Get-Service Signalith).Status)" }
  for ($i = 0; $i -lt 30; $i++) {
    try { Invoke-WebRequest https://localhost:8080/livez -SkipCertificateCheck -UseBasicParsing | Out-Null; return } catch { Start-Sleep 2 }
  }
  Get-Content "$env:ProgramData\Signalith\signalith.log" -Tail 50 -ErrorAction SilentlyContinue
  throw "Signalith does not answer on https://localhost:8080"
}
function Test-SignIn([string]$Password) {
  $body = @{ username = "admin"; password = $Password } | ConvertTo-Json
  Invoke-RestMethod https://localhost:8080/api/login -Method Post -ContentType "application/json" -Body $body -SkipCertificateCheck | Out-Null
}

Write-Host "== Install $Previous"
Invoke-Msi "/i" $Previous "$env:RUNNER_TEMP\msi-install.log"
Wait-Up
$password = (& $exe initial-password).Trim()
if ($LASTEXITCODE -ne 0 -or -not $password) { throw "signalith initial-password failed" }
Test-SignIn $password
if (-not (Get-NetFirewallRule -DisplayName "Signalith" -ErrorAction SilentlyContinue)) { throw "no firewall rule for the web UI" }
$machinePath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($machinePath -notlike "*$env:ProgramFiles\Signalith*") { throw "signalith is not on the PATH" }
# Only SYSTEM, Administrators and the service may read the config folder.
$sids = (Get-Acl $env:ProgramData\Signalith).Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique
foreach ($sid in $sids) {
  if ($sid -notin @("S-1-5-18", "S-1-5-32-544") -and $sid -notlike "S-1-5-80-*") { throw "$sid may use $env:ProgramData\Signalith" }
}
$account = (Get-CimInstance Win32_Service -Filter "Name='Signalith'").StartName
if ($account -ne "NT SERVICE\Signalith") { throw "the service runs as $account" }

Write-Host "== Upgrade to $New"
Invoke-Msi "/i" $New "$env:RUNNER_TEMP\msi-upgrade.log"
Wait-Up
$got = & $exe version
if ($got -notlike "*$Version*") { throw "signalith version says $got, want $Version" }
if ((& $exe initial-password).Trim() -ne $password) { throw "the first password changed in the upgrade" }
Test-SignIn $password
$installed = @(Get-CimInstance Win32_Product -Filter "Name='Signalith'")
if ($installed.Count -ne 1) { throw "$($installed.Count) Signalith products are installed after the upgrade" }

Write-Host "== Uninstall"
Invoke-Msi "/x" $New "$env:RUNNER_TEMP\msi-uninstall.log"
if (Get-Service Signalith -ErrorAction SilentlyContinue) { throw "the service is still there" }
if (Test-Path $exe) { throw "$exe is still there" }
if (-not (Test-Path $config)) { throw "the config was not kept" }
if (Get-NetFirewallRule -DisplayName "Signalith*" -ErrorAction SilentlyContinue) { throw "firewall rules are still there" }

Write-Host "== Install again: the kept config and password are used"
Invoke-Msi "/i" $New "$env:RUNNER_TEMP\msi-reinstall.log"
Wait-Up
Test-SignIn $password
Write-Host "The .msi installs, upgrades and uninstalls cleanly."
