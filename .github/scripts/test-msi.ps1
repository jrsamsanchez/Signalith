# Copyright 2026 The Signalith authors
# SPDX-License-Identifier: Apache-2.0
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

function Invoke-Msi([string]$Action, [string]$Msi, [string]$Log, [string[]]$Properties = @(), [switch]$Fails) {
  $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList (@($Action, "`"$((Resolve-Path $Msi).Path)`"", "/qn", "/l*v", "`"$Log`"") + $Properties)
  if ($Fails) {
    if ($p.ExitCode -eq 0) { throw "msiexec $Action $Msi worked, but it should have failed" }
    Write-Host "msiexec failed as it should (exit code $($p.ExitCode))"
    if (Test-Path "$env:windir\Temp\signalith-rollback.log") { Get-Content "$env:windir\Temp\signalith-rollback.log" }
    return
  }
  if ($p.ExitCode -ne 0) {
    Get-Content $Log -Tail 80
    if (Test-Path "$env:windir\Temp\signalith-install.log") { Get-Content "$env:windir\Temp\signalith-install.log" }
    throw "msiexec $Action $Msi failed with exit code $($p.ExitCode)"
  }
}
# The web port: 9000, or 8080 for a config written before 0.3, which an
# upgrade keeps.
$script:port = 0
function Wait-Up {
  if ((Get-Service Signalith).Status -ne "Running") { throw "the Signalith service is $((Get-Service Signalith).Status)" }
  for ($i = 0; $i -lt 30; $i++) {
    foreach ($p in 9000, 8080) {
      try { Invoke-WebRequest "https://localhost:$p/livez" -SkipCertificateCheck -UseBasicParsing | Out-Null; $script:port = $p; return } catch { }
    }
    Start-Sleep 2
  }
  Get-Content "$env:ProgramData\Signalith\signalith.log" -Tail 50 -ErrorAction SilentlyContinue
  throw "Signalith does not answer on https://localhost:9000 (or 8080)"
}
# The built-in admin: signalithadmin from 0.3.1, admin before, which an
# upgrade keeps. The first sign-in finds which the previous release made.
$script:admin = ""
function Test-SignIn([string]$Password) {
  $names = if ($script:admin) { @($script:admin) } else { @("signalithadmin", "admin") }
  foreach ($name in $names) {
    $body = @{ username = $name; password = $Password } | ConvertTo-Json
    try {
      Invoke-RestMethod "https://localhost:$($script:port)/api/login" -Method Post -ContentType "application/json" -Body $body -SkipCertificateCheck | Out-Null
      $script:admin = $name
      return
    } catch {
      if ($name -eq $names[-1]) { throw }
    }
  }
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

Write-Host "== A failed upgrade puts $Previous back"
# A config the new version cannot start with makes its setup fail.
$good = Get-Content -Raw -LiteralPath $config
Add-Content -LiteralPath $config "`n:: not a setting ::"
Invoke-Msi "/i" $New "$env:RUNNER_TEMP\msi-upgrade-fail.log" -Fails
Set-Content -LiteralPath $config $good -NoNewline
$installed = @(Get-CimInstance Win32_Product -Filter "Name='Signalith'")
if ($installed.Count -ne 1 -or $installed[0].Version -eq $Version) { throw "after the failed upgrade, Signalith $($installed.Version -join ', ') is installed, want the previous version only" }
if (-not (Test-Path $exe) -or (& $exe version) -like "*$Version*") { throw "after the failed upgrade, $exe is missing or is the new version" }
# The rollback starts the previous version's service a minute later.
for ($i = 0; $i -lt 60 -and (Get-Service Signalith -ErrorAction SilentlyContinue).Status -ne "Running"; $i++) { Start-Sleep 3 }
Wait-Up
Test-SignIn $password

Write-Host "== Upgrade to $New"
Invoke-Msi "/i" $New "$env:RUNNER_TEMP\msi-upgrade.log"
Wait-Up
$got = & $exe version
if ($got -notlike "*$Version*") { throw "signalith version says $got, want $Version" }
$info = (Get-Item $exe).VersionInfo
if ($info.ProductName -ne "Signalith" -or $info.ProductVersion -ne $Version) { throw "signalith.exe says it is $($info.ProductName) $($info.ProductVersion), want Signalith $Version" }
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

Write-Host "== A failed install over the kept config is undone like a new one, not like an upgrade"
$good = Get-Content -Raw -LiteralPath $config
Add-Content -LiteralPath $config "`n:: not a setting ::"
Invoke-Msi "/i" $New "$env:RUNNER_TEMP\msi-reinstall-fail.log" -Fails
Set-Content -LiteralPath $config $good -NoNewline
if (Get-Service Signalith -ErrorAction SilentlyContinue) { throw "the service is left after the failed install" }
if (Test-Path $exe) { throw "$exe is left after the failed install" }
if (Get-NetFirewallRule -DisplayName "Signalith*" -ErrorAction SilentlyContinue) { throw "firewall rules are left after the failed install" }
if (-not (Test-Path $config)) { throw "the config was not kept" }

Write-Host "== Install again: the kept config and password are used"
Invoke-Msi "/i" $New "$env:RUNNER_TEMP\msi-reinstall.log"
Wait-Up
Test-SignIn $password
Write-Host "== A new install sets up OpenSearch on this computer"
Invoke-Msi "/x" $New "$env:RUNNER_TEMP\msi-uninstall-2.log"
Remove-Item -Recurse -Force "$env:ProgramData\Signalith"
# A first install that fails undoes what it set up.
Invoke-Msi "/i" $New "$env:RUNNER_TEMP\msi-fresh-fail.log" -Properties @("OPENSEARCHZIP=C:\no-such-opensearch.zip") -Fails
if (Get-Service Signalith, SignalithOpenSearch -ErrorAction SilentlyContinue) { throw "a service is left after the failed install" }
if (Test-Path $exe) { throw "$exe is left after the failed install" }
if (Test-Path "$env:ProgramFiles\Signalith\OpenSearch") { throw "OpenSearch's program is left after the failed install" }
if (Get-NetFirewallRule -DisplayName "Signalith*" -ErrorAction SilentlyContinue) { throw "firewall rules are left after the failed install" }
Remove-Item -Recurse -Force "$env:ProgramData\Signalith" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "$env:ProgramData\SignalithOpenSearch" -ErrorAction SilentlyContinue
Invoke-Msi "/i" $New "$env:RUNNER_TEMP\msi-fresh.log"
# The pinned SHA-512 is the one OpenSearch publishes for the release.
$status = (& $exe opensearch status) -join "`n"
Write-Host $status
if ($status -notmatch "Release installed: (\S+), SHA-512 ([0-9a-f]{128})") { throw "opensearch status does not name the release" }
$relUrl, $pin = $Matches[1], $Matches[2]
$published = [Text.Encoding]::ASCII.GetString((Invoke-WebRequest "$relUrl.sha512" -UseBasicParsing).RawContentStream.ToArray())
if (($published -split "\s+")[0].ToLower() -ne $pin) { throw "the pinned SHA-512 $pin is not the one published for $relUrl ($published)" }
$os = Get-CimInstance Win32_Service -Filter "Name='SignalithOpenSearch'"
if (-not $os -or $os.State -ne "Running") { throw "the SignalithOpenSearch service is not running" }
if ($os.StartName -ne "NT SERVICE\SignalithOpenSearch") { throw "OpenSearch runs as $($os.StartName)" }
$osPort = (Get-Content -Raw "$env:ProgramData\SignalithOpenSearch\installed.json" | ConvertFrom-Json).port
$listen = @(Get-NetTCPConnection -State Listen -LocalPort $osPort | ForEach-Object { $_.LocalAddress } | Sort-Object -Unique)
if (($listen -join ",") -ne "127.0.0.1") { throw "OpenSearch listens on $($listen -join ', '), want 127.0.0.1 only" }
# Only a certificate from its CA signs in: no password works.
$code = 0
try { Invoke-WebRequest "https://127.0.0.1:$osPort/" -SkipCertificateCheck -UseBasicParsing -Headers @{ Authorization = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("admin:admin")) } | Out-Null } catch { $code = [int]$_.Exception.Response.StatusCode }
if ($code -ne 401) { throw "OpenSearch answered $code to the demo password, want 401" }
if ((Get-Content -Raw $config) -notmatch "https://127\.0\.0\.1:$osPort") { throw "signalith.yaml does not use the OpenSearch on this computer" }
Wait-Up
for ($i = 0; $i -lt 60; $i++) {
  try { Invoke-WebRequest "https://localhost:$($script:port)/readyz" -SkipCertificateCheck -UseBasicParsing | Out-Null; $ready = $true; break } catch { Start-Sleep 3 }
}
if (-not $ready) { Get-Content "$env:ProgramData\Signalith\signalith.log" -Tail 50 -ErrorAction SilentlyContinue; throw "Signalith is not ready with the OpenSearch on this computer" }
$password = (& $exe initial-password).Trim()
$body = @{ username = "signalithadmin"; password = $password } | ConvertTo-Json
Invoke-RestMethod "https://localhost:$($script:port)/api/login" -Method Post -ContentType "application/json" -Body $body -SkipCertificateCheck | Out-Null

Write-Host "== Uninstall removes OpenSearch's service and program, and keeps its data"
Invoke-Msi "/x" $New "$env:RUNNER_TEMP\msi-uninstall-3.log"
if (Get-Service SignalithOpenSearch -ErrorAction SilentlyContinue) { throw "the SignalithOpenSearch service is still there" }
if (Test-Path "$env:ProgramFiles\Signalith\OpenSearch") { throw "OpenSearch's program is still there" }
if (-not (Test-Path "$env:ProgramData\SignalithOpenSearch\data")) { throw "OpenSearch's data was not kept" }
Write-Host "The .msi installs, upgrades and uninstalls cleanly, with OpenSearch."
