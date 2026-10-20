# Copyright 2026 The Signalith authors
# SPDX-License-Identifier: Apache-2.0
# Run by the .msi package, as SYSTEM, after it has put the files in place:
# runs install.ps1 from this folder for a new install, an upgrade or a
# repair, keeping a new install's admin password for
# "signalith initial-password". Everything it prints goes to
# C:\Windows\Temp\signalith-install.log, since an installer shows no output.
# The installer passes its OPENSEARCHURL, OPENSEARCHZIP and OPENSEARCHPROXY
# properties as "url:<value>", "zip:<value>" and "proxy:<value>", so an
# empty one is still an argument.
# With -Rollback (the installer's rollback, when the install fails after
# this ran) it undoes what this run set up on a computer that had no
# Signalith before: the Signalith service, the OpenSearch service and
# program it installed (its data is kept), and the firewall rules. On an
# upgrade the installer puts the previous version back itself; this then
# makes sure its service is there again and starts it a minute later,
# once its files are back.
param([string]$OpenSearchUrl = "url:", [string]$OpenSearchZip = "zip:", [string]$OpenSearchProxy = "proxy:", [switch]$Rollback)
$OpenSearchUrl = $OpenSearchUrl -replace '^url:', ''
$OpenSearchZip = $OpenSearchZip -replace '^zip:', ''
$OpenSearchProxy = $OpenSearchProxy -replace '^proxy:', ''
$exe = Join-Path $PSScriptRoot "signalith.exe"
$config = Join-Path $env:ProgramData "Signalith\signalith.yaml"
$osState = Join-Path $env:ProgramData "SignalithOpenSearch\installed.json"
# What was here before this run, for -Rollback: in the program folder,
# which only administrators may change (unlike C:\Windows\Temp).
$before = Join-Path $PSScriptRoot "setup-before.json"

if ($Rollback) {
  $log = Join-Path $env:windir "Temp\signalith-rollback.log"
  Start-Transcript -Path $log -Force | Out-Null
  try {
    $was = Get-Content -Raw -LiteralPath $before -ErrorAction Stop | ConvertFrom-Json
    if (-not $was.config) {
      Write-Host "The install failed: removing what it set up."
      if (Get-Service Signalith -ErrorAction SilentlyContinue) {
        Stop-Service Signalith -Force -ErrorAction SilentlyContinue
        & $exe service uninstall -c $config
      }
      if (-not $was.opensearch -and (Test-Path -LiteralPath $osState)) { & $exe opensearch remove }
      Remove-NetFirewallRule -DisplayName 'Signalith', 'Signalith agents', 'Signalith syslog *' -ErrorAction SilentlyContinue
    } else {
      # The previous version's files come back after this; its service is
      # set up again for them when it is gone, and started once they are.
      Write-Host "The upgrade failed: the previous version is put back."
      if (-not (Get-Service Signalith -ErrorAction SilentlyContinue)) { & $exe service install -c $config }
      Start-Process -WindowStyle Hidden (Join-Path $PSHOME "powershell.exe") -ArgumentList @("-NoProfile", "-NonInteractive", "-Command",
        "Start-Sleep 60; Start-Service Signalith *> (Join-Path `$env:windir 'Temp\signalith-rollback-start.log')")
    }
  } catch {
    Write-Host "Rollback: $_"
  } finally {
    Stop-Transcript | Out-Null
  }
  exit 0
}

@{ config = (Test-Path -LiteralPath $config); opensearch = (Test-Path -LiteralPath $osState) } | ConvertTo-Json | Set-Content -LiteralPath $before -Encoding ascii
$log = Join-Path $env:windir "Temp\signalith-install.log"
Start-Transcript -Path $log -Force | Out-Null
$code = 0
try {
  & (Join-Path $PSScriptRoot "install.ps1") -OpenSearchUrl $OpenSearchUrl -OpenSearchZip $OpenSearchZip -OpenSearchProxy $OpenSearchProxy -InstallDir $PSScriptRoot -SavePassword
} catch {
  Write-Host "Setup failed: $_"
  $code = 1
} finally {
  Stop-Transcript | Out-Null
}
exit $code
