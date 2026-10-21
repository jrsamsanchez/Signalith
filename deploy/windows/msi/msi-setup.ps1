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
# With -Rollback (the installer's rollback, when the install fails) it
# undoes what this run set up: on a new install, the Signalith service,
# the OpenSearch service and program (its data is kept) and the firewall
# rules, whichever were not there before. On an upgrade (-Upgrade "up:"
# followed by the installer's WIX_UPGRADE_DETECTED, the version being
# replaced) the installer puts the previous version's files back itself;
# this makes sure its service is there and starts it a minute later, once
# they are.
param([string]$OpenSearchUrl = "url:", [string]$OpenSearchZip = "zip:", [string]$OpenSearchProxy = "proxy:", [switch]$Rollback,
  [string]$Upgrade = "up:")
$OpenSearchUrl = $OpenSearchUrl -replace '^url:', ''
$OpenSearchZip = $OpenSearchZip -replace '^zip:', ''
$OpenSearchProxy = $OpenSearchProxy -replace '^proxy:', ''
$Upgrade = $Upgrade -replace '^up:', ''
$exe = Join-Path $PSScriptRoot "signalith.exe"
$config = Join-Path $env:ProgramData "Signalith\signalith.yaml"
$osState = Join-Path $env:ProgramData "SignalithOpenSearch\installed.json"
$osHome = Join-Path $PSScriptRoot "OpenSearch"
# What was here before this run, for -Rollback: in the program folder,
# which only administrators may change (unlike C:\Windows\Temp).
$before = Join-Path $PSScriptRoot "setup-before.json"

if ($Rollback) {
  $log = Join-Path $env:windir "Temp\signalith-rollback.log"
  Start-Transcript -Path $log -Force | Out-Null
  try {
    # Written by this run; none when the install failed before it ran.
    $was = $null
    if (Test-Path -LiteralPath $before) {
      $was = Get-Content -Raw -LiteralPath $before -ErrorAction Stop | ConvertFrom-Json
      Remove-Item -LiteralPath $before -Force
    }
    if ($Upgrade) {
      # The previous version's files come back after this; its service is
      # set up again for them when it is gone, and started once they are.
      Write-Host "The upgrade failed: the previous version is put back."
      if (-not (Get-Service Signalith -ErrorAction SilentlyContinue)) { & $exe service install -c $config }
      # Only once its program is back.
      $exeLit = $exe -replace "'", "''"
      Start-Process -WindowStyle Hidden (Join-Path $PSHOME "powershell.exe") -ArgumentList @("-NoProfile", "-NonInteractive", "-Command",
        "Start-Sleep 60; if (Test-Path -LiteralPath '$exeLit') { Start-Service Signalith *> (Join-Path `$env:windir 'Temp\signalith-rollback-start.log') }")
    } elseif ($was) {
      Write-Host "The install failed: removing what it set up."
      if (-not $was.signalith -and (Get-Service Signalith -ErrorAction SilentlyContinue)) {
        Stop-Service Signalith -Force -ErrorAction SilentlyContinue
        & $exe service uninstall -c $config
      }
      if (-not $was.opensearch -and (Test-Path -LiteralPath $osState)) { & $exe opensearch remove -home $osHome }
      if (-not $was.signalith) {
        Remove-NetFirewallRule -DisplayName 'Signalith', 'Signalith agents', 'Signalith syslog *' -ErrorAction SilentlyContinue
      }
    }
  } catch {
    Write-Host "Rollback: $_"
  } finally {
    Stop-Transcript | Out-Null
  }
  exit 0
}

$log = Join-Path $env:windir "Temp\signalith-install.log"
Start-Transcript -Path $log -Force | Out-Null
$code = 0
try {
  # Which services were here before this run, for -Rollback: never a note
  # an earlier run left.
  Remove-Item -LiteralPath $before -Force -ErrorAction SilentlyContinue
  @{ signalith = [bool](Get-Service Signalith -ErrorAction SilentlyContinue)
     opensearch = [bool](Get-Service SignalithOpenSearch -ErrorAction SilentlyContinue) } |
    ConvertTo-Json | Set-Content -LiteralPath $before -Encoding ascii -ErrorAction Stop
  & (Join-Path $PSScriptRoot "install.ps1") -OpenSearchUrl $OpenSearchUrl -OpenSearchZip $OpenSearchZip -OpenSearchProxy $OpenSearchProxy -InstallDir $PSScriptRoot -SavePassword
  # Set up: the note is not left for a later run's rollback to misread.
  Remove-Item -LiteralPath $before -Force -ErrorAction SilentlyContinue
} catch {
  Write-Host "Setup failed: $_"
  $code = 1
} finally {
  Stop-Transcript | Out-Null
}
exit $code
