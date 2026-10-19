# Run by the .msi package, as SYSTEM, after it has put the files in place:
# runs install.ps1 from this folder for a new install, an upgrade or a
# repair, keeping a new install's admin password for
# "signalith initial-password". Everything it prints goes to
# C:\Windows\Temp\signalith-install.log, since an installer shows no output.
# The installer passes its OPENSEARCHURL and OPENSEARCHZIP properties as
# "url:<value>" and "zip:<value>", so an empty one is still an argument.
param([string]$OpenSearchUrl = "url:", [string]$OpenSearchZip = "zip:")
$OpenSearchUrl = $OpenSearchUrl -replace '^url:', ''
$OpenSearchZip = $OpenSearchZip -replace '^zip:', ''
$log = Join-Path $env:windir "Temp\signalith-install.log"
Start-Transcript -Path $log -Force | Out-Null
$code = 0
try {
  & (Join-Path $PSScriptRoot "install.ps1") -OpenSearchUrl $OpenSearchUrl -OpenSearchZip $OpenSearchZip -InstallDir $PSScriptRoot -SavePassword
} catch {
  Write-Host "Setup failed: $_"
  $code = 1
} finally {
  Stop-Transcript | Out-Null
}
exit $code
