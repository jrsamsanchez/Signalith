# Signs a Windows program or installer with the code-signing certificate
# in $env:CERT (a base64 .pfx) and $env:CERT_PASSWORD, timestamped, so
# Windows shows the publisher instead of "Unknown publisher".
param([Parameter(Mandatory)][string]$File)
$ErrorActionPreference = "Stop"
$pfx = Join-Path $env:RUNNER_TEMP "signing.pfx"
[IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($env:CERT))
try {
  $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" | Sort-Object FullName -Descending | Select-Object -First 1
  & $signtool.FullName sign /fd SHA256 /f $pfx /p $env:CERT_PASSWORD /tr http://timestamp.digicert.com /td SHA256 /d Signalith $File
  if ($LASTEXITCODE -ne 0) { throw "signtool failed for $File" }
} finally {
  Remove-Item -Force $pfx
}
