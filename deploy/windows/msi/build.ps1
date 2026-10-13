# Builds Signalith's Windows installer with the WiX Toolset v5:
#   .\deploy\windows\msi\build.ps1 -Version 0.1.0 -Exe dist\signalith-windows-amd64.exe -Out dist
# Needs the .NET SDK (dotnet). WiX v5 is used rather than later versions,
# whose binaries come with a maintenance-fee agreement; v5 is MS-RL only.
param(
  [Parameter(Mandatory)][string]$Version,
  [Parameter(Mandatory)][string]$Exe,
  [Parameter(Mandatory)][string]$Out
)
$ErrorActionPreference = "Stop"
$wixVersion = "5.0.2"

# A Windows Installer version is three numbers: 0.1.0-rc.1 installs as 0.1.0.
if ($Version -notmatch '^(\d+\.\d+\.\d+)') { throw "Version $Version does not start with three numbers" }
$msiVersion = $Matches[1]

if (-not (Get-Command wix -ErrorAction SilentlyContinue) -or ((wix --version) -notlike "$wixVersion*")) {
  dotnet tool install --global wix --version $wixVersion
  if ($LASTEXITCODE -ne 0) { dotnet tool update --global wix --version $wixVersion }
  $env:PATH += ";$env:USERPROFILE\.dotnet\tools"
}
foreach ($ext in "WixToolset.UI.wixext", "WixToolset.Util.wixext") {
  wix extension add --global "$ext/$wixVersion"
  if ($LASTEXITCODE -ne 0) { throw "Could not add the WiX extension $ext" }
}

# The licence page shows LICENSE, which WiX wants as RTF.
$here = $PSScriptRoot
$work = Join-Path ([IO.Path]::GetTempPath()) ("signalith-msi-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
$text = (Get-Content -Raw (Join-Path $here "..\..\..\LICENSE")) -replace '\\', '\\' -replace '\{', '\{' -replace '\}', '\}'
$text = $text -replace "`r`n", "`n" -replace "`n", "\par`n"
$rtf = Join-Path $work "License.rtf"
Set-Content -Path $rtf -Encoding ASCII -Value ("{\rtf1\ansi\deff0{\fonttbl{\f0 Consolas;}}\fs16 " + $text + "}")

$exePath = (Resolve-Path $Exe).Path
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$msi = Join-Path (Resolve-Path $Out).Path "signalith-$Version-x64.msi"
Push-Location $here
try {
  wix build Package.wxs -arch x64 -ext WixToolset.UI.wixext -ext WixToolset.Util.wixext `
    -d "Version=$msiVersion" -d "Exe=$exePath" -d "LicenseRtf=$rtf" `
    -o $msi
  if ($LASTEXITCODE -ne 0) { throw "wix build failed" }
} finally {
  Pop-Location
  Remove-Item -Recurse -Force $work
}
Write-Host "Built $msi"
