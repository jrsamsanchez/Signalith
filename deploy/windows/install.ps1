# Installs or upgrades Signalith as a Windows service.
# Run in an elevated PowerShell from the folder that contains signalith.exe:
#   .\install.ps1 -OpenSearchUrl http://127.0.0.1:9200
# To upgrade, put the new signalith.exe next to this script and run it
# again: it stops the service, replaces the program, keeps the config and
# data, encrypts passwords and keys still stored as plain text, and starts
# the service again.
#
# The service runs as its own account, NT SERVICE\Signalith, which may
# change files only in the config folder (and in data folders set in
# signalith.yaml). Only SYSTEM, Administrators and that account can read
# the config folder, since it holds the master key, the encrypted
# passwords and keys, and the key of the HTTPS certificate. It is also the
# state folder, where the server keeps its identity among the servers that
# share one OpenSearch (node.id, and cluster\lock while it runs).
#
# A new config serves the web UI over HTTPS with a certificate Signalith
# makes for itself, and receives syslog on UDP and TCP 514 and over TLS on
# 6514; pass -SyslogUdp "", -SyslogTcp "" or -SyslogTls "" to leave one
# off, or other addresses such as 0.0.0.0:1514.
# The firewall rules for syslog admit only the syslog.allow senders when the
# config lists any.
param(
  [string]$OpenSearchUrl = "http://127.0.0.1:9200",
  [string]$Listen = "0.0.0.0:8080",
  [string]$SyslogUdp = "0.0.0.0:514",
  [string]$SyslogTcp = "0.0.0.0:514",
  [string]$SyslogTls = "0.0.0.0:6514",
  [string]$InstallDir = "$env:ProgramFiles\Signalith",
  [string]$ConfigDir = "$env:ProgramData\Signalith",
  # Keeps a new install's generated admin password in the config folder
  # for "signalith initial-password" instead of printing it (the .msi
  # package uses this, since nobody sees its output).
  [switch]$SavePassword
)
$ErrorActionPreference = "Stop"

$system = "S-1-5-18"
$admins = "S-1-5-32-544"
$users = "S-1-5-32-545"
# NT SERVICE\Signalith is S-1-5-80- and the SHA-1 of the upper-case service
# name in UTF-16, as Windows works it out, so it is known before the
# service exists and folders can be prepared for it first.
$hash = [Security.Cryptography.SHA1]::Create().ComputeHash([Text.Encoding]::Unicode.GetBytes("SIGNALITH"))
$serviceSid = "S-1-5-80-" + ((0..4 | ForEach-Object { [BitConverter]::ToUInt32($hash, $_ * 4) }) -join "-")
$me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value

# Grant-ServiceAccess gives NT SERVICE\Signalith access to a folder and
# everything in it. icacls cannot do this before the service exists (it
# looks the SID up by name, which fails with error 1332 on a new install),
# so the entry is added by SID directly.
function Grant-ServiceAccess {
  param([string]$Path, [Security.AccessControl.FileSystemRights]$Rights)
  $dir = Get-Item -LiteralPath $Path -Force
  if ($PSVersionTable.PSEdition -eq "Core") {
    $acl = [IO.FileSystemAclExtensions]::GetAccessControl($dir, [Security.AccessControl.AccessControlSections]::Access)
  } else {
    $acl = $dir.GetAccessControl([Security.AccessControl.AccessControlSections]::Access)
  }
  $rule = New-Object Security.AccessControl.FileSystemAccessRule(([Security.Principal.SecurityIdentifier]$serviceSid), $Rights, "ContainerInherit,ObjectInherit", "None", "Allow")
  $acl.AddAccessRule($rule)
  if ($PSVersionTable.PSEdition -eq "Core") {
    [IO.FileSystemAclExtensions]::SetAccessControl($dir, $acl)
  } else {
    $dir.SetAccessControl($acl)
  }
}

# Invoke-Checked runs a program and stops the script if it fails.
function Invoke-Checked {
  param([string]$What, [scriptblock]$Command)
  & $Command
  if ($LASTEXITCODE -ne 0) { throw "$What failed (exit code $LASTEXITCODE). Nothing after it was done; fix the problem and run this script again." }
}

# A running service is stopped first, so its program can be replaced.
$existing = Get-Service -Name Signalith -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne "Stopped") {
  Write-Host "Stopping the Signalith service to upgrade it..."
  # A stop may take up to 90 seconds: the background jobs finish their
  # current step and are handed to another server first.
  Stop-Service -Name Signalith -Force
  $existing.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(120))
}

$exe = Join-Path $InstallDir "signalith.exe"
$config = Join-Path $ConfigDir "signalith.yaml"

# New-PrivateFolder creates a folder that only SYSTEM and Administrators
# may use, owned by Administrators, from the moment it exists: in
# ProgramData every user may otherwise add files to a new folder before
# its permissions are tightened.
function New-PrivateFolder {
  param([string]$Path)
  $acl = New-Object Security.AccessControl.DirectorySecurity
  $acl.SetAccessRuleProtection($true, $false)
  $acl.SetOwner([Security.Principal.SecurityIdentifier]$admins)
  foreach ($sid in @($system, $admins)) {
    $rule = New-Object Security.AccessControl.FileSystemAccessRule(([Security.Principal.SecurityIdentifier]$sid), "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($rule)
  }
  $parent = Split-Path -Parent $Path
  if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
  if ($PSVersionTable.PSEdition -eq "Core") {
    [IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($Path), $acl)
  } else {
    [IO.Directory]::CreateDirectory($Path, $acl) | Out-Null
  }
}

$freshConfigDir = -not (Test-Path -LiteralPath $ConfigDir)
if ($freshConfigDir) { New-PrivateFolder $ConfigDir }
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# Any user may create folders in ProgramData, so a config folder, or
# anything in it, that someone else made first could hold settings,
# users or keys of theirs. They are used only when SYSTEM,
# Administrators, you or the service own every item.
foreach ($item in @(Get-Item -LiteralPath $ConfigDir -Force) + @(Get-ChildItem -LiteralPath $ConfigDir -Recurse -Force -ErrorAction Stop)) {
  $path = $item.FullName
  $owner = (Get-Acl -LiteralPath $path).GetOwner([Security.Principal.SecurityIdentifier]).Value
  if (@($system, $admins, $me, $serviceSid) -notcontains $owner) {
    $name = $owner
    try { $name = ([Security.Principal.SecurityIdentifier]$owner).Translate([Security.Principal.NTAccount]).Value } catch { }
    throw "$path belongs to $name, not to an administrator, so it may not be what you expect. Check what is in $ConfigDir; if it is all yours, make Administrators its owner (icacls `"$ConfigDir`" /setowner *$admins /T) and run this script again."
  }
}
# A new install starts from an empty folder: files someone left there
# before Signalith was installed are not trusted.
if (-not (Test-Path -LiteralPath $config) -and @(Get-ChildItem -LiteralPath $ConfigDir -Force).Count -gt 0) {
  throw "$ConfigDir already has files in it but no signalith.yaml, so it was not made by this script. Check what is in it, move it aside (or delete it if you don't need it), and run this script again."
}

# The config folder is owned by Administrators and readable only by SYSTEM
# and Administrators (not inherited from ProgramData, where every user can
# read) before signalith init writes anything into it. Everything inside
# gets that list, the state folder's files too: the master key (keys), the
# HTTPS certificate (tls) and this server's identity (node.id,
# cluster\lock).
function Protect-ConfigFolder {
  Invoke-Checked "Taking ownership of $ConfigDir" { icacls $ConfigDir /setowner "*$admins" /T /C /Q }
  Invoke-Checked "Protecting $ConfigDir" { icacls $ConfigDir /inheritance:r /grant:r "*${system}:(OI)(CI)F" "*${admins}:(OI)(CI)F" /Q }
  if (@(Get-ChildItem -LiteralPath $ConfigDir -Force).Count -gt 0) {
    Invoke-Checked "Resetting the permissions inside $ConfigDir" { icacls "$ConfigDir\*" /reset /T /C /Q }
  }
}
Protect-ConfigFolder

# Outside Program Files only administrators may change the program, since
# the service runs whatever signalith.exe is there.
if (-not $InstallDir.StartsWith($env:ProgramFiles, [StringComparison]::OrdinalIgnoreCase)) {
  Invoke-Checked "Taking ownership of $InstallDir" { icacls $InstallDir /setowner "*$admins" /T /C /Q }
  Invoke-Checked "Protecting $InstallDir" { icacls $InstallDir /inheritance:r /grant:r "*${system}:(OI)(CI)F" "*${admins}:(OI)(CI)F" "*${users}:(OI)(CI)RX" /Q }
  Grant-ServiceAccess $InstallDir "ReadAndExecute"
  if (@(Get-ChildItem -LiteralPath $InstallDir -Force).Count -gt 0) {
    Invoke-Checked "Resetting the permissions inside $InstallDir" { icacls "$InstallDir\*" /reset /T /C /Q }
  }
}
# The .msi package has put the program in place already.
$source = Join-Path $PSScriptRoot "signalith.exe"
if ([IO.Path]::GetFullPath($source) -ne [IO.Path]::GetFullPath($exe)) { Copy-Item -Force $source $InstallDir }

if (-not (Test-Path -LiteralPath $config)) {
  # -flag=value keeps an empty value, which PowerShell would otherwise drop.
  $initArgs = @("init", "-c", $config, "-listen", $Listen, "-opensearch", $OpenSearchUrl, "-syslog-udp=$SyslogUdp", "-syslog-tcp=$SyslogTcp", "-syslog-tls=$SyslogTls")
  if ($SavePassword) { $initArgs += "-save-password" }
  Invoke-Checked "signalith init" { & $exe @initArgs }
} else {
  # An upgrade: passwords and keys an older version kept as plain text are
  # encrypted, without changing anything else in the files.
  & $exe secrets encrypt -c $config
  if ($LASTEXITCODE -ne 0) { Write-Warning "Some passwords or keys could not be encrypted (see above). Check with: signalith secrets status" }
}

# Again for what init or the upgrade wrote, and then the service may
# change what is in the folder.
Protect-ConfigFolder
Grant-ServiceAccess $ConfigDir "Modify"

Invoke-Checked "signalith validate" { & $exe validate -c $config }
# Creates the service, or updates one installed before (older versions ran
# as LocalSystem), to run as NT SERVICE\Signalith and restart after a
# failure. It also gives that account the data folders signalith.yaml
# names outside this folder, such as an archive on another disk, and the
# folder of the Settings page's file, and read access to the certificate
# and key files that signalith.yaml or the Settings page names.
Invoke-Checked "signalith service install" { & $exe service install -c $config }
# Waits until the service runs, and stops here, naming the log, if it
# stops again instead.
Invoke-Checked "signalith service start" { & $exe service start -c $config }
# One rule for the web page, API and agents, replaced on each run.
Remove-NetFirewallRule -DisplayName "Signalith" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Signalith" -Direction Inbound -Protocol TCP -LocalPort ($Listen.Split(":")[-1]) -Program $exe -Action Allow -ErrorAction SilentlyContinue | Out-Null

# Open the syslog ports the config turns on (syslog.udp, syslog.tcp,
# syslog.tls), only to the senders in syslog.allow when it lists any.
# signalith reads the config itself, so every YAML style works.
$ports = @(& $exe validate -c $config -syslog-ports)
if ($LASTEXITCODE -ne 0) {
  Write-Warning "Could not read the syslog settings in $config, so no firewall rules for syslog were added. Fix the config, then run this script again."
} else {
  foreach ($line in $ports) {
    $kind, $port, $allow = $line -split ' '
    if (-not $port) { continue }
    $protocol = if ($kind -eq "udp") { "UDP" } else { "TCP" }
    $name = "Signalith syslog $($kind.ToUpper()) $port"
    $rule = @{ DisplayName = $name; Direction = "Inbound"; Protocol = $protocol; LocalPort = $port; Action = "Allow" }
    $from = "any sender"
    if ($allow -and $allow -ne "any") {
      $rule.RemoteAddress = $allow -split ','
      $from = $allow -replace ',', ', '
    }
    Remove-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
    New-NetFirewallRule @rule -ErrorAction SilentlyContinue | Out-Null
    Write-Host "Syslog: receiving on $protocol port $port ($kind) from $from."
  }
}
Write-Host "Signalith is running. Open https://localhost:$($Listen.Split(':')[-1])"
Write-Host "Your browser warns about the certificate until you trust Signalith's own CA ($ConfigDir\tls\ca.pem); docs\https.md says how."
Write-Host "The master key for the passwords and keys Signalith stores is in $ConfigDir\keys, protected for this computer only."
Write-Host "This server's identity, shown on the Servers page, is in $ConfigDir\node.id; never copy it to another server."
Write-Host "Keep a copy of those passwords and keys, or a key you can move, as docs\encryption.md explains."
# The HTTPS certificate and its CA go to $ConfigDir\tls. Retention settings
# saved in the web UI go to $ConfigDir\lookups, and days archived before
# deletion to $ConfigDir\archive (retention.archive_dir in signalith.yaml
# moves them). Those folders get the permissions above. An archive folder
# elsewhere gets its own access list from the server (SYSTEM,
# Administrators and NT SERVICE\Signalith only).
