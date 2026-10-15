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
#
# To add this computer to the servers of an existing Signalith (a cluster),
# use the line from Servers > Add a server, which downloads this script,
# checks it and runs it with -Join. It can also be run by hand from the
# folder of the .msi (C:\Program Files\Signalith) or of the Windows zip:
#   .\install.ps1 -Join 'SJ1....'
# With -Join, "signalith join" checks the token against the cluster and
# OpenSearch from this computer before it writes anything, and writes this
# server's settings and keys instead of "signalith init". -Version is the
# version the cluster runs, which this computer must run too; -From is the
# server the program is downloaded from when this computer has none, and
# -Sha256 the SHA-256 it must have (also for -Binary, a program file to use
# instead of the signalith.exe next to this script).
param(
  [string]$OpenSearchUrl = "http://127.0.0.1:9200",
  # The web page and API; agents send to 7779 (server.agent_listen).
  [string]$Listen = "0.0.0.0:9000",
  [string]$SyslogUdp = "0.0.0.0:514",
  [string]$SyslogTcp = "0.0.0.0:514",
  [string]$SyslogTls = "0.0.0.0:6514",
  [string]$InstallDir = "$env:ProgramFiles\Signalith",
  [string]$ConfigDir = "$env:ProgramData\Signalith",
  # Keeps a new install's generated admin password in the config folder
  # for "signalith initial-password" instead of printing it (the .msi
  # package uses this, since nobody sees its output).
  [switch]$SavePassword,
  # Joins a cluster with the token from Servers > Add a server.
  [string]$Join = "",
  # This server's name on the Servers page (default: the computer's name).
  [string]$Name = "",
  # The address the other servers reach this one at.
  [string]$NodeUrl = "",
  [string]$From = "",
  [string]$Version = "",
  [string]$Sha256 = "",
  [string]$Binary = ""
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

# Version-Of returns the version a signalith.exe reports ("signalith 1.5.0").
function Version-Of {
  param([string]$Path)
  try { return ((& $Path version 2>$null | Select-Object -First 1) -split ' ')[1] } catch { return "" }
}

# Test-Sha256 stops unless the file has the SHA-256 -Sha256 names.
function Test-Sha256 {
  param([string]$Path, [string]$What)
  if (-not $Sha256) { return }
  if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $Sha256.ToUpperInvariant()) {
    throw "$What does not have the SHA-256 the line names, so it was not installed. Copy the line from Servers > Add a server again; if it happens again, the download was changed on its way here."
  }
}

$exe = Join-Path $InstallDir "signalith.exe"
$source = Join-Path $PSScriptRoot "signalith.exe"
$download = $null
if ($Join) {
  Write-Host "Signalith: checking this computer"
  $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this in PowerShell opened with Run as administrator: it installs a service."
  }
  Write-Host "  - running as an administrator"
  if (-not $Join.StartsWith("SJ1.")) {
    throw "The -Join value is not a Signalith join token (they start with SJ1.). Copy the whole line from Servers > Add a server again."
  }
  if ($Sha256 -and $Sha256 -notmatch '^[0-9a-fA-F]{64}$') { throw "-Sha256 must be 64 hexadecimal characters." }
  if ($From -and -not $From.StartsWith("https://")) { throw "-From must be an https:// address." }
  $arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
  Write-Host "  - processor: $arch"
  # Installed by the .msi, the program stays the .msi's: a different
  # version is upgraded with the .msi, not replaced here.
  $msi = @(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq "Signalith" })
  if ($msi.Count -gt 0 -and (Test-Path -LiteralPath $exe)) {
    $have = Version-Of $exe
    if ($Version -and $have -ne $Version) {
      throw "This computer has Signalith $have installed from the .msi, but the cluster runs $Version, and every server must run the same version. Install the Signalith $Version .msi first (https://signalith.io/docs/install-packages/), then run the same line again: the token is used only when the join succeeds."
    }
    Write-Host "  - Signalith $have is installed from the .msi; it is used as it is"
    $source = $exe
  } elseif ($Binary) {
    if (-not (Test-Path -LiteralPath $Binary)) { throw "-Binary ${Binary}: there is no such file." }
    Test-Sha256 $Binary $Binary
    $source = $Binary
  } elseif ((Test-Path -LiteralPath $exe) -and $Version -and (Version-Of $exe) -eq $Version) {
    $source = $exe
  } elseif ((Test-Path -LiteralPath $source) -and (-not $Version -or (Version-Of $source) -eq $Version)) {
    Test-Sha256 $source $source
  } else {
    if (-not $From) { throw "There is no Signalith $Version program here. Run this from the folder of the Signalith .msi or zip, or give -From, the server to download it from." }
    if (-not $Sha256) { throw "-Sha256 is needed to check the program downloaded from $From." }
    $download = Join-Path $env:TEMP ("signalith-" + [guid]::NewGuid() + ".exe")
    $uri = "$From/api/cluster/join/binary?os=windows&arch=$arch"
    # The certificate is not checked here: the SHA-256 in the line is,
    # which is stronger.
    try {
      if ($PSVersionTable.PSEdition -eq "Core") {
        Invoke-WebRequest $uri -OutFile $download -SkipCertificateCheck -MaximumRedirection 0
      } else {
        [Net.ServicePointManager]::SecurityProtocol = "Tls12"
        [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        try { Invoke-WebRequest $uri -OutFile $download -UseBasicParsing -MaximumRedirection 0 } finally { [Net.ServicePointManager]::ServerCertificateValidationCallback = $null }
      }
    } catch {
      $code = 0
      if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
      if ($code -eq 404) {
        throw "$From cannot hand out the program for Windows $arch (it runs on another kind of computer). Install the Signalith $Version .msi first (https://signalith.io/docs/install-packages/), then run the same line again."
      }
      throw "Could not download the program from $From ($($_.Exception.Message)). Check that this computer can reach it (the web port), then run the same line again."
    }
    Test-Sha256 $download "The program downloaded from $From"
    $source = $download
  }
  Write-Host "  - the program: Signalith $(Version-Of $source)"
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
if ([IO.Path]::GetFullPath($source) -ne [IO.Path]::GetFullPath($exe)) { Copy-Item -Force $source $exe }
if ($download) { Remove-Item -Force -LiteralPath $download -ErrorAction SilentlyContinue }

if ($Join) {
  # Writes this server's settings and keys (and signalith.yaml when there
  # is none); the service is installed and started below.
  Write-Host ""
  Write-Host "Joining the cluster"
  # The token reaches join in SIGNALITH_JOIN, never on its command line,
  # which other users of the computer could see in the process list.
  $joinArgs = @("join", "-c", $config, "--no-start", "--yes")
  if ($Name) { $joinArgs += @("--name", $Name) }
  if ($NodeUrl) { $joinArgs += @("--node-url", $NodeUrl) }
  # The same port as the firewall rule below.
  $joinArgs += @("--listen", $Listen)
  $env:SIGNALITH_JOIN = $Join
  try { & $exe @joinArgs } finally { Remove-Item Env:SIGNALITH_JOIN -ErrorAction SilentlyContinue }
  switch ($LASTEXITCODE) {
    0 { }
    { $_ -in 2, 3 } { throw "The join was refused (see above). Nothing was changed by it." }
    4 { throw "This computer is not ready to join (see above). Nothing was changed by it. The token is used up: make a new one on Servers > Add a server once the problem is fixed." }
    5 { throw "The join could not save its files, so it undid what it wrote (see above)." }
    default { throw "signalith join failed (exit code $LASTEXITCODE, see above)." }
  }
} elseif (-not (Test-Path -LiteralPath $config)) {
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
# One rule for the web page and API, and one for agents, replaced on each
# run, for the ports the config uses: an upgrade keeps the ones it had.
$webPort = ($Listen.Split(":")[-1])
$agentPort = ""
$listeners = @(& $exe validate -c $config -web-ports)
if ($LASTEXITCODE -eq 0) {
  foreach ($line in $listeners) {
    $kind, $port = $line -split ' '
    if ($kind -eq "web" -and $port) { $webPort = $port }
    if ($kind -eq "agents" -and $port) { $agentPort = $port }
  }
}
Remove-NetFirewallRule -DisplayName "Signalith" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Signalith" -Direction Inbound -Protocol TCP -LocalPort $webPort -Program $exe -Action Allow -ErrorAction SilentlyContinue | Out-Null
Remove-NetFirewallRule -DisplayName "Signalith agents" -ErrorAction SilentlyContinue
if ($agentPort) {
  New-NetFirewallRule -DisplayName "Signalith agents" -Direction Inbound -Protocol TCP -LocalPort $agentPort -Program $exe -Action Allow -ErrorAction SilentlyContinue | Out-Null
}

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
Write-Host "Signalith is running. Open https://localhost:$webPort"
if ($agentPort) { Write-Host "Agents send to port $agentPort; set them up from the Add data page." }
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
