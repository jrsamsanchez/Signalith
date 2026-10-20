# Copyright 2026 The Signalith authors
# SPDX-License-Identifier: Apache-2.0
# Installs the Signalith Agent on a Windows computer: one program that runs
# the collectors for it. It fetches what to collect from Signalith every
# few minutes, writes Fluent Bit's configuration, keeps Fluent Bit running
# and reports how it is, so nobody edits a configuration file by hand.
#
# Add data > Signalith Agent > Windows gives one line for PowerShell opened
# with Run as administrator. It downloads this script from Signalith,
# checks its SHA-256, and runs it with the agent token on the pipeline:
#
#   ... 'sgl_...' | & $f -From https://siem:7779 -CaSha256 <hex> -Version 0.4.0 -Token - -Osquery
#
# "-Token -" reads the token from the pipeline. The script runs in the same
# PowerShell, so the token is on no program's command line, and the script
# takes the line out of PowerShell's saved history when it is done.
#
# What it does, in order, stopping at the first problem with a plain
# message:
#   1. Checks the computer: administrator, 64-bit x86, Windows 10 or Server
#      2016 or later.
#   2. Checks Signalith's certificate authority against the fingerprint in
#      the line (-CaSha256), then asks Signalith, with the token, for the
#      agent's configuration: a revoked or wrong token stops here, before
#      anything is installed. Every later request to Signalith checks its
#      certificate against that authority, and its name.
#   3. Downloads Fluent Bit for Windows from its publisher (the version
#      pinned below) and checks its SHA-256 against the one the publisher
#      lists, or against -FluentBitSha256. -FluentBitZip uses a zip already
#      on the computer instead, for computers without internet access.
#   4. With -Sysmon: when Sysmon is not installed yet, downloads it from
#      Microsoft (its license does not allow handing it out otherwise),
#      checks that Microsoft signed it, and installs it with the
#      configuration below. A Sysmon already installed keeps its own.
#   5. With -Osquery: when osquery is not installed yet, downloads its MSI
#      from its publisher (the version pinned below), checks its signature
#      (or -OsquerySha256), and installs it. osquery's own service is
#      turned off: the agent runs osquery with the flags it writes from
#      Signalith's configuration, and osquery enrolls with the agent token.
#      -OsqueryMsi uses an MSI already on the computer instead.
#   6. Downloads the agent program from Signalith and checks its SHA-256,
#      writes the agent's settings, token and certificate authority to a
#      folder only SYSTEM and Administrators can open, and starts the
#      SignalithAgent service.
#   7. Waits until the agent runs Fluent Bit (and osquery) with Signalith's
#      configuration and Signalith has its status.
#
# Run it again to repair, or to upgrade Fluent Bit and the agent: it
# changes only what differs. It keeps a copy of itself in the agent's
# program folder, whose -Uninstall removes what it added (the list is the
# manifest file in the agent's data folder).
param(
  # Signalith's address, which the agent sends to.
  [string]$From = "",
  # SHA-256 of Signalith's certificate authority; the script refuses
  # another one. Left out when Signalith's certificate is from a public
  # authority.
  [string]$CaSha256 = "",
  # The new certificate authority while Signalith switches.
  [string]$NextCaSha256 = "",
  # Signalith's version.
  [string]$Version = "",
  # The agent token, or - to read it from the pipeline. Left out on a run
  # again, the agent keeps its own.
  [string]$Token = "",
  # Also install Sysmon, downloaded from Microsoft.
  [switch]$Sysmon,
  # A Fluent Bit for Windows zip (fluent-bit-<version>-win64.zip) already
  # on this computer, used instead of downloading one.
  [string]$FluentBitZip = "",
  # The SHA-256 the Fluent Bit zip must have.
  [string]$FluentBitSha256 = "",
  # Also install osquery, for inventory, file changes and live queries. A
  # run again keeps osquery once the script installed it.
  [switch]$Osquery,
  # An osquery MSI already on this computer, used instead of downloading
  # one.
  [string]$OsqueryMsi = "",
  # The SHA-256 the osquery MSI must have.
  [string]$OsquerySha256 = "",
  # Write every file under this folder and print the commands instead of
  # running them.
  [string]$DryRun = "",
  # Remove what the script added.
  [switch]$Uninstall
)
$ErrorActionPreference = "Stop"
# Read now: $input is the pipeline, and is empty once anything reads it.
$piped = @($input)

# --- Pinned versions and sources -------------------------------------------
# Fluent Bit for Windows. The publisher lists each file's SHA-256 next to
# it (<zip>.sha256), which the script checks the zip against.
$FluentBitVersion = "4.0.3"
$FluentBitUrl = "https://packages.fluentbit.io/windows/fluent-bit-$FluentBitVersion-win64.zip"
# osquery for Windows, from its publisher. The script checks the MSI's
# Authenticode signature, or the SHA-256 given with -OsquerySha256.
$OsqueryVersion = "5.12.1"
$OsqueryUrl = "https://pkg.osquery.io/windows/osquery-$OsqueryVersion.msi"
# Sysmon, from Microsoft's Sysinternals.
$SysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$Systems = "Windows 10 or 11 and Windows Server 2016 or later (64-bit x86)"

$ServiceName = "SignalithAgent"
$system = "S-1-5-18"
$admins = "S-1-5-32-544"
# NT SERVICE\TrustedInstaller, which owns Program Files.
$trustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

# Where the agent lives. The agent program reads the same paths
# (internal/agentd), and the configuration Signalith makes for it names
# the same certificate authority and buffer folders.
$R = ""
if ($DryRun) {
  $R = [IO.Path]::GetFullPath($DryRun)
  New-Item -ItemType Directory -Force -Path $R | Out-Null
  $ProgramDir = Join-Path $R "Program Files/Signalith Agent"
  $ConfDir = Join-Path $R "ProgramData/Signalith Agent"
  $OsquerydExe = Join-Path $R "Program Files/osquery/osqueryd/osqueryd.exe"
} else {
  $pf = $env:ProgramFiles
  if (-not $pf) { $pf = "C:\Program Files" }
  $ProgramDir = Join-Path $pf "Signalith Agent"
  $ConfDir = Join-Path $env:ProgramData "Signalith Agent"
  # Where osquery's MSI puts it; the agent looks there too.
  $OsquerydExe = Join-Path $pf "osquery\osqueryd\osqueryd.exe"
}
$Program = Join-Path $ProgramDir "signalith-agent.exe"
$FluentBitDir = Join-Path $ProgramDir "fluent-bit"
$FluentBitExe = Join-Path $FluentBitDir "bin\fluent-bit.exe"
$ScriptCopy = Join-Path $ProgramDir "install.ps1"
$Manifest = Join-Path $ConfDir "manifest"

$again = "Copy the whole line again from Add data > Signalith Agent > Windows."

# --- Saying what happens ---------------------------------------------------

$script:warned = 0
function Say([string]$Text) { Write-Host $Text }
function Ok([string]$Text) { Write-Host ("  " + [char]0x2713 + " " + $Text) }
function Info([string]$Text) { Write-Host "  - $Text" }
function Would([string]$Text) { Write-Host "    would run: $Text" }
# Warn prints a warning and how to fix it; the install goes on.
function Warn([string]$Text, [string]$Fix = "") {
  $script:warned++
  Write-Host "  ! $Text" -ForegroundColor Yellow
  if ($Fix) { Write-Host "      Fix: $Fix" -ForegroundColor Yellow }
}
# Fail stops the script with what went wrong and how to fix it.
class AgentInstallStop : Exception { AgentInstallStop([string]$m) : base($m) { } }
function Fail([string]$Text, [string]$Fix = "") {
  Write-Host ("  " + [char]0x2717 + " " + $Text) -ForegroundColor Red
  if ($Fix) { Write-Host "      Fix: $Fix" -ForegroundColor Red }
  throw [AgentInstallStop]::new($Text)
}

# --- Talking to Signalith ----------------------------------------------------
# Downloads go through this small helper so that Windows PowerShell 5.1
# and PowerShell 7 check certificates the same way: against the computer's
# trusted authorities, or, once the script has checked Signalith's own
# certificate authority, against that authority only (and the name in the
# address either way). The callback is per request, so nothing else in
# this PowerShell is affected.
if (-not ("SignalithAgentInstall.Fetch2" -as [type])) {
  # PowerShell 7 warns that HttpWebRequest is old; it is the one API both
  # PowerShells have that checks a certificate per request.
  Add-Type -IgnoreWarnings -WarningAction SilentlyContinue -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SignalithAgentInstall {
  public class Fetch2 {
    readonly bool insecure;
    readonly List<X509Certificate2> pinned = new List<X509Certificate2>();
    readonly List<string> pins = new List<string>();
    public string Sha256Header = "";
    public string Error = "";

    // insecure is only for downloading the certificate authority, whose
    // fingerprint the script checks itself.
    public Fetch2(bool insecure) { this.insecure = insecure; }

    public static string Sha256(byte[] b) {
      using (var h = SHA256.Create()) {
        return BitConverter.ToString(h.ComputeHash(b)).Replace("-", "").ToLowerInvariant();
      }
    }

    // Sha256File is a file's SHA-256 (Get-FileHash is missing where
    // Windows PowerShell starts with PowerShell 7's module path).
    public static string Sha256File(string path) {
      using (var h = SHA256.Create())
      using (var f = File.OpenRead(path)) {
        return BitConverter.ToString(h.ComputeHash(f)).Replace("-", "").ToLowerInvariant();
      }
    }

    // Pin trusts the certificate authority der (and only the pinned ones).
    public void Pin(byte[] der) {
      var c = new X509Certificate2(der);
      pinned.Add(c);
      pins.Add(Sha256(c.RawData));
    }

    bool Check(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors) {
      if (insecure) return true;
      if (pins.Count == 0) return errors == SslPolicyErrors.None;
      // The name must match whatever the authority.
      if ((errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != SslPolicyErrors.None) return false;
      using (var c = new X509Chain()) {
        c.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        c.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
        foreach (var p in pinned) c.ChainPolicy.ExtraStore.Add(p);
        c.Build(new X509Certificate2(cert));
        foreach (X509ChainElement e in c.ChainElements) {
          foreach (X509ChainStatus s in e.ChainElementStatus) {
            if (s.Status != X509ChainStatusFlags.NoError && s.Status != X509ChainStatusFlags.UntrustedRoot) return false;
          }
        }
        if (c.ChainElements.Count == 0) return false;
        var root = c.ChainElements[c.ChainElements.Count - 1].Certificate;
        return pins.Contains(Sha256(root.RawData));
      }
    }

    // Get downloads url to outFile and returns the HTTP status, or 0 when
    // there was no answer (Error says why). token, when not empty, goes in
    // Authorization. Redirects are followed only when follow is true, and
    // only to https.
    public int Get(string url, string token, string outFile, int timeoutSeconds, bool follow) {
      Error = "";
      Sha256Header = "";
      var req = (HttpWebRequest)WebRequest.Create(url);
      req.Method = "GET";
      req.AllowAutoRedirect = follow;
      req.Timeout = timeoutSeconds * 1000;
      req.ReadWriteTimeout = timeoutSeconds * 1000;
      req.UserAgent = "signalith-agent-install";
      req.ServerCertificateValidationCallback = Check;
      if (!string.IsNullOrEmpty(token)) req.Headers["Authorization"] = "Bearer " + token;
      HttpWebResponse resp;
      try {
        resp = (HttpWebResponse)req.GetResponse();
      } catch (WebException e) {
        resp = e.Response as HttpWebResponse;
        if (resp == null) {
          Error = e.InnerException != null ? e.Message + " (" + e.InnerException.Message + ")" : e.Message;
          return 0;
        }
      }
      using (resp) {
        if (resp.ResponseUri.Scheme != "https") {
          Error = "it was sent on to a plain http address";
          return 0;
        }
        Sha256Header = resp.Headers["X-Signalith-SHA256"] ?? "";
        using (var s = resp.GetResponseStream())
        using (var f = File.Create(outFile)) {
          s.CopyTo(f);
        }
        return (int)resp.StatusCode;
      }
    }
  }
}
'@
}
# TLS 1.2 for Windows PowerShell 5.1, which may not offer it by itself.
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }

$script:tmp = Join-Path ([IO.Path]::GetTempPath()) ("signalith-agent-" + [guid]::NewGuid())
$script:sig = $null
$script:caPem = ""

# Sig-Get asks Signalith for $Path with the agent token into $Out, and
# returns the HTTP status.
function Sig-Get([string]$Path, [string]$Out, [int]$Timeout = 30) {
  return $script:sig.Get("$From$Path", $Token, $Out, $Timeout, $false)
}
# Sig-Error is the error message of Signalith's JSON answer in $Out.
function Sig-Error([string]$Out) {
  try { return ([IO.File]::ReadAllText($Out) | ConvertFrom-Json).error } catch { return "" }
}

# --- Writing files -----------------------------------------------------------

$script:changed = $false
$script:restart = $false

function Manifest-Has([string]$Line) {
  if (-not (Test-Path -LiteralPath $Manifest)) { return $false }
  return @([IO.File]::ReadAllLines($Manifest)) -contains $Line
}
# Manifest-Add records what the script added, for -Uninstall.
function Manifest-Add([string]$Line) {
  if (Manifest-Has $Line) { return }
  if (-not (Test-Path -LiteralPath $Manifest)) {
    [IO.File]::WriteAllText($Manifest, "# Written by the Signalith Agent install script: what it added, for -Uninstall.`n")
  }
  [IO.File]::AppendAllText($Manifest, "$Line`n")
}

# New-PrivateFolder creates a folder that only SYSTEM and Administrators
# may use, owned by Administrators, from the moment it exists: in
# ProgramData every user may otherwise add files to a new folder before
# its permissions are tightened. (The same as deploy/windows/install.ps1.)
function New-PrivateFolder([string]$Path) {
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

# Protect-Folder makes $Path owned by Administrators and usable only by
# SYSTEM and Administrators (plus read for Users when $Readable), for the
# folder and everything in it.
function Protect-Folder([string]$Path, [bool]$Readable) {
  $grants = @("*${system}:(OI)(CI)F", "*${admins}:(OI)(CI)F")
  if ($Readable) { $grants += "*S-1-5-32-545:(OI)(CI)RX" }
  & icacls $Path /setowner "*$admins" /T /C /Q | Out-Null
  if ($LASTEXITCODE -ne 0) { Fail "Could not make Administrators the owner of $Path (icacls exit code $LASTEXITCODE)." }
  & icacls $Path /inheritance:r /grant:r @grants /Q | Out-Null
  if ($LASTEXITCODE -ne 0) { Fail "Could not protect $Path (icacls exit code $LASTEXITCODE)." }
  if (@(Get-ChildItem -LiteralPath $Path -Force).Count -gt 0) {
    & icacls "$Path\*" /reset /T /C /Q | Out-Null
  }
}

# Assert-Owned stops when anything in $Path belongs to someone other than
# SYSTEM, Administrators or the user running this: any user may create
# folders in ProgramData, so a folder someone made first could hold files
# of theirs that the agent, which runs as SYSTEM, would use.
function Assert-Owned([string]$Path) {
  $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  foreach ($item in @(Get-Item -LiteralPath $Path -Force) + @(Get-ChildItem -LiteralPath $Path -Recurse -Force)) {
    $owner = (Get-Acl -LiteralPath $item.FullName).GetOwner([Security.Principal.SecurityIdentifier]).Value
    if (@($system, $admins, $me) -notcontains $owner) {
      $name = $owner
      try { $name = ([Security.Principal.SecurityIdentifier]$owner).Translate([Security.Principal.NTAccount]).Value } catch { }
      Fail "$($item.FullName) belongs to $name, not to an administrator, so it may not be what you expect." "Check what is in $Path; if it is all yours, make Administrators its owner (icacls `"$Path`" /setowner *$admins /T), or delete it, and run the line again."
    }
  }
}

function Same-Bytes([byte[]]$A, [string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { return $false }
  return [SignalithAgentInstall.Fetch2]::Sha256($A) -eq [SignalithAgentInstall.Fetch2]::Sha256([IO.File]::ReadAllBytes($Path))
}

# Put-Bytes writes $Bytes to $Path when they differ from what is there:
# to a new file first, renamed over the old one, so the agent never reads
# half a file. It returns whether the file changed.
function Put-Bytes([string]$Path, [byte[]]$Bytes) {
  if (Same-Bytes $Bytes $Path) { return $false }
  $new = "$Path.signalith-new"
  if (Test-Path -LiteralPath $new) { Remove-Item -LiteralPath $new -Force }
  [IO.File]::WriteAllBytes($new, $Bytes)
  Move-Item -LiteralPath $new -Destination $Path -Force
  Manifest-Add "file $Path"
  return $true
}
function Put-Text([string]$Path, [string]$Text) {
  return Put-Bytes $Path ([Text.UTF8Encoding]::new($false).GetBytes($Text))
}

# --- The computer ------------------------------------------------------------

$script:arch = "amd64"
function Check-Machine {
  if ($DryRun) {
    Info "dry run: files go under $R, commands are printed, nothing else changes"
    return
  }
  $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail "Run this in PowerShell opened with Run as administrator: it installs a service." "Right-click PowerShell, choose Run as administrator, and paste the line again."
  }
  Ok "running as an administrator"
  if (-not [Environment]::Is64BitOperatingSystem) { Fail "The agent runs on 64-bit Windows only." }
  $machine = $env:PROCESSOR_ARCHITECTURE
  if ($env:PROCESSOR_ARCHITEW6432) { $machine = $env:PROCESSOR_ARCHITEW6432 }
  if ($machine -ne "AMD64") {
    Fail "The agent runs on 64-bit x86 Windows, not $machine yet." "Set up Fluent Bit by hand from Add data > Windows instead."
  }
  # A 32-bit PowerShell would install into Program Files (x86) and see
  # another registry.
  if (-not [Environment]::Is64BitProcess) {
    Fail "This is the 32-bit PowerShell." "Open the 64-bit Windows PowerShell (not the one marked x86) as administrator and paste the line again."
  }
  Ok "processor: amd64"
  $v = [Environment]::OSVersion.Version
  if ($v.Major -lt 10 -or $v.Build -lt 14393) {
    Fail "The agent runs on $Systems; this computer runs Windows $v." "Set up Fluent Bit by hand from Add data > Windows instead."
  }
  $name = ""
  try { $name = (Get-CimInstance Win32_OperatingSystem).Caption } catch { }
  if (-not $name) { $name = "Windows $v" }
  Ok "system: $name"
}

function Check-Args {
  if (-not $From) { Fail "-From is missing: the address of your Signalith." $again }
  if (-not $From.StartsWith("https://")) { Fail "-From must be an https:// address: the agent sends only over HTTPS." }
  if ($From -notmatch '^https://[A-Za-z0-9.\-\[\]:]+$') {
    Fail "-From must be Signalith's address and nothing else, like https://siem.example.com:7779 (no path)."
  }
  foreach ($p in @(@("-CaSha256", $CaSha256), @("-NextCaSha256", $NextCaSha256), @("-FluentBitSha256", $FluentBitSha256), @("-OsquerySha256", $OsquerySha256))) {
    if ($p[1] -and $p[1] -notmatch '^[0-9a-fA-F]{64}$') { Fail "$($p[0]) must be 64 hexadecimal characters." $again }
  }
  $script:CaSha256 = $CaSha256.ToLowerInvariant()
  $script:NextCaSha256 = $NextCaSha256.ToLowerInvariant()
  if ($NextCaSha256 -and -not $CaSha256) { Fail "-NextCaSha256 needs -CaSha256 too." }
  if (-not $Version) { $script:Version = "unknown" }
  elseif ($Version -notmatch '^[A-Za-z0-9.+-]+$') { Fail "-Version must be a version number, like 0.4.0." }
  if ($FluentBitZip -and -not (Test-Path -LiteralPath $FluentBitZip -PathType Leaf)) { Fail "-FluentBitZip ${FluentBitZip}: there is no such file." }
  if ($OsqueryMsi -and -not (Test-Path -LiteralPath $OsqueryMsi -PathType Leaf)) { Fail "-OsqueryMsi ${OsqueryMsi}: there is no such file." }
  if (($OsqueryMsi -or $OsquerySha256) -and -not $Osquery) { $script:Osquery = [switch]$true }
  if ($Token -eq "-") {
    $script:Token = (($piped | ForEach-Object { "$_" }) -join "").Trim()
    $script:tokenFromLine = $true
    if (-not $script:Token) { Fail "No token on the pipeline." "$again It has 'sgl_...' | before the script." }
  }
  $tokenFile = Join-Path $ConfDir "token"
  if (-not $script:Token -and (Test-Path -LiteralPath $tokenFile)) {
    # A run again without a token keeps the agent's token.
    $script:Token = ([IO.File]::ReadAllText($tokenFile)).Trim()
  }
  if (-not $script:Token) { Fail "-Token is missing." "$again It holds the agent's token." }
  if (-not $script:Token.StartsWith("sgl_")) { Fail "This is not a Signalith agent token (they start with sgl_)." $again }
  if ($script:Token -cnotmatch '^sgl_[a-z2-7]{52}$') { Fail "The token is not whole: a Signalith agent token is sgl_ and 52 letters and digits." $again }
}

# --- Signalith ---------------------------------------------------------------

# Fetch-CA downloads one of Signalith's certificate authorities ($Which)
# and checks it is the one the line names ($Want). Signalith hands out one
# certificate each time: a file with more is refused, as someone in
# between could add their own after the real one.
function Fetch-CA([string]$Which, [string]$Want) {
  $q = ""
  if ($Which -ne "current") { $q = "?which=$Which" }
  $out = Join-Path $script:tmp "ca-$Which.pem"
  # Not checked by a certificate: the fingerprint below is.
  $insecure = New-Object SignalithAgentInstall.Fetch2 $true
  $code = $insecure.Get("$From/api/tls/ca.pem$q", "", $out, 30, $false)
  if ($code -eq 0) {
    Fail "Could not reach Signalith at ${From}: $($insecure.Error)" "Check that this computer can reach it (Test-NetConnection), that the address is right, and that no firewall is in between, then run the line again."
  }
  if ($code -ne 200) { Fail "Signalith at $From did not hand out its certificate authority (it answered $code)." $again }
  $text = [IO.File]::ReadAllText($out)
  $blocks = [regex]::Matches($text, '-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----')
  $n = ([regex]::Matches($text, '-----BEGIN CERTIFICATE-----')).Count
  if ($n -ne 1 -or $blocks.Count -ne 1) {
    Fail "Signalith at $From handed out $n certificates where it hands out one." "$again If it still fails, someone may be in between this computer and Signalith."
  }
  $der = [Convert]::FromBase64String(($blocks[0].Groups[1].Value -replace '\s', ''))
  if ([SignalithAgentInstall.Fetch2]::Sha256($der) -ne $Want) {
    Fail "This Signalith's certificate authority is not the one the line names." "$again If it still fails, someone may be in between this computer and Signalith."
  }
  $script:sig.Pin($der)
  # Only the certificate checked above is kept.
  $script:caPem += $blocks[0].Value.Replace("`r", "") + "`n"
}

function Check-CA {
  if (-not $CaSha256) {
    $script:sig = New-Object SignalithAgentInstall.Fetch2 $false
    $code = $script:sig.Get("$From/", "", (Join-Path $script:tmp "root"), 30, $false)
    if ($code -eq 0) {
      Fail "Could not reach Signalith at $From over HTTPS with this computer's trusted certificate authorities: $($script:sig.Error)" "Check the address; if Signalith uses its own certificate authority, copy the line again from Add data: it then names it with -CaSha256."
    }
    Ok "Signalith at $From (certificate checked by this computer's trusted authorities)"
    return
  }
  $script:sig = New-Object SignalithAgentInstall.Fetch2 $false
  Fetch-CA "current" $CaSha256
  if ($NextCaSha256) { Fetch-CA "next" $NextCaSha256 }
  Ok "Signalith at $From, its certificate authority is the one the line names"
}

function Check-Token {
  $out = Join-Path $script:tmp "config.json"
  $code = Sig-Get "/api/agent/config?os=windows&arch=$($script:arch)&server=$From" $out
  switch ($code) {
    200 { }
    0 { Fail "Could not reach Signalith at $From to check the token: $($script:sig.Error)" "Check that this computer can reach it, then run the line again." }
    { $_ -eq 401 -or $_ -eq 403 } { Fail "Signalith refused the token: $(Sig-Error $out)" "Make the line again on Add data > Signalith Agent." }
    503 { Fail "Signalith is still starting." "Run the line again in a minute." }
    default { Fail "Signalith did not hand out the agent's configuration (it answered $code): $(Sig-Error $out)" $again }
  }
  Ok "the token is an agent token Signalith knows"
}

# --- Fluent Bit --------------------------------------------------------------

function Program-Version([string]$Exe) {
  if (-not (Test-Path -LiteralPath $Exe)) { return "" }
  # Windows PowerShell 5.1 turns a program's error output into errors
  # that stop the script; here they are only output.
  $ErrorActionPreference = "Continue"
  try {
    $out = & $Exe --version 2>&1 | Select-Object -First 1
    if ("$out" -match 'v?(\d+\.\d+\.\d+)') { return $Matches[1] }
  } catch { }
  return ""
}

# Fluent Bit's own service, from an install by hand, would send a second
# copy of everything when it sends to Signalith too: it is stopped and
# turned off then (-Uninstall turns it back on). One that sends elsewhere
# is left alone.
function Vendor-FluentBit {
  $svc = Get-Service -Name "fluent-bit" -ErrorAction SilentlyContinue
  if (-not $svc) { return }
  $image = ""
  try { $image = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\fluent-bit").ImagePath } catch { }
  $conf = ""
  if ($image -match '-c\s+"([^"]+)"' -or $image -match '-c\s+(\S+)') { $conf = $Matches[1] }
  $sendsHere = $false
  if ($conf -and (Test-Path -LiteralPath $conf)) {
    $sendsHere = (Get-Content -LiteralPath $conf -Raw) -match 'signalith'
  }
  if (-not $sendsHere) {
    Warn "Fluent Bit's own service (fluent-bit) runs here too; it was left alone, as its configuration does not name Signalith." "If it sends to Signalith, stop it (Set-Service fluent-bit -StartupType Disabled; Stop-Service fluent-bit), or each event arrives twice."
    return
  }
  $start = (Get-CimInstance Win32_Service -Filter "Name='fluent-bit'").StartMode
  if ($start -eq "Disabled" -and $svc.Status -eq "Stopped") { return }
  Manifest-Add "service-start fluent-bit $start"
  Stop-Service -Name "fluent-bit" -Force -ErrorAction SilentlyContinue
  Set-Service -Name "fluent-bit" -StartupType Disabled
  Ok "stopped and turned off Fluent Bit's own service, which sent to Signalith too (the agent runs Fluent Bit now)"
}

function FluentBit-Install {
  $have = Program-Version $FluentBitExe
  if ($DryRun -and (Manifest-Has "fluentbit $FluentBitVersion")) { $have = $FluentBitVersion }
  if ($have -eq $FluentBitVersion -and -not $FluentBitZip) {
    Ok "Fluent Bit $have"
    return
  }
  $zip = Join-Path $script:tmp "fluent-bit.zip"
  $want = $FluentBitSha256.ToLowerInvariant()
  if ($FluentBitZip) {
    Copy-Item -LiteralPath $FluentBitZip -Destination $zip
    if (-not $want) { Info "using $FluentBitZip as it is (give -FluentBitSha256 to check it)" }
  } elseif ($DryRun) {
    Info "would download $FluentBitUrl and check its SHA-256"
    Manifest-Add "fluentbit $FluentBitVersion"
    $script:changed = $true
    return
  } else {
    $pub = New-Object SignalithAgentInstall.Fetch2 $false
    $code = $pub.Get($FluentBitUrl, "", $zip, 600, $true)
    if ($code -ne 200) {
      Fail "Could not download Fluent Bit from $FluentBitUrl ($(if ($code) { "it answered $code" } else { $pub.Error }))." "Check that this computer reaches packages.fluentbit.io; without internet access, download the zip elsewhere and run the line again with -FluentBitZip <path to the zip>."
    }
    if (-not $want) {
      $sumFile = Join-Path $script:tmp "fluent-bit.zip.sha256"
      $code = $pub.Get("$FluentBitUrl.sha256", "", $sumFile, 60, $true)
      if ($code -eq 200 -and ([IO.File]::ReadAllText($sumFile) -match '\b([0-9a-fA-F]{64})\b')) {
        $want = $Matches[1].ToLowerInvariant()
      } else {
        Fail "Could not get the SHA-256 Fluent Bit's publisher lists for the zip ($FluentBitUrl.sha256), so the zip was not used." "Run the line again with -FluentBitSha256 <the SHA-256 listed on docs.fluentbit.io for fluent-bit-$FluentBitVersion-win64.zip>."
      }
    }
  }
  if ($want) {
    $got = [SignalithAgentInstall.Fetch2]::Sha256File($zip)
    if ($got -ne $want) { Fail "The Fluent Bit zip is not the one expected (its SHA-256 is $got, not $want), so it was not installed." "Download it again; if it keeps failing, it was changed on its way here." }
    Ok "Fluent Bit zip checked (SHA-256 $($got.Substring(0, 12)))"
  }
  $unpacked = Join-Path $script:tmp "fluent-bit"
  Expand-Archive -LiteralPath $zip -DestinationPath $unpacked -Force
  $exe = @(Get-ChildItem -LiteralPath $unpacked -Recurse -Filter "fluent-bit.exe" | Where-Object { $_.Directory.Name -eq "bin" }) | Select-Object -First 1
  if (-not $exe) { Fail "The zip holds no bin\fluent-bit.exe, so it is not Fluent Bit for Windows." }
  $root = $exe.Directory.Parent.FullName
  $ErrorActionPreference = "Continue"
  & $exe.FullName --version *> $null
  $ErrorActionPreference = "Stop"
  if ($LASTEXITCODE -eq -1073741515) {
    Fail "Fluent Bit cannot start on this computer: the Microsoft Visual C++ runtime it needs is missing." "Install it from https://aka.ms/vs/17/release/vc_redist.x64.exe, then run the line again."
  }
  $newVersion = Program-Version $exe.FullName
  if (-not $newVersion) { Fail "Fluent Bit from the zip does not run here (exit code $LASTEXITCODE)." }
  Stop-Agent
  if (Test-Path -LiteralPath $FluentBitDir) { Remove-Item -LiteralPath $FluentBitDir -Recurse -Force }
  # Copied, not moved: the temporary folder may be on another drive.
  Copy-Item -LiteralPath $root -Destination $FluentBitDir -Recurse
  Manifest-Add "dir $FluentBitDir"
  $script:changed = $true
  $script:restart = $true
  if ($have) { Ok "upgraded Fluent Bit from $have to $newVersion" } else { Ok "installed Fluent Bit $newVersion" }
}

# --- Sysmon ------------------------------------------------------------------

# The Sysmon configuration the script installs: every process start, DNS
# query, driver, remote thread, raw disk read, named pipe and WMI
# subscription; network connections except browsers'; images loaded that
# are not signed; access to LSASS; files created where programs and
# scripts are dropped; and changes to the registry keys malware uses to
# start again. It feeds the Sysmon detections without logging every file
# and registry write. Change it later with Sysmon64 -c <file>.
$SysmonConfig = @'
<Sysmon schemaversion="4.90">
  <HashAlgorithms>SHA256,IMPHASH</HashAlgorithms>
  <CheckRevocation/>
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <FileCreateTime onmatch="include"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="exclude">
        <Image condition="end with">\chrome.exe</Image>
        <Image condition="end with">\msedge.exe</Image>
        <Image condition="end with">\firefox.exe</Image>
        <Image condition="end with">\msedgewebview2.exe</Image>
      </NetworkConnect>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <ProcessTerminate onmatch="include"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <DriverLoad onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <ImageLoad onmatch="include">
        <Signed condition="is">false</Signed>
      </ImageLoad>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <CreateRemoteThread onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <RawAccessRead onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="end with">\lsass.exe</TargetImage>
      </ProcessAccess>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">\Start Menu\Programs\Startup\</TargetFilename>
        <TargetFilename condition="end with">.exe</TargetFilename>
        <TargetFilename condition="end with">.dll</TargetFilename>
        <TargetFilename condition="end with">.sys</TargetFilename>
        <TargetFilename condition="end with">.ps1</TargetFilename>
        <TargetFilename condition="end with">.vbs</TargetFilename>
        <TargetFilename condition="end with">.js</TargetFilename>
        <TargetFilename condition="end with">.hta</TargetFilename>
        <TargetFilename condition="end with">.bat</TargetFilename>
        <TargetFilename condition="end with">.cmd</TargetFilename>
        <TargetFilename condition="end with">.scr</TargetFilename>
        <TargetFilename condition="end with">.lnk</TargetFilename>
        <TargetFilename condition="end with">.iso</TargetFilename>
      </FileCreate>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="contains">\CurrentVersion\Run</TargetObject>
        <TargetObject condition="contains">\Policies\Explorer\Run</TargetObject>
        <TargetObject condition="contains">\Winlogon\</TargetObject>
        <TargetObject condition="contains">\Image File Execution Options\</TargetObject>
        <TargetObject condition="contains">\SilentProcessExit\</TargetObject>
        <TargetObject condition="contains">\CurrentControlSet\Services\</TargetObject>
        <TargetObject condition="contains">\Control\Lsa\</TargetObject>
        <TargetObject condition="contains">\Control\SecurityProviders\</TargetObject>
        <TargetObject condition="contains">\Windows Defender\</TargetObject>
        <TargetObject condition="contains">\Environment\</TargetObject>
        <TargetObject condition="contains">\Shell\Open\Command</TargetObject>
        <TargetObject condition="contains">\InprocServer32\</TargetObject>
        <TargetObject condition="contains">\AppInit_DLLs</TargetObject>
        <TargetObject condition="contains">\Terminal Server\</TargetObject>
      </RegistryEvent>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <FileCreateStreamHash onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <PipeEvent onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <WmiEvent onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <DnsQuery onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <FileDelete onmatch="include"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <ClipboardChange onmatch="include"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <ProcessTampering onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <FileDeleteDetected onmatch="include"/>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
'@

function Sysmon-Install {
  if (-not $Sysmon) { return }
  if ($DryRun) {
    if (-not (Manifest-Has "sysmon")) {
      Info "would download $SysmonUrl, check that Microsoft signed Sysmon64.exe, and install it with the configuration in this script"
      Manifest-Add "sysmon"
      $script:changed = $true
    }
    return
  }
  $existing = @(Get-Service -Name "Sysmon64", "Sysmon" -ErrorAction SilentlyContinue)
  if ($existing.Count -gt 0) {
    Ok "Sysmon is installed already ($($existing[0].Name)); it keeps its own configuration"
    return
  }
  $zip = Join-Path $script:tmp "Sysmon.zip"
  $pub = New-Object SignalithAgentInstall.Fetch2 $false
  $code = $pub.Get($SysmonUrl, "", $zip, 300, $true)
  if ($code -ne 200) {
    Fail "Could not download Sysmon from $SysmonUrl ($(if ($code) { "it answered $code" } else { $pub.Error }))." "Check that this computer reaches download.sysinternals.com, or run the line without -Sysmon."
  }
  $dir = Join-Path $script:tmp "sysmon"
  Expand-Archive -LiteralPath $zip -DestinationPath $dir -Force
  $exe = Join-Path $dir "Sysmon64.exe"
  if (-not (Test-Path -LiteralPath $exe)) { Fail "The Sysmon zip holds no Sysmon64.exe." }
  $sig = Get-AuthenticodeSignature -LiteralPath $exe
  if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)') {
    Fail "Sysmon64.exe from $SysmonUrl is not signed by Microsoft (signature: $($sig.Status)), so it was not installed." "Run the line again later, or without -Sysmon."
  }
  Ok "Sysmon64.exe is signed by Microsoft"
  $conf = Join-Path $ConfDir "sysmon.xml"
  Put-Text $conf $SysmonConfig | Out-Null
  # Choosing -Sysmon accepts the Sysinternals license, as the page says.
  $ErrorActionPreference = "Continue"
  $out = & $exe -accepteula -i $conf 2>&1
  $ErrorActionPreference = "Stop"
  if ($LASTEXITCODE -ne 0) {
    $out | Select-Object -Last 10 | ForEach-Object { Write-Host "      $_" }
    Fail "Installing Sysmon failed (exit code $LASTEXITCODE, see above)." "Run the line again without -Sysmon to install the agent alone."
  }
  Manifest-Add "sysmon"
  $script:changed = $true
  # The agent tells Signalith that Sysmon runs, which adds its log.
  $script:restart = $true
  Ok "installed Sysmon with the agent's configuration"
}

# --- osquery -----------------------------------------------------------------

# Osquery-Wanted says whether the agent runs osquery here: asked for now,
# or installed by an earlier run.
function Osquery-Wanted { return [bool]$Osquery -or (Manifest-Has "osquery") }

# Vendor-Osquery stops osquery's own service and turns it off: the agent
# runs osquery with its own flags, and two would share one database.
# -Uninstall turns it back on when osquery stays.
function Vendor-Osquery {
  $svc = Get-Service -Name "osqueryd" -ErrorAction SilentlyContinue
  if (-not $svc) { return }
  $start = (Get-CimInstance Win32_Service -Filter "Name='osqueryd'").StartMode
  if ($start -eq "Disabled" -and $svc.Status -eq "Stopped") { return }
  if (-not (Manifest-Has "osquery-msi")) { Manifest-Add "service-start osqueryd $start" }
  Stop-Service -Name "osqueryd" -Force -ErrorAction SilentlyContinue
  Set-Service -Name "osqueryd" -StartupType Disabled
  $script:changed = $true
  Ok "turned off osquery's own service (the agent runs osquery now)"
}

function Osquery-Install {
  if (-not (Osquery-Wanted)) { return }
  if ($DryRun) {
    if (-not (Manifest-Has "osquery")) {
      Info "would download $OsqueryUrl, check its signature, install it, and turn off osquery's own service"
      Manifest-Add "osquery"
      $script:changed = $true
    }
    return
  }
  if (Test-Path -LiteralPath $OsquerydExe) {
    Ok "osquery $(Program-Version $OsquerydExe)"
  } else {
    $msi = Join-Path $script:tmp "osquery.msi"
    $want = $OsquerySha256.ToLowerInvariant()
    if ($OsqueryMsi) {
      Copy-Item -LiteralPath $OsqueryMsi -Destination $msi
    } else {
      $pub = New-Object SignalithAgentInstall.Fetch2 $false
      $code = $pub.Get($OsqueryUrl, "", $msi, 600, $true)
      if ($code -ne 200) {
        Fail "Could not download osquery from $OsqueryUrl ($(if ($code) { "it answered $code" } else { $pub.Error }))." "Check that this computer reaches pkg.osquery.io; without internet access, download the MSI elsewhere and run the line again with -OsqueryMsi <path to the MSI>, or run it without -Osquery."
      }
    }
    if ($want) {
      $got = [SignalithAgentInstall.Fetch2]::Sha256File($msi)
      if ($got -ne $want) { Fail "The osquery MSI is not the one expected (its SHA-256 is $got, not $want), so it was not installed." "Download it again; if it keeps failing, it was changed on its way here." }
      Ok "osquery MSI checked (SHA-256 $($got.Substring(0, 12)))"
    } else {
      $sig = Get-AuthenticodeSignature -LiteralPath $msi
      if ($sig.Status -ne "Valid") {
        Fail "The osquery MSI has no valid signature (signature: $($sig.Status)), so it was not installed." "Run the line again later; or check the MSI's SHA-256 against the one on osquery.io/downloads and run the line again with -OsquerySha256 <it>; or run it without -Osquery."
      }
      Ok "osquery MSI signed by $($sig.SignerCertificate.Subject)"
    }
    $log = Join-Path $script:tmp "osquery-msi.log"
    $p = Start-Process -FilePath "msiexec.exe" -ArgumentList @("/i", "`"$msi`"", "/qn", "/norestart", "/l*v", "`"$log`"") -Wait -PassThru
    if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) {
      if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log -Tail 10 | ForEach-Object { Write-Host "      $_" } }
      Fail "Installing osquery failed (msiexec exit code $($p.ExitCode))." "Run the line again without -Osquery to install the agent alone."
    }
    Manifest-Add "osquery-msi"
    if (-not (Test-Path -LiteralPath $OsquerydExe)) { Fail "The osquery MSI did not put osqueryd at $OsquerydExe." "Run the line again without -Osquery to install the agent alone." }
    Ok "installed osquery $(Program-Version $OsquerydExe)"
    $script:changed = $true
    # The agent tells Signalith it has osquery, which adds osquery's part.
    $script:restart = $true
  }
  Vendor-Osquery
  if (-not (Manifest-Has "osquery")) {
    Manifest-Add "osquery"
    $script:changed = $true
    $script:restart = $true
  }
}

# --- The agent ---------------------------------------------------------------

function Agent-Service {
  if ($DryRun) { return $null }
  return Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
}

function Stop-Agent {
  $svc = Agent-Service
  if ($svc -and $svc.Status -ne "Stopped") {
    Stop-Service -Name $ServiceName -Force
    $svc.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(60))
  }
}

function Agent-Program {
  $out = Join-Path $script:tmp "agent.exe"
  $code = Sig-Get "/api/agent/program?os=windows&arch=$($script:arch)" $out 300
  switch ($code) {
    200 { }
    0 { Fail "Could not download the agent program from Signalith: $($script:sig.Error)" "Check that this computer can reach it, then run the line again." }
    404 { Fail "This Signalith has no agent program for Windows: $(Sig-Error $out)" "Install a released Signalith version, which carries the agent programs, or set up Fluent Bit by hand from Add data > Windows." }
    default { Fail "Signalith did not hand out the agent program (it answered $code): $(Sig-Error $out)" "Run the line again." }
  }
  $want = $script:sig.Sha256Header.ToLowerInvariant()
  if ($want -notmatch '^[0-9a-f]{64}$') { Fail "Signalith did not say the agent program's SHA-256." "Run the line again." }
  $got = [SignalithAgentInstall.Fetch2]::Sha256File($out)
  if ($got -ne $want) { Fail "The agent program downloaded is not whole (its SHA-256 differs)." "Run the line again." }
  if (-not (Test-Path -LiteralPath $Program) -or [SignalithAgentInstall.Fetch2]::Sha256File($Program) -ne $got) {
    Stop-Agent
    Copy-Item -LiteralPath $out -Destination $Program -Force
    Manifest-Add "file $Program"
    $script:changed = $true
    $script:restart = $true
  }
  Ok "the agent program ($($got.Substring(0, 12)))"
}

# Assert-NotLink stops when $Path is a link or junction: the agent, which
# runs as SYSTEM, would read and write wherever it points.
function Assert-NotLink([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { return }
  $item = Get-Item -LiteralPath $Path -Force
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
    Fail "$Path is a link or junction, which the script does not follow." "Look at what made it (it should be a plain folder), remove it, and run the line again."
  }
}

# Assert-SafeParent stops unless the folder $Path is in is a plain folder
# owned by SYSTEM, Administrators or TrustedInstaller: whoever may change that folder can
# swap the agent's folder for one of their own. (The agent checks the
# same each time it starts.)
function Assert-SafeParent([string]$Path) {
  $parent = Split-Path -Parent $Path
  Assert-NotLink $parent
  if ($DryRun) { return }
  $owner = (Get-Acl -LiteralPath $parent).GetOwner([Security.Principal.SecurityIdentifier]).Value
  if (@($system, $admins, $trustedInstaller) -notcontains $owner) {
    $name = $owner
    try { $name = ([Security.Principal.SecurityIdentifier]$owner).Translate([Security.Principal.NTAccount]).Value } catch { }
    Fail "$parent belongs to $name, not to SYSTEM or Administrators, so the agent's folder in it is not safe." "Make Administrators its owner (icacls `"$parent`" /setowner *$admins), and run the line again."
  }
}

function Agent-Folders {
  foreach ($dir in @($ConfDir, $ProgramDir)) {
    Assert-SafeParent $dir
    Assert-NotLink $dir
  }
  if ($DryRun) {
    New-Item -ItemType Directory -Force -Path $ConfDir, $ProgramDir | Out-Null
    return
  }
  if (-not (Test-Path -LiteralPath $ConfDir)) {
    New-PrivateFolder $ConfDir
  } else {
    Assert-Owned $ConfDir
  }
  Protect-Folder $ConfDir $false
  New-Item -ItemType Directory -Force -Path $ProgramDir | Out-Null
  Assert-Owned $ProgramDir
  Protect-Folder $ProgramDir $true
}

function Agent-Files {
  $files = @(
    @((Join-Path $ConfDir "token"), "$Token`n"),
    @((Join-Path $ConfDir "agent.conf"), "# Written by the Signalith Agent install script (deploy/agent/install.ps1).`n# Run the line from Add data again to change it.`nSERVER=$From`nSIGNALITH_VERSION=$Version`nOSQUERY=$(if (Osquery-Wanted) { 'yes' } else { 'no' })`n")
  )
  foreach ($f in $files) {
    if (Put-Text $f[0] $f[1]) { $script:changed = $true; $script:restart = $true }
  }
  $ca = Join-Path $ConfDir "ca.pem"
  if ($script:caPem) {
    if (Put-Text $ca $script:caPem) { $script:changed = $true; $script:restart = $true }
  } elseif ((Test-Path -LiteralPath $ca) -and (Manifest-Has "file $ca")) {
    Remove-Item -LiteralPath $ca -Force
    $script:changed = $true
    $script:restart = $true
  }
  # A copy of this script, for -Uninstall.
  $self = $PSCommandPath
  if ($self -and (Test-Path -LiteralPath $self)) {
    if (Put-Bytes $ScriptCopy ([IO.File]::ReadAllBytes($self))) { $script:changed = $true }
  }
  # Fluent Bit came from the temporary folder with its permissions: every
  # file gets the folder's own again.
  if (-not $DryRun) {
    Protect-Folder $ProgramDir $true
    Protect-Folder $ConfDir $false
  }
}

function Agent-Start {
  $bin = "`"$Program`" run"
  if ($DryRun) {
    if (-not (Manifest-Has "service $ServiceName")) {
      Would "New-Service -Name $ServiceName -BinaryPathName '$bin' -StartupType Automatic"
      Would "sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/60000"
      Manifest-Add "service $ServiceName"
    }
    Would "Restart-Service $ServiceName"
    return
  }
  $svc = Agent-Service
  if (-not $svc) {
    New-Service -Name $ServiceName -BinaryPathName $bin -DisplayName "Signalith Agent" -StartupType Automatic `
      -Description "Collects this computer's logs for Signalith: fetches what to collect from Signalith, runs Fluent Bit and reports its status." | Out-Null
    Manifest-Add "service $ServiceName"
  } else {
    # A service changed by hand runs the agent at its path again. (Set in
    # the registry: Windows PowerShell 5.1 cannot pass a quoted path to
    # sc.exe.)
    Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name ImagePath -Value $bin
    Set-Service -Name $ServiceName -StartupType Automatic
  }
  # Windows starts the agent again when it stops by itself: after 5 and 10
  # seconds, then each minute; the count resets after a day.
  & sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/60000 | Out-Null
  & sc.exe failureflag $ServiceName 1 | Out-Null
  $health = Join-Path $ConfDir "health"
  Stop-Agent
  if (Test-Path -LiteralPath $health) { Remove-Item -LiteralPath $health -Force }
  try {
    Start-Service -Name $ServiceName
  } catch {
    Fail "The agent's service did not start: $($_.Exception.Message)" "See $(Join-Path $ConfDir 'agent.log') and the Windows event log (System)."
  }
  Ok "started the agent"
  # The agent fetches its configuration, starts Fluent Bit and reports
  # within a few seconds; two minutes covers a slow network.
  $items = @{}
  $osq = Osquery-Wanted
  for ($i = 0; $i -lt 60; $i++) {
    $items = Read-Health $health
    if ($items["fluentbit"] -eq "running" -and $items["reported"] -eq "yes" -and (-not $osq -or $items["osquery"] -eq "running")) {
      if ($osq) { Ok "Fluent Bit and osquery run with Signalith's configuration, and Signalith has the agent's status" }
      else { Ok "Fluent Bit runs with Signalith's configuration, and Signalith has the agent's status" }
      return
    }
    if ((Get-Service -Name $ServiceName).Status -eq "Stopped" -and $i -gt 5) { break }
    Start-Sleep -Seconds 2
  }
  $log = Join-Path $ConfDir "agent.log"
  if ($items["config"] -ne "ok") {
    $why = $items["config"]
    if (-not $why) { $why = "no answer yet" }
    Fail "The agent could not get its configuration: $why" "See $log."
  }
  if ($items["fluentbit"] -ne "running") {
    $fb = $items["fluentbit"]
    if (-not $fb) { $fb = "not started" }
    Fail "Fluent Bit is not running: $fb" "See $log."
  }
  if ($items["reported"] -ne "yes") {
    Warn "Fluent Bit runs, but Signalith has not had the agent's status yet." "Check the Endpoints page in a few minutes; $log says why."
  }
  if ($osq -and $items["osquery"] -ne "running") {
    $oq = $items["osquery"]
    if (-not $oq) { $oq = "the agent has not started it" }
    Warn "osquery is not running yet: $oq" "Check the Endpoints page in a few minutes; $log says why."
  }
}

# Read-Health reads the short file the agent writes about itself: one
# item=value line each for config, fluentbit, osquery and reported.
function Read-Health([string]$Path) {
  $h = @{}
  if (Test-Path -LiteralPath $Path) {
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
      $k, $v = $line -split '=', 2
      if ($k -and -not $h.ContainsKey($k)) { $h[$k] = $v }
    }
  }
  return $h
}

# Remove-LineFromHistory takes the pasted line, which holds the token, out
# of PowerShell's saved history (PSReadLine saves each line as it runs).
function Remove-LineFromHistory {
  if (-not $script:tokenFromLine -or $DryRun) { return }
  try {
    $path = (Get-PSReadLineOption).HistorySavePath
    if ($path -and (Test-Path -LiteralPath $path)) {
      $lines = [IO.File]::ReadAllLines($path)
      $keep = @($lines | Where-Object { -not $_.Contains($Token) })
      if ($keep.Count -ne $lines.Count) {
        [IO.File]::WriteAllLines($path, [string[]]$keep)
        $script:scrubbed = $true
      }
    }
  } catch { }
}

# --- Removing ----------------------------------------------------------------

function Remove-Agent {
  if (-not $DryRun) {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
      Fail "Run this in PowerShell opened with Run as administrator: it removes a service."
    }
  }
  if (-not (Test-Path -LiteralPath $Manifest)) { Fail "This computer has no agent the script installed (no $Manifest)." }
  Say "Signalith Agent: removing what the install script added"
  $lines = @([IO.File]::ReadAllLines($Manifest))
  if ($lines -contains "service $ServiceName") {
    if ($DryRun) {
      Would "Stop-Service $ServiceName; sc.exe delete $ServiceName"
    } elseif (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
      Stop-Agent
      & sc.exe delete $ServiceName | Out-Null
      Ok "removed the SignalithAgent service"
    }
  }
  if ($lines -contains "sysmon") {
    if ($DryRun) {
      Would "Sysmon64.exe -u force"
    } elseif (Test-Path -LiteralPath (Join-Path $env:SystemRoot "Sysmon64.exe")) {
      $sysmonExe = Join-Path $env:SystemRoot "Sysmon64.exe"
      $ErrorActionPreference = "Continue"
      & $sysmonExe -u force 2>&1 | Out-Null
      $ErrorActionPreference = "Stop"
      if ($LASTEXITCODE -eq 0) { Ok "removed Sysmon, which the script installed" } else { Warn "Removing Sysmon failed (exit code $LASTEXITCODE)." "Sysmon64.exe -u force, in an elevated PowerShell." }
    }
  }
  if ($lines -contains "osquery-msi") {
    if ($DryRun) {
      Would "msiexec /x <osquery> /qn"
    } else {
      $product = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue |
        Where-Object { (Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue).DisplayName -eq "osquery" } | Select-Object -First 1
      if ($product -and $product.PSChildName -match '^\{[0-9A-Fa-f-]+\}$') {
        $p = Start-Process -FilePath "msiexec.exe" -ArgumentList @("/x", $product.PSChildName, "/qn", "/norestart") -Wait -PassThru
        if ($p.ExitCode -eq 0 -or $p.ExitCode -eq 3010) { Ok "removed osquery, which the script installed" }
        else { Warn "Removing osquery failed (msiexec exit code $($p.ExitCode))." "Remove osquery in Settings > Apps." }
      }
    }
  }
  foreach ($line in $lines) {
    if ($line -match '^service-start (fluent-bit|osqueryd) (\w+)$') {
      $name, $mode = $Matches[1], $Matches[2]
      $what = if ($name -eq "osqueryd") { "osquery's" } else { "Fluent Bit's" }
      if ($mode -eq "Auto") { $mode = "Automatic" }
      if ($DryRun) {
        Would "Set-Service $name -StartupType $mode; Start-Service $name"
      } elseif (Get-Service -Name $name -ErrorAction SilentlyContinue) {
        try {
          Set-Service -Name $name -StartupType $mode
          if ($mode -eq "Automatic") { Start-Service -Name $name }
          Ok "turned $what own service back on"
        } catch { Warn "Could not turn $what own service back on: $($_.Exception.Message)" "Set-Service $name -StartupType Automatic; Start-Service $name" }
      }
    }
  }
  # The program folder holds this script's copy too; PowerShell has read
  # the whole script already.
  foreach ($dir in @($ProgramDir, $ConfDir)) {
    if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
  }
  Ok "removed the agent's files"
  Say ""
  Say "The agent is removed. If no other computer uses its token, revoke it in Signalith: Settings > Agent tokens."
}

# --- Main --------------------------------------------------------------------

$status = 0
try {
  New-Item -ItemType Directory -Force -Path $script:tmp | Out-Null
  if ($Uninstall) {
    Remove-Agent
  } else {
    Check-Args
    Say "Signalith Agent: checking this computer"
    Check-Machine
    Say ""
    Say "Signalith"
    Check-CA
    Check-Token
    Say ""
    Say "Installing"
    Agent-Folders
    # Left by a run that was stopped halfway (by a power cut, say).
    Get-ChildItem -LiteralPath $ConfDir -Filter "*.signalith-new" -Force | Remove-Item -Force
    if (-not $DryRun) { Vendor-FluentBit }
    FluentBit-Install
    Sysmon-Install
    Osquery-Install
    Agent-Program
    Agent-Files
    Say ""
    $svc = Agent-Service
    if (-not $script:changed -and ($DryRun -or ($svc -and $svc.Status -eq "Running"))) {
      Say "Nothing to change: the agent is set up as the line says."
    } else {
      Say "Starting"
      Agent-Start
      Say ""
      if ($script:warned -gt 0) {
        Say "Done, with $($script:warned) warning(s) above. This computer shows on the Endpoints page in Signalith."
      } else {
        Say "Done. This computer shows on the Endpoints page in Signalith, and its events in Search within a minute."
      }
    }
  }
} catch [AgentInstallStop] {
  $status = 1
} catch {
  Write-Host ("  " + [char]0x2717 + " " + $_.Exception.Message) -ForegroundColor Red
  Write-Host "      Fix: run the line again; if it fails the same way, tell us what it says." -ForegroundColor Red
  $status = 1
} finally {
  if (Test-Path -LiteralPath $script:tmp) { Remove-Item -LiteralPath $script:tmp -Recurse -Force -ErrorAction SilentlyContinue }
  Remove-LineFromHistory
}
if ($script:scrubbed) { Say "The line, which holds the token, was taken out of PowerShell's saved history. Close this window to clear it from the window's own history too." }
exit $status
