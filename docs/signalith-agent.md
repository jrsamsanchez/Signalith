---
description: Install the Signalith Agent with one line per Linux or Windows computer. It fetches what to collect from Signalith, runs Fluent Bit and osquery for you and reports how they are, so there is no configuration file to edit.
---

# Signalith Agent

The Signalith Agent is one small program per computer that takes care of collecting its
logs. You paste one line on the computer; after that, nothing is configured by hand:

- the line installs Fluent Bit and osquery from their publishers and the agent from your
  Signalith server (and, on Windows, Sysmon from Microsoft if you choose);
- every five minutes the agent asks Signalith what to collect, writes Fluent Bit's
  configuration and osquery's settings, and restarts them when they changed;
- it keeps them running, starting them again when they stop, and tells Signalith how
  they are, which the [Endpoints page](endpoints.md) shows for each computer.

The agent does not collect anything itself: Fluent Bit reads the logs and sends them, as
with a configuration you set up by hand ([Agents and syslog](sending-data.md)), and
osquery reports inventory and file changes and answers live queries, as with the
[osquery option](endpoints.md). Setting Fluent Bit or osquery up by hand, the
OpenTelemetry Collector, syslog and Splunk HEC senders all keep working; the agent is the
easy way, not the only one.

## What it runs on

On **Linux**, the install line supports these systems, on 64-bit x86 (amd64) and 64-bit
ARM (arm64):

| System | Versions |
|---|---|
| Ubuntu | 22.04, 24.04 |
| Debian | 12, 13 |
| Red Hat Enterprise Linux, Rocky Linux, AlmaLinux, Oracle Linux | 8, 9 |
| Amazon Linux | 2023 |

The computer needs systemd, `curl`, and outbound HTTPS to Signalith's agent port (7779 by
default), to `packages.fluentbit.io` and, for osquery, to `pkg.osquery.io`.

On **Windows**: Windows 10 or 11 and Windows Server 2016 or later, 64-bit x86, with
outbound HTTPS to Signalith's agent port, to `packages.fluentbit.io`, for osquery to
`pkg.osquery.io`, and for Sysmon to `download.sysinternals.com`. The line runs in Windows PowerShell 5.1 (part of Windows) or
PowerShell 7, opened with **Run as administrator**.

On **macOS**: macOS 12 or later, on Apple silicon or Intel, with outbound HTTPS to
Signalith's agent port and to `pkg.osquery.io`. On a Mac the agent runs osquery, which
collects process starts, sign-ins, file changes and the inventory (see [On a Mac](#on-a-mac)).

Nothing has to reach the computer.

## Install it

1. In Signalith, open **Add data** and pick **Signalith Agent** (admins only).
2. Check **Agents send to**: the address the computer reaches Signalith at, on the agent
   port, such as `https://siem.example.com:7779`.
3. Name the token, or keep the name given, and select **Copy**. Signalith makes an agent
   token for the computers you install from this line and puts it in the line.
4. Pick **Linux**, **Windows** or **macOS** above the line. **Also install osquery** is ticked; untick
   it to leave osquery out (see [osquery](#osquery)). On Windows, tick **Also install
   Sysmon** to add it (see [Sysmon](#sysmon-on-windows)).
5. On the computer, paste the line: on Linux and macOS in a terminal, as a user who can
   use `sudo`; on Windows in PowerShell opened with **Run as administrator**.

The Linux line looks like this (the page fills in the real values):

```sh
 f=$(mktemp) && curl -fsSk --proto '=https' https://siem.example.com:7779/api/agent/install.sh -o "$f" \
  && echo "<sha-256>  $f" | sha256sum -c --quiet \
  && echo 'sgl_…' | sudo sh "$f" --from https://siem.example.com:7779 --ca-sha256 <hex> --version 0.4.0 --token - --osquery
```

The Windows line does the same in PowerShell, ending with
`'sgl_…' | & $f -From https://siem.example.com:7779 -CaSha256 <hex> -Version 0.4.0 -Token - -Osquery`.
The macOS line fetches `install-macos.sh` instead, checks it with `shasum -a 256`, and
always installs osquery.

The script checks the computer, then Signalith, before it installs anything, and stops
with a plain message at the first problem. When it finishes, the computer shows on the
**Endpoints** page and its events in **Search** within a minute; **Add data** shows when
the agent has reported.

Use the same line on as many computers as you like: they share its token. Make a new line
(with a new token) for each group you may want to cut off on its own, such as web servers
and domain controllers.

To see what it would change first, add `--dry-run /tmp/agent` (Linux and macOS) or
`-DryRun $env:TEMP\agent` (Windows) to the end of the line: it writes every file under
that folder and prints the commands instead of running them.

## How it stays safe

- **The script is checked before it runs.** The line downloads it without trusting the
  server's certificate (the computer does not know Signalith's certificate authority
  yet), then checks its SHA-256 against the one in the line before running it.
- **Signalith is checked before the token is sent.** The script downloads Signalith's
  certificate authority and refuses it unless its SHA-256 is the one in the line
  (`--ca-sha256`). Every later request, by the script and then by the agent, checks
  Signalith's certificate with it. When Signalith's certificate is from a public
  authority, the line names none and the computer's own trusted authorities check it.
- **The token is never on a command line.** On Linux it reaches the script on its
  standard input (`--token -`), so other users of the computer cannot see it in the
  process list, and the line starts with a space, which keeps it out of bash's history on
  Ubuntu and Debian. On Windows it reaches the script through the pipeline in the same
  PowerShell, and the script takes the line out of PowerShell's saved history when it is
  done. On the computer it is in a file only root (Linux) or SYSTEM and Administrators
  (Windows) can read; Fluent Bit's configuration does not hold it (Fluent Bit reads it
  from its environment).
- **Packages come from their publishers.** On Linux, Fluent Bit comes from Fluent Bit's
  own signed package repository; the script refuses its signing key unless its
  fingerprint is the one pinned in the script. On Windows, the script downloads the
  Fluent Bit version it pins from Fluent Bit's site and checks the zip's SHA-256 against
  the one the publisher lists next to it (or against `-FluentBitSha256`). Fluent Bit publishes no signing key for the Windows zip; checking it against a SHA-256 carried in Signalith's signed content updates is planned, together with signed agent updates. osquery
  comes from osquery's own signed package repository on Linux, its signing key pinned the
  same way; on Windows the script downloads the osquery MSI version it pins and installs
  it only when its Authenticode signature is valid (or its SHA-256 is the one given with
  `-OsquerySha256`); checking it against a SHA-256 in Signalith's signed content updates
  comes with signed agent updates, as for Fluent Bit's zip. Sysmon is
  downloaded from Microsoft and used only when Microsoft's signature on it is valid. The
  agent program comes from your Signalith server, and the script checks its SHA-256
  against the one Signalith gives with it.
- **What the server can change is limited.** The server sends the agent Fluent Bit's
  configuration, osquery's settings and the certificate authorities to trust. The agent
  passes osquery only the settings it knows (where Signalith is and how often to ask),
  never ones that load other programs into osquery, and names osquery's files itself. The agent keeps a new set of
  authorities only when it still trusts the server it is talking to, so a mistake cannot
  cut the computer off. Where packages come from, and their signing keys, are in the
  script, never in what the server sends.
  The server does decide what Fluent Bit reads and where it sends, as root on every
  computer with the agent, within the limits below: guard Signalith's admin accounts and
  the server itself as you would any tool that manages your computers.
- **The service is fenced in.** On Linux the agent runs as root so Fluent Bit can read
  every log, but its systemd service keeps only the right to read files
  (`CapabilityBoundingSet=CAP_DAC_READ_SEARCH`), sees the system read-only
  (`ProtectSystem=strict`) and writes only its own two folders. On Windows it runs as
  SYSTEM, which reading the Security log needs; its folders are owned by Administrators
  and only SYSTEM and Administrators can change them (the script refuses a data folder
  someone else made first, or a link in its place, and the agent refuses to start when
  its folder or the one above it is not owned by SYSTEM or Administrators), and Fluent Bit and osquery run in a job object, so they never outlive the
  agent. On Linux osquery runs in a service of its own, `signalith-osquery`, because it
  reads the whole computer, which the agent's fenced-in service may not: Fluent Bit,
  which reads log lines anyone can write to, stays fenced in. Before osquery starts, its
  service checks the settings the agent wrote, outside the agent's service, and osquery
  runs with the checked copy with extensions off, so nothing in the agent's service can
  hand osquery more. osquery's `curl` and `curl_certificate` tables, which would make the
  computer fetch any address, are off whatever the server sends.
- **It cannot take over the computer's memory or CPU.** On Linux the agent's service,
  which runs Fluent Bit too, may use at most 512 MB of memory and two CPU cores
  (`MemoryMax=512M`, `CPUQuota=200%`), and osquery's at most 512 MB and one core; on
  Windows each collector may commit at most 512 MB. One that goes past it is stopped
  and started again. Computers set up before 0.3.2 get these when you run the line again.
- **Updates are signed.** An agent updates itself only to a program listed in a manifest
  signed with the Signalith release key, whose public key is built into the agent, and
  only to a newer version. A server that was broken into can hand out neither a program
  of its own nor an older one with a known flaw. See [Updates](#updates).

## On the computer

### Linux

| Path | What it is |
|---|---|
| `/usr/local/sbin/signalith-agent` | The agent program |
| `/etc/signalith-agent/agent.conf` | The server address, and whether osquery is set up, written by the install line |
| `/etc/signalith-agent/token` | The agent token (root only) |
| `/etc/signalith-agent/ca.pem` | Signalith's certificate authority |
| `/etc/signalith-agent/fluent-bit.conf` | Fluent Bit's configuration, written by the agent |
| `/var/lib/signalith-agent/` | The configuration in use, Fluent Bit's buffer and positions, the agent's status |
| `/etc/signalith-agent/osquery.flags` | osquery's settings, written by the agent |
| `/etc/systemd/system/signalith-agent.service` | The agent's service |
| `/etc/systemd/system/signalith-osquery.service` | osquery's service, which runs while `osquery.flags` exists |
| `/etc/systemd/system/signalith-osquery-flags.path` | Restarts osquery when the agent writes new settings |
| `/usr/local/lib/signalith-agent/install.sh` | A copy of the install script, for `--uninstall` |

Fluent Bit's own `fluent-bit` service and osquery's own `osqueryd` service are masked, so
there is never a second copy: the agent runs Fluent Bit, and osquery runs as
`signalith-osquery` with the agent's settings.

Useful commands:

```sh
sudo signalith-agent status            # how the agent and Fluent Bit are
sudo systemctl status signalith-agent  # the service
sudo journalctl -u signalith-agent -n 50   # the agent's and Fluent Bit's log
sudo journalctl -u signalith-osquery -n 50 # osquery's log
```

### Windows

| Path | What it is |
|---|---|
| `C:\Program Files\Signalith Agent\signalith-agent.exe` | The agent program |
| `C:\Program Files\Signalith Agent\fluent-bit\` | Fluent Bit |
| `C:\Program Files\Signalith Agent\install.ps1` | A copy of the install script, for `-Uninstall` |
| `C:\ProgramData\Signalith Agent\` | The settings, token and certificate authority (SYSTEM and Administrators only), Fluent Bit's configuration and buffer, osquery's settings and database, the agent's status and its log, `agent.log` |
| `C:\Program Files\osquery\` | osquery, from its MSI |

The agent is the **SignalithAgent** service, which Windows starts at boot and starts again
when it stops. If Fluent Bit was installed by hand and its `fluent-bit` service sends to
Signalith, the script stops and turns it off, so events do not arrive twice; one that
sends elsewhere is left alone. osquery's own `osqueryd` service is turned off: the agent
runs osquery.

Useful commands, in an elevated PowerShell:

```powershell
& 'C:\Program Files\Signalith Agent\signalith-agent.exe' status   # how the agent and Fluent Bit are
Get-Service SignalithAgent                                          # the service
Get-Content 'C:\ProgramData\Signalith Agent\agent.log' -Tail 50    # the agent's and Fluent Bit's log
```

### macOS

| Path | What it is |
|---|---|
| `/opt/signalith-agent/bin/signalith-agent` | The agent program |
| `/etc/signalith-agent/agent.conf` | The server address, written by the install line |
| `/etc/signalith-agent/token` | The agent token (root only) |
| `/etc/signalith-agent/ca.pem` | Signalith's certificate authority |
| `/etc/signalith-agent/osquery.flags` | osquery's settings, written by the agent |
| `/var/lib/signalith-agent/` | The configuration in use, osquery's database, the agent's status, its log `agent.log` and the updater's log `updater.log` |
| `/Library/LaunchDaemons/io.signalith.agent.plist` | The agent's service, which macOS starts at boot and starts again when it stops |
| `/opt/osquery/` | osquery, from its signed package |
| `/opt/signalith-agent/lib/install-macos.sh` | A copy of the install script, for `--uninstall` |

The agent runs osquery itself. If osquery's own `io.osquery.agent` service was set up by
hand, the script warns about it, since both would send the same events; remove it with
`sudo launchctl bootout system/io.osquery.agent`.

Useful commands:

```sh
sudo /opt/signalith-agent/bin/signalith-agent status   # how the agent and osquery are
sudo launchctl print system/io.signalith.agent         # the service
sudo tail -n 50 /var/lib/signalith-agent/agent.log     # the agent's and osquery's log
```

### All of them

When Signalith cannot be reached, the agent keeps running the configuration it has and
Fluent Bit keeps events in its buffer until Signalith is back. The buffer holds at most
1 GB on disk (4 GB on a network sensor); past that, the oldest events are dropped rather
than filling the computer's disk.

When Signalith refuses the computer's token three times in a row (it was revoked, or the
server no longer knows it), the agent stops Fluent Bit and osquery instead of having them
read events Signalith would refuse. They keep their place in each log, and start again
from it once Signalith accepts the token. `signalith-agent status` shows why they stopped.

## What it collects

On Linux, the agent collects what the **Linux** option on **Add data** collects: sign-ins,
`sudo`, account changes and the other Linux logs the detections use. It reads the sign-in
log from `/var/log/auth.log` or `/var/log/secure` when the computer has one, and from the
systemd journal otherwise, and adds Sysmon for Linux's events when Sysmon is installed.

On Windows, it collects what the **Windows** option collects: the Security, System and
Application logs, Defender, PowerShell (with script blocks) and the other event logs the
detections use, and Sysmon's log when Sysmon is installed.

On macOS, everything comes from osquery: process starts (from Apple's EndpointSecurity,
once osquery has Full Disk Access), the inventory, file changes in the watched folders,
and the checks on the [Endpoints page](endpoints.md). The choices below that name a
Linux or Windows log do nothing on a Mac; turning **osquery** off stops the Mac's
collection.

### Change what agents collect

Everything above is on by default. To change it, open **Endpoints > What hosts collect**
and pick an **Install line**: the choices apply to every computer installed with that
line's token, so give different groups (web servers, desktops) their own line on **Add
data** and choose for each. Agents pick up a change the next time they ask for their
configuration, within 5 minutes; nothing needs to be done on the computers.

| Choice | What it does |
| --- | --- |
| **osquery** | Off stops osquery on computers that have it (it stays installed) |
| **Sysmon** | Off stops reading Sysmon's events on Windows and Linux |
| **PowerShell logs** | Off stops reading Windows PowerShell's logs |
| **Web server logs** | Off stops reading Apache's and Nginx's access logs on Linux |
| **Audit log** | Off stops reading the Linux audit log |
| **Linux sign-ins** | Where sign-ins are read from: where the computer writes them (the default), `auth.log` or `secure`, or the systemd journal |
| **Automatic updates** | Off keeps the line's computers on the version they run (see [Updates](#updates)) |

Turning a log off hides what happens on those computers, so saving asks for your
password again (see [Confirming it's you](users.md#confirming-its-you)), and each change
goes to the audit log as `agent collection settings changed`, with what it was before
and after, so a gap in what detections see can be traced to the change. Only admins can change it;
analysts see it in the token list. The osquery part of the same window (watched files,
checks and how often they run) applies to every osquery host. The API is
`PUT /api/agent-tokens/{id}/collect` with `{"osquery": "off", "linux_log": "journal"}`
(any choice left out is on, or `auto` for `linux_log`).

## osquery

With **Also install osquery** ticked (the line ends with `--osquery`, or `-Osquery` on
Windows), the computer also runs [osquery](https://osquery.io), with Signalith as its
management server: its inventory, file changes and live queries are on the
[Endpoints page](endpoints.md), as with the osquery option, with nothing to set up on the
computer.

- On Linux the script adds osquery's signed package repository and installs the `osquery`
  package; on Windows it installs osquery's MSI (see
  [How it stays safe](#how-it-stays-safe)). An osquery already installed is used as it is.
- The agent writes osquery's settings from what Signalith hands out. osquery enrolls with
  the agent token, so revoking the token cuts off both, and checks Signalith's
  certificate with the same certificate authority as the agent.
- osquery checks Signalith's certificate against the address it connects to. With an IP
  address as **Agents send to**, that works only when Signalith uses its own certificate
  authority; otherwise the Endpoints page shows osquery as off, with why, and Fluent Bit
  keeps working. Use a host name the certificate covers.
- A run again without `--osquery` keeps osquery once the script installed it.
  `--uninstall` removes osquery only if the script installed it, and turns osquery's own
  service back on otherwise.

## On a Mac

macOS keeps its system logs in a form only Apple's own tools read, so on a Mac the agent
collects with osquery, which reads what the detections need through Apple's interfaces.

- The script installs osquery's package from `pkg.osquery.io` only when it is signed by
  osquery's developer (Apple Developer ID team `3522FA9PXF`), checked with `pkgutil`, and
  runs an osquery already installed only when `codesign` shows the same signer. Give
  `--osquery-sha256 <hex>` to check the package against a SHA-256 instead.
- osquery needs **Full Disk Access** to see process starts and files under users' home
  folders. macOS lets only a person at the Mac (or a device management profile) grant it:
  open **System Settings > Privacy & Security > Full Disk Access**, select **+**, press
  **Cmd+Shift+G**, type `/opt/osquery/lib/osquery.app` and add it. The script prints the
  same steps when it finishes. With a management tool such as Jamf or Intune, grant it
  with a Privacy Preferences Policy Control profile for the bundle ID `io.osquery.agent`
  instead, before or after running the line.
- The agent programs for macOS are not notarized by Apple. The line downloads the agent
  with `curl`, which macOS does not mark as downloaded from the internet, so Gatekeeper
  does not stop it; do not copy the program to Macs by other means.

## Process creation auditing on Windows

Most Windows detections read program starts with their command lines. Without Sysmon,
these come from the Security log's event 4688, which Windows writes only when **Audit
Process Creation** is on, and which names the command line only when **Include command
line in process creation events** is on. Both are off in a new Windows and both are in
the CIS benchmarks, so the install script turns them on (`auditpol` for the first, the
`ProcessCreationIncludeCmdLine_Enabled` policy value for the second). Add
`-NoProcessAuditing` to the line to leave them as they are. A domain group policy that
sets either one wins over the script; set them there for every computer instead.

Command lines can hold secrets that someone typed into one, such as a password given to
a program as an argument. The Security log is readable only by administrators, and in
Signalith by the roles that may search the Windows events. `-Uninstall` leaves the
auditing on.

## Sysmon on Windows

Sysmon records process starts with their command lines, network connections, DNS
queries, registry changes and more, which many detections need. Windows does not include
it, and its license does not allow anyone but Microsoft to hand it out, so the agent does
not carry it. Tick **Also install Sysmon** on **Add data** (the line then ends with
`-Sysmon`) and the script:

- downloads Sysmon from Microsoft (`download.sysinternals.com`) and installs it only
  when Microsoft's signature on `Sysmon64.exe` is valid;
- installs it with a configuration made for Signalith's detections: every process
  start, DNS query, driver, remote thread, named pipe and WMI subscription, network
  connections except web browsers', unsigned modules loaded, access to LSASS, programs
  and scripts written to disk, and changes to the registry keys malware uses to start
  again. It is in the script, and you can change it later with `Sysmon64 -c <file>`;
- leaves a Sysmon already installed, and its configuration, as it is.

Ticking it accepts the [Sysinternals license](https://learn.microsoft.com/sysinternals/license-terms).
The agent tells Signalith that Sysmon runs, and Signalith adds Sysmon's log to what Fluent
Bit reads. `-Uninstall` removes Sysmon only if the script installed it.

## Updates

Agents keep themselves up to date with the Signalith server: when the server is upgraded
to a release with a newer agent, each agent installs it on its own within a few minutes,
and nothing needs to be done on the computers.

How it works, and why it is safe:

1. The release build signs a manifest listing each agent program's SHA-256 and the
   version. The server hands out the programs and the manifest it came with.
2. The agent downloads the manifest and the program, and checks the manifest's
   signature with the release key built into it, that the version is newer than its
   own, and that the program's SHA-256 is the one listed. It then runs the new program
   once to see it starts.
3. The updater installs it: on Linux the `signalith-agent-update` service, which runs
   outside the agent's fenced-in service (the agent itself cannot change its own
   program); on Windows a copy of the agent. The updater checks the signature and the
   SHA-256 again itself, keeps the version before, and restarts the agent.
   Neither takes a manifest signed with a revoked key: the server hands each agent
   its [revocation list](key-management.md#revocation-lists), and the agent and the
   updater each keep the newest one they have seen.
4. If the new version does not reach Signalith within 3 minutes, or does not keep running, the
   updater puts the version before back and restarts it. The computer's row on the
   **Endpoints** page then says the update failed, with the reason.

To hold a group of computers at the version they run, turn **Automatic updates** off for
their install line in **Endpoints > What hosts collect**. That is also how to roll a
release out in stages: leave updates on for a small test line first, and turn them on for
the others once it looks good. Turning updates back on lets the line catch up.

Agents installed before signed updates, and builds made from source (which have no
release key), do not update themselves; run the install line again to upgrade them.
To see what the server hands out, run `signalith agent-programs status` on it.

## Computers without internet access

On Windows, download `fluent-bit-<version>-win64.zip` (the version is at the top of the
script) from [Fluent Bit's site](https://docs.fluentbit.io/manual/installation/downloads/windows),
copy it to the computer and add `-FluentBitZip <path to the zip>` (and
`-FluentBitSha256 <its SHA-256>` to have it checked) to the line. For osquery, download
`osquery-<version>.msi` from [osquery's site](https://osquery.io/downloads) and add
`-OsqueryMsi <path to the MSI>` (and `-OsquerySha256 <its SHA-256>`). The computer still
needs to reach Signalith.

## Run it again, or remove it

Running the line again is safe: it changes only what differs, upgrades Fluent Bit and the
agent (and, on Linux, osquery), and repairs what was changed. Without `--token -` (and the `echo` before it), or
`-Token -` on Windows, it keeps the computer's token.

To remove the agent, Fluent Bit, osquery if the script installed it, and every file the
script wrote:

```sh
sudo sh /usr/local/lib/signalith-agent/install.sh --uninstall
```

On Windows, in an elevated PowerShell:

```powershell
& 'C:\Program Files\Signalith Agent\install.ps1' -Uninstall
```

On macOS:

```sh
sudo sh /opt/signalith-agent/lib/install-macos.sh --uninstall
```

Then revoke the line's token in **Settings > Agent tokens** if no other computer uses it.

## When something goes wrong

The install line says what stopped it and how to fix it. The common ones:

| It says | Do this |
|---|---|
| Signalith refused the token | Make the line again on **Add data**: the token was revoked, or the line was cut off when copied. |
| This Signalith's certificate authority is not the one the line names | Copy the line again. If it keeps failing, something between the computer and Signalith is answering in its place. |
| This Signalith has no agent program | Signalith was built from source. Released versions (packages, Docker image) carry the agent programs. |
| Update failed | The agent went back to the version before. `sudo journalctl -u signalith-agent-update -n 50` (Linux), `C:\ProgramData\Signalith Agent\updater.log` (Windows) or `sudo tail /var/lib/signalith-agent/updater.log` (macOS) shows why. |
| Fluent Bit is not running | `sudo journalctl -u signalith-agent -n 50` (Linux) or `agent.log` (Windows) shows Fluent Bit's last lines. |
| osquery is not running yet | `sudo journalctl -u signalith-osquery -n 50` (Linux) or `agent.log` (Windows and macOS) shows osquery's last lines. |
| No process starts from a Mac | Give osquery Full Disk Access (see [On a Mac](#on-a-mac)). |
| The agent runs on macOS 12 or later | Update macOS, or set osquery up by hand from **Add data > osquery**. |
| The osquery MSI has no valid signature | Check the MSI's SHA-256 against the one on osquery's download page and add `-OsquerySha256 <hex>`, or run the line without `-Osquery`. |
| Run this in PowerShell opened with Run as administrator | Right-click PowerShell, choose **Run as administrator**, and paste the line again. |
| The Microsoft Visual C++ runtime it needs is missing | Install it from Microsoft (the message has the link) and run the line again. |
| Could not get the SHA-256 Fluent Bit's publisher lists | Add `-FluentBitSha256 <hex>` with the SHA-256 shown on Fluent Bit's download page. |

On the **Endpoints** page, a computer whose Fluent Bit or osquery stopped, or that could
not get its configuration, has a warning, with their last lines.

## For developers

The server side is in `internal/api/agentmanaged.go`: `GET /api/agent/install` (admins)
makes the line, and the routes the script and agent call with the agent token are
`GET /api/agent/program`, `GET /api/agent/manifest` (the programs' signed manifest),
`GET /api/agent/config` (answered `304` when the agent has the latest; it offers an
update in `update`) and `POST /api/agent/status`. Updates are in
`internal/agentd/update.go` and the release key in `internal/agentproto/release.keys`. What the agent and server say to each other is in
`internal/agentproto`. The agent is `cmd/signalith-agent` and `internal/agentd`; the
install scripts are `deploy/agent/install.sh`, `deploy/agent/install.ps1` and
`deploy/agent/install-macos.sh` (served at `GET /api/agent/install.sh`,
`GET /api/agent/install.ps1` and `GET /api/agent/install-macos.sh`). The server hands out the agent programs in
`/usr/share/signalith/agents` (the packages and the Docker image put them there), the
`agents` folder next to the `signalith` program, or the folder in
`SIGNALITH_AGENT_PROGRAMS`.
