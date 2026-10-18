---
description: Install the Signalith Agent with one line per Linux or Windows computer. It fetches what to collect from Signalith, runs Fluent Bit for you and reports how it is, so there is no configuration file to edit.
---

# Signalith Agent

The Signalith Agent is one small program per computer that takes care of collecting its
logs. You paste one line on the computer; after that, nothing is configured by hand:

- the line installs Fluent Bit from its publisher and the agent from your Signalith
  server (and, on Windows, Sysmon from Microsoft if you choose);
- every five minutes the agent asks Signalith what to collect, writes Fluent Bit's
  configuration and restarts Fluent Bit when it changed;
- it keeps Fluent Bit running, starting it again when it stops, and tells Signalith how
  it is, which the [Endpoints page](endpoints.md) shows for each computer.

The agent does not collect anything itself: Fluent Bit reads the logs and sends them, as
with a configuration you set up by hand ([Agents and syslog](sending-data.md)). Setting
Fluent Bit up by hand, the OpenTelemetry Collector, syslog and Splunk HEC senders all
keep working; the agent is the easy way, not the only one.

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
default) and to `packages.fluentbit.io`.

On **Windows**: Windows 10 or 11 and Windows Server 2016 or later, 64-bit x86, with
outbound HTTPS to Signalith's agent port, to `packages.fluentbit.io` and, for Sysmon, to
`download.sysinternals.com`. The line runs in Windows PowerShell 5.1 (part of Windows) or
PowerShell 7, opened with **Run as administrator**.

Nothing has to reach the computer. macOS is next; until then, use
[osquery](endpoints.md) or the [OpenTelemetry Collector](opentelemetry.md) for Macs.

## Install it

1. In Signalith, open **Add data** and pick **Signalith Agent** (admins only).
2. Check **Agents send to**: the address the computer reaches Signalith at, on the agent
   port, such as `https://siem.example.com:7779`.
3. Name the token, or keep the name given, and select **Copy**. Signalith makes an agent
   token for the computers you install from this line and puts it in the line.
4. Pick **Linux** or **Windows** above the line. On Windows, tick **Also install Sysmon**
   to add it (see [Sysmon](#sysmon-on-windows)).
5. On the computer, paste the line: on Linux in a terminal, as a user who can use `sudo`;
   on Windows in PowerShell opened with **Run as administrator**.

The Linux line looks like this (the page fills in the real values):

```sh
 f=$(mktemp) && curl -fsSk --proto '=https' https://siem.example.com:7779/api/agent/install.sh -o "$f" \
  && echo "<sha-256>  $f" | sha256sum -c --quiet \
  && echo 'sgl_…' | sudo sh "$f" --from https://siem.example.com:7779 --ca-sha256 <hex> --version 0.4.0 --token -
```

The Windows line does the same in PowerShell, ending with
`'sgl_…' | & $f -From https://siem.example.com:7779 -CaSha256 <hex> -Version 0.4.0 -Token -`.

The script checks the computer, then Signalith, before it installs anything, and stops
with a plain message at the first problem. When it finishes, the computer shows on the
**Endpoints** page and its events in **Search** within a minute; **Add data** shows when
the agent has reported.

Use the same line on as many computers as you like: they share its token. Make a new line
(with a new token) for each group you may want to cut off on its own, such as web servers
and domain controllers.

To see what it would change first, add `--dry-run /tmp/agent` (Linux) or
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
  the one the publisher lists next to it (or against `-FluentBitSha256`). Fluent Bit publishes no signing key for the Windows zip; checking it against a SHA-256 carried in Signalith's signed content updates is planned, together with signed agent updates. Sysmon is
  downloaded from Microsoft and used only when Microsoft's signature on it is valid. The
  agent program comes from your Signalith server, and the script checks its SHA-256
  against the one Signalith gives with it.
- **What the server can change is limited.** The server sends the agent Fluent Bit's
  configuration and the certificate authorities to trust. The agent keeps a new set of
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
  its folder or the one above it is not owned by SYSTEM or Administrators), and Fluent Bit runs in a job object, so it never outlives the
  agent.

## On the computer

### Linux

| Path | What it is |
|---|---|
| `/usr/local/sbin/signalith-agent` | The agent program |
| `/etc/signalith-agent/agent.conf` | The server address, written by the install line |
| `/etc/signalith-agent/token` | The agent token (root only) |
| `/etc/signalith-agent/ca.pem` | Signalith's certificate authority |
| `/etc/signalith-agent/fluent-bit.conf` | Fluent Bit's configuration, written by the agent |
| `/var/lib/signalith-agent/` | The configuration in use, Fluent Bit's buffer and positions, the agent's status |
| `/etc/systemd/system/signalith-agent.service` | The agent's service |
| `/usr/local/lib/signalith-agent/install.sh` | A copy of the install script, for `--uninstall` |

Fluent Bit's own `fluent-bit` service is masked, so there is never a second copy sending:
the agent runs Fluent Bit itself.

Useful commands:

```sh
sudo signalith-agent status            # how the agent and Fluent Bit are
sudo systemctl status signalith-agent  # the service
sudo journalctl -u signalith-agent -n 50   # the agent's and Fluent Bit's log
```

### Windows

| Path | What it is |
|---|---|
| `C:\Program Files\Signalith Agent\signalith-agent.exe` | The agent program |
| `C:\Program Files\Signalith Agent\fluent-bit\` | Fluent Bit |
| `C:\Program Files\Signalith Agent\install.ps1` | A copy of the install script, for `-Uninstall` |
| `C:\ProgramData\Signalith Agent\` | The settings, token and certificate authority (SYSTEM and Administrators only), Fluent Bit's configuration and buffer, the agent's status and its log, `agent.log` |

The agent is the **SignalithAgent** service, which Windows starts at boot and starts again
when it stops. If Fluent Bit was installed by hand and its `fluent-bit` service sends to
Signalith, the script stops and turns it off, so events do not arrive twice; one that
sends elsewhere is left alone.

Useful commands, in an elevated PowerShell:

```powershell
& 'C:\Program Files\Signalith Agent\signalith-agent.exe' status   # how the agent and Fluent Bit are
Get-Service SignalithAgent                                          # the service
Get-Content 'C:\ProgramData\Signalith Agent\agent.log' -Tail 50    # the agent's and Fluent Bit's log
```

### Both

When Signalith cannot be reached, the agent keeps running the configuration it has and
Fluent Bit keeps events in its buffer until Signalith is back.

## What it collects

On Linux, the agent collects what the **Linux** option on **Add data** collects: sign-ins,
`sudo`, account changes and the other Linux logs the detections use. It reads the sign-in
log from `/var/log/auth.log` or `/var/log/secure` when the computer has one, and from the
systemd journal otherwise, and adds Sysmon for Linux's events when Sysmon is installed.

On Windows, it collects what the **Windows** option collects: the Security, System and
Application logs, Defender, PowerShell (with script blocks) and the other event logs the
detections use, and Sysmon's log when Sysmon is installed.

Choosing what each group of computers collects from the **Endpoints** page is coming.

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

## Computers without internet access

On Windows, download `fluent-bit-<version>-win64.zip` (the version is at the top of the
script) from [Fluent Bit's site](https://docs.fluentbit.io/manual/installation/downloads/windows),
copy it to the computer and add `-FluentBitZip <path to the zip>` (and
`-FluentBitSha256 <its SHA-256>` to have it checked) to the line. The computer still
needs to reach Signalith.

## Run it again, or remove it

Running the line again is safe: it changes only what differs, upgrades Fluent Bit and the
agent, and repairs what was changed. Without `--token -` (and the `echo` before it), or
`-Token -` on Windows, it keeps the computer's token.

To remove the agent, Fluent Bit and every file the script wrote:

```sh
sudo sh /usr/local/lib/signalith-agent/install.sh --uninstall
```

On Windows, in an elevated PowerShell:

```powershell
& 'C:\Program Files\Signalith Agent\install.ps1' -Uninstall
```

Then revoke the line's token in **Settings > Agent tokens** if no other computer uses it.

## When something goes wrong

The install line says what stopped it and how to fix it. The common ones:

| It says | Do this |
|---|---|
| Signalith refused the token | Make the line again on **Add data**: the token was revoked, or the line was cut off when copied. |
| This Signalith's certificate authority is not the one the line names | Copy the line again. If it keeps failing, something between the computer and Signalith is answering in its place. |
| This Signalith has no agent program | Signalith was built from source. Released versions (packages, Docker image) carry the agent programs. |
| Fluent Bit is not running | `sudo journalctl -u signalith-agent -n 50` (Linux) or `agent.log` (Windows) shows Fluent Bit's last lines. |
| Run this in PowerShell opened with Run as administrator | Right-click PowerShell, choose **Run as administrator**, and paste the line again. |
| The Microsoft Visual C++ runtime it needs is missing | Install it from Microsoft (the message has the link) and run the line again. |
| Could not get the SHA-256 Fluent Bit's publisher lists | Add `-FluentBitSha256 <hex>` with the SHA-256 shown on Fluent Bit's download page. |

On the **Endpoints** page, a computer whose Fluent Bit stopped or that could not get its
configuration has a warning, with Fluent Bit's last lines.

## For developers

The server side is in `internal/api/agentmanaged.go`: `GET /api/agent/install` (admins)
makes the line, and the routes the script and agent call with the agent token are
`GET /api/agent/program`, `GET /api/agent/config` (answered `304` when the agent has the
latest) and `POST /api/agent/status`. What the agent and server say to each other is in
`internal/agentproto`. The agent is `cmd/signalith-agent` and `internal/agentd`; the
install scripts are `deploy/agent/install.sh` and `deploy/agent/install.ps1` (served at
`GET /api/agent/install.sh` and `GET /api/agent/install.ps1`). The server hands out the agent programs in
`/usr/share/signalith/agents` (the packages and the Docker image put them there), the
`agents` folder next to the `signalith` program, or the folder in
`SIGNALITH_AGENT_PROGRAMS`.
