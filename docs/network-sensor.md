# Network sensor (Zeek, Suricata)

A network sensor watches the traffic on your network and writes down what it sees. Signalith
reads what two free tools write, **Zeek** and **Suricata**, and turns it into searchable events,
threat intel matches, findings and a **Network** dashboard. It works for any network: an
office, a school, a clinic or a data centre.

## What a network sensor is

A network sensor is a small Linux computer (or virtual machine) that gets a copy of your
network traffic. The copy comes from a switch port set to **mirror** (also called SPAN) the
port your internet connection or servers are on, or from a **network tap**. The sensor only
listens: it never changes or blocks traffic.

```
  internet ── firewall ── switch ──── your computers and servers
                            │
                            │ mirror (SPAN) port: a copy of the traffic
                            ▼
                ┌───────────────────────────┐
                │ sensor (Linux)            │
                │  Zeek: what happened      │  HTTPS  ┌───────────┐
                │  Suricata: IDS alerts     │────────▶│ Signalith │
                │  Fluent Bit: sends logs   │         └───────────┘
                └───────────────────────────┘
```

Two programs run on the sensor, side by side:

- **Zeek** writes one log line for every connection, DNS lookup, web request, TLS session,
  certificate and file it sees. It answers "what happened on the network".
- **Suricata** checks the same traffic against a set of rules, such as the free **Emerging
  Threats Open** rules, and writes an alert when one matches (malware downloads, exploits,
  command and control traffic). It answers "was any of it known to be bad".

You can run either one alone, or both. **Fluent Bit**, the same agent Signalith uses
everywhere else, sends both programs' logs to Signalith over HTTPS.

## What you need

- **A copy of the traffic**: a switch port set to mirror the uplink, or a network tap. Most
  managed switches can mirror a port, even inexpensive ones.
- **A machine with two network ports**: one plugged into the mirror port (it only listens and
  has no IP address), and one for normal network access, to reach Signalith and get updates.
- **Linux**: Ubuntu Server 24.04 LTS is the easiest choice; Debian 12 or 13 and Rocky, Alma or Red
  Hat Enterprise Linux 9 work too. Zeek does not run on Windows. The simplest sensor is a
  spare mini PC with two network ports.

  If you only have Windows servers, the sensor can be a small Ubuntu virtual machine in
  Hyper-V, but Hyper-V's own port mirroring only copies traffic between virtual machines on
  the same virtual switch: it does not see your office network or internet link. To see the
  real network, the Hyper-V host needs a spare physical network port cabled to the switch's
  mirror port, given to the sensor virtual machine through an external virtual switch of its
  own (with **Allow management operating system to share this network adapter** turned off),
  and Hyper-V must be set to pass that port's mirrored traffic on to the virtual machine,
  which takes extra PowerShell settings. A mini PC is usually simpler.
- **Outbound HTTPS** from the sensor to Signalith's agent port (7779 by default), and to the package
  repositories and the rules site for updates. Nothing needs to reach the sensor: it opens no
  ports.

How big a sensor you need depends on how much traffic it sees:

| Traffic on the mirror port | Sensor | Events to Signalith per day | Signalith storage per day |
| --- | --- | --- | --- |
| Up to 100 Mbit/s (an office of about 50 people) | 4 CPU cores, 8 GB memory, 100 GB disk | 1 to 3 million | 1.5 to 4 GB |
| Up to 1 Gbit/s | 8 CPU cores, 16 GB memory, 250 GB SSD, an Intel network card | 10 to 30 million | 15 to 40 GB |
| Several Gbit/s | 16 or more CPU cores, 32 GB or more memory, a network card with RSS; or one sensor per uplink | 50 million and up | 75 GB and up |

These are rough guides, assuming about 1.3 KB stored per event. To send less: keep
Suricata's protocol logs off when Zeek runs (the default), leave backup and storage traffic
out with a capture filter on the sensor, and keep Network_Traffic for a shorter time on the
[Data retention](retention.md) page.

## Already running Zeek or Suricata

If Zeek, Suricata or both already run on a machine, sending their logs takes a few minutes.
On Signalith, open **Add data** and pick **Network sensor**:

1. Tick the tools that run there: **Zeek**, **Suricata**, or both.
2. If your logs are not in the usual place, change the paths:
    - **Zeek logs in**: the folder with Zeek's current logs. `/opt/zeek/logs/current` for
      Zeek's own packages (the default), `/usr/local/zeek/logs/current` when Zeek was built
      from source, `/nsm/zeek/logs/current` on Security Onion.
    - **Suricata EVE file**: `/var/log/suricata/eve.json` by default. If yours is elsewhere,
      look for `filename` under `eve-log` in `suricata.yaml`.
3. Follow the steps on the page, on the sensor: install Fluent Bit, turn on Zeek's JSON logs,
   save Signalith's CA certificate and the configuration, and restart Fluent Bit.

The page makes a token (purpose `sensor`) when you copy or download the configuration, named
after the **Token for these agents** field. Every copy made under the same name uses the same
token, so before copying, change the name to the sensor's own (such as `nsm-01`): each sensor
then has its own token. To stop a sensor sending, revoke its token on **Settings > Agent
tokens** (see [Agent tokens](agent-tokens.md)).

### Zeek's JSON logs

Zeek writes tab-separated logs unless told otherwise. Signalith needs JSON, one object per
line. Add this line to Zeek's `local.zeek` (`/opt/zeek/share/zeek/site/local.zeek` for Zeek's
packages) and apply it:

```sh
echo '@load policy/tuning/json-logs' | sudo tee -a /opt/zeek/share/zeek/site/local.zeek
sudo /opt/zeek/bin/zeekctl deploy
```

`zeekctl` is in Zeek's own `bin` folder, which is not on the usual search path: use the full
path (`/usr/local/zeek/bin/zeekctl` when Zeek was built from source). Security Onion's Zeek
already writes JSON and has Community ID on, so on Security Onion skip this and the next
section.

Suricata's `eve.json` is always JSON, so it needs nothing.

### Community ID (recommended)

Zeek and Suricata can both tag each event with the **Community ID** of its connection, a
short code that is the same in both tools. With it, a search like
`community_id="1:LQU9qZlK+B5F3KDmev6m5PMibrg="` shows a Suricata alert next to the Zeek
connection, DNS lookup, web request and files of the same flow.

- Zeek: add `@load policy/protocols/conn/community-id-logging` to `local.zeek`, then run
  `sudo /opt/zeek/bin/zeekctl deploy`.
- Suricata: in `suricata.yaml`, under the `eve-log` output, set `community-id: true`, then
  restart Suricata (`sudo systemctl restart suricata`).

### When both tools run

Zeek and Suricata can both log connections, DNS, web requests and TLS. To avoid counting
them twice, when both run the configuration sends everything from Zeek and only Suricata's
alerts, anomalies, files and statistics. Tick **Also Suricata protocol logs** on the Add
data page to send Suricata's flow, DNS, web and TLS events as well.

| Running | Sent from Zeek | Sent from Suricata |
| --- | --- | --- |
| Both | everything | everything except flow, netflow, dns, http and tls (unless you tick the switch) |
| Zeek only | everything | - |
| Suricata only | - | everything |

### What the configuration does

The configuration reads the logs as they are written, starting with new lines (logs written
before you set it up are not sent). It follows Zeek's hourly log rotation, keeps what it has
not sent yet on the sensor's disk while Signalith is busy or down, and sends over HTTPS,
checking Signalith's certificate with the CA you saved. The part that reads the logs looks
like this:

```ini
[INPUT]
    Name                 tail
    Tag                  zeek.*
    Path                 /opt/zeek/logs/current/*.log
    Exclude_Path         *loaded_scripts.log,*packet_filter.log,*stderr.log,*stdout.log,*print.log
    DB                   /var/lib/fluent-bit/signalith-zeek.db
    Skip_Long_Lines      On
    storage.type         filesystem

[INPUT]
    Name                 tail
    Tag                  suricata.eve
    Path                 /var/log/suricata/eve.json
    DB                   /var/lib/fluent-bit/signalith-suricata.db
    Skip_Long_Lines      On
    storage.type         filesystem
```

If Fluent Bit already runs on the sensor for something else, add these inputs and the
generated `[FILTER]` and `[OUTPUT]` sections to your own configuration. Keep the tags
`zeek.*` and `suricata.eve`: they are how Signalith knows what the lines are. (Signalith also
recognises a Zeek or Suricata line by its shape under another tag, but the tag is surer.)

## Suricata on pfSense or OPNsense

pfSense and OPNsense run Suricata on the firewall itself, and can send its EVE log as
syslog. Signalith recognises an EVE JSON object inside a syslog message and maps it exactly
like one sent by Fluent Bit.

1. In Suricata's settings on the firewall, turn on the EVE JSON log and set its output to
   **syslog** (pfSense: the interface's **EVE Output Settings**, output type **SYSLOG**;
   OPNsense: **Services > Intrusion Detection > Administration**, then the option to send
   the EVE log to syslog).
2. Send the firewall's syslog to Signalith: open **Add data**, pick **Syslog** and follow the
   pfSense and OPNsense steps there. Use TLS (port 6514) when the firewall supports it;
   plain UDP syslog is unencrypted and can lose messages.

The event time and the sensor name come from the EVE object (`timestamp`, `host`), else from
the syslog header. Very long EVE events can be cut short by the firewall's syslog; a cut
event is not valid JSON, so it is kept as a plain syslog event. Fluent Bit on a full sensor
does not have this limit.

## Building a new sensor

On Signalith, open **Add data**, pick **Network sensor**, then the **Set up a new sensor**
tab. It shows what a sensor needs and a few options, and makes one line to run on the new
machine:

- **Capture port**: the port plugged into the mirror port or tap, such as `ens192`. Leave it
  empty to choose on the sensor: the script lists the ports with their link and traffic.
- **Your networks**: the address ranges inside your network, separated by commas, so Zeek
  and Suricata know which side of a connection is yours. Empty means the private ranges
  (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fd00::/8`).
- **Zeek**, **Suricata** and **Also Suricata protocol logs**: which programs to install, as
  on the other tab.
- **Install with**: **Packages** (recommended) installs Zeek, Suricata and Fluent Bit from
  their publishers' signed package repositories; **Docker** runs their official images
  instead (see [Docker](#docker)).
- **Token for these agents**: the name of the sensor's agent token.

Press **Copy**: Signalith makes the sensor's token and puts it in the line. The line holds
that token, so anyone with it can send data as this sensor: don't share it. Paste it on the
new machine, as a user who can use `sudo`:

```
 f=$(mktemp) && curl -fsSk --proto '=https' https://siem.example.com:7779/api/sensor/install.sh -o "$f" && echo "<sha-256>  $f" | sha256sum -c --quiet && echo 'sgl_...' | sudo sh "$f" --role sensor --from https://siem.example.com:7779 --ca-sha256 <fingerprint> --version 1.6.0 --token -
```

It downloads the sensor install script from Signalith, checks it against the SHA-256 in the
line, and runs it. The token goes in on the standard input, so it never shows in the list
of running programs.

The line itself holds the token, though, and the shell may keep it in its history
(`~/.bash_history`). Unlike the one-use join token of [Add a server](multi-server.md), a
sensor's token keeps working until you revoke it. The line starts with a space, which keeps
it out of bash's history on Ubuntu and Debian (they set `HISTCONTROL=ignoreboth`); on Rocky,
Alma Linux and other shells, clear the history after running it (`history -c`, or remove the
line from `~/.bash_history`). If someone else may have seen it, revoke the token
(**Settings > Agent tokens**) and make a new line.

The first download skips the certificate check
(the new machine does not trust Signalith's certificate authority yet); the SHA-256 checks
the script, and the script then checks Signalith's certificate authority against
`--ca-sha256` before it trusts it. With a certificate from a public authority there is no
`--ca-sha256`: the machine's own trusted authorities are used.

Signalith must use HTTPS: the tab makes no line while it serves plain HTTP, because a sensor
sends what it sees on your network.

While you install, the tab waits for the sensor and says **nsm-01 is sending** once its
first logs arrive (it stops waiting after 30 minutes).

The line runs on **Ubuntu 22.04 or 24.04, Debian 12 or 13, Rocky Linux 9 or AlmaLinux 9**, on
64-bit x86 or ARM, with systemd. Zeek publishes no packages for Rocky or Alma Linux: there, use
`--no-zeek` (Suricata only) or `--docker`. The checklist says so before anything is installed.

### What the script checks

First it checks the machine and Signalith, and prints a checklist. **✗** stops it, **!** is a
warning (it goes on), **-** is for your information.

| Check | When it is not met |
| --- | --- |
| A supported Linux, 64-bit, with systemd, run with `sudo` | ✗ stops |
| Each program chosen has signed packages for this system, with a signing key the script can check (see [Signing keys](#signing-keys)) | ✗ stops, before anything is installed, and says what works instead (`--docker`, or `--no-zeek`) |
| Signalith answers, its certificate authority matches `--ca-sha256`, and it accepts the token | ✗ stops, before anything is installed |
| 4 or more processor cores, 8 GB or more memory, 50 GB or more free under `/var` and `/opt` | ! Zeek and Suricata may drop packets, or run out of room |
| The capture port has a link, receives packets in 10 seconds, and has no IP address | ! check the cable, the mirror port, and remove the address |
| A second network port, to reach Signalith | ! a sensor needs two |
| The clock is synchronised | ! times of what the sensor sees may be off |
| The disk is encrypted (LUKS) | - the logs hold what people do on your network |

Warnings scroll past while it installs, so it counts them again at the end (**2 warning(s)
above**): read the **Fix** line under each.

Add `--check-only` to the line to only check, or `--dry-run /tmp/sensor` to see every file it
would write (under that folder) and every command it would run, changing nothing.

### Choosing the capture port

With `--interface` the script uses that port. Without it, it picks the one free port: not the
one that holds the default route (the one this machine reaches the network with), and not one
with an IP address or in a bridge or bond, which carries some other network (storage,
backups). When there are several free ports, it lists them with their link and packet counts
and asks; when none is free, it stops and asks you to name the port with `--interface`. It
uses the port that holds the default route only when `--interface` names it, and warns, since
listening there could cut you off.

The script then keeps the capture port up with no address, in promiscuous mode, never
answering (no ARP, no IPv6), and turns off the network card offloads that merge packets and
confuse Zeek and Suricata (GRO, LRO, GSO, TSO): `signalith-sensor-capture.service` does this
at every start. It keeps what the port was like before, and puts it back when it stops (and
so on `--uninstall`). It never changes the machine's network settings files.

### Options

| Option | What it does |
| --- | --- |
| `--role sensor` | What to build. The only role for now. |
| `--from <address>` | Signalith's address on its [agent port](sending-data.md#the-agent-port), which the sensor sends to, such as `https://siem.example.com:7779`. |
| `--ca-sha256 <hex>` | SHA-256 of Signalith's certificate authority; the script refuses any other. |
| `--next-ca-sha256 <hex>` | The new certificate authority, while Signalith switches to it. |
| `--version <v>` | Signalith's version, shown on the Endpoints page. |
| `--token -` | Read the sensor's agent token from the standard input. |
| `--name <name>` | The sensor's name in Signalith (default: the host name). |
| `--interface <port>` | The capture port. |
| `--networks <cidr,...>` | Your own networks (default: the private ranges). |
| `--no-zeek`, `--no-suricata` | Suricata only, or Zeek only. |
| `--suricata-protocols` | Suricata also logs flows, DNS, HTTP and TLS (on when there is no Zeek). |
| `--local-rules <file>` | A file of your own Suricata rules, added to the downloaded ones. |
| `--zeek-workers <n>` | Zeek processes reading the port (default: one Zeek process below 8 cores; from 8 cores, a quarter of them, at most 8). |
| `--suricata-threads <n>` | Suricata capture threads (default: half the cores). |
| `--docker` | Run the three programs in containers. |
| `--check-only` | Check the machine and Signalith, change nothing. |
| `--dry-run <folder>` | Write every file under the folder and print the commands, changing nothing. |
| `--uninstall [--purge]` | Remove what the script added (`--purge`: the logs too). |

### What it installs, and from where

Only from each publisher's own signed package repository. Each repository's signing key is
downloaded from the publisher and used only when its fingerprint is the one pinned in the
script (see [Signing keys](#signing-keys)); the key is trusted for that repository alone
(`signed-by`), not for every package on the machine.

| Program | Ubuntu | Debian 12 | Debian 13 | Rocky, Alma Linux 9 |
| --- | --- | --- | --- | --- |
| Zeek (LTS, package `zeek-8.0`) | openSUSE Build Service `security:zeek`, as Zeek documents | the same | the same | none: use `--no-zeek` or `--docker` |
| Suricata, suricata-update | the OISF PPA `ppa:oisf/suricata-stable` | Debian's `bookworm-backports` | Debian's own `trixie` | OISF's COPR `@oisf/suricata-8.0` |
| Fluent Bit | packages.fluentbit.io | packages.fluentbit.io | packages.fluentbit.io | packages.fluentbit.io |

Signalith does not include or pass on any of them, nor any rules: your machine downloads
them from their publishers.

What it writes:

- `/etc/signalith-sensor/`: `sensor.conf` (the options), `token.env` (the token, root only),
  `ca.pem` (Signalith's certificate authority), `fluent-bit.conf` (the agent's configuration,
  from Signalith), `local.rules` (your own Suricata rules, see
  [Keeping rules up to date](#keeping-rules-up-to-date)), `manifest` (everything the script
  added, for `--uninstall`).
- `/etc/suricata/signalith-sensor.yaml`, which loads the package's `suricata.yaml` and changes
  only what the sensor needs (the capture port, your networks, the EVE log, Community ID), and
  `disable.conf` and `threshold.config` beside it, which the script creates once and never
  overwrites.
- `/var/lib/signalith-sensor/suricata/`: the rules and `suricata-update`'s downloads, which
  only root can change.
- `/usr/lib/signalith-sensor/`: its helpers, and a copy of the script itself, for
  `--uninstall`.
- Zeek's `node.cfg`, `networks.cfg`, `zeekctl.cfg` and a `signalith.zeek` site script (JSON
  logs, Community ID).
- The systemd units `signalith-zeek`, `signalith-suricata`, `signalith-fluent-bit`,
  `signalith-sensor-capture`, and the timers `signalith-suricata-update`,
  `signalith-sensor-status` and `signalith-zeekctl-cron`. The packages' own `suricata` and
  `fluent-bit` services are masked, so only Signalith's run.

### Who runs as whom

- **Zeek** runs as its own `zeek` user, with only the right to capture packets
  (`CAP_NET_RAW`), never as root. It cannot change the machine's network settings.
- **Suricata** starts as root to open the port, then drops to its `suricata` user. Its rules
  are root's and it only reads them.
- **The rules update** runs as root, and works only in folders that only root can change, so
  a Suricata that someone took over through the traffic it reads cannot use it to gain more.
- **Fluent Bit** runs as `signalith-sensor`, with no special rights; it can read Zeek's and
  Suricata's logs (their groups) and nothing else. Only it gets the token, from `token.env`.
- Every unit is locked down with systemd's sandboxing (read-only system, private `/tmp`, no
  new privileges); `systemd-analyze security signalith-zeek` shows the details.
- Zeek and Suricata keep two days of logs on the sensor; Signalith holds the history.

### Rules

The script downloads the **Emerging Threats Open** rules with `suricata-update` and installs
`signalith-suricata-update.timer`, which updates them once a day (at a random time, so
sensors don't all ask at once): `suricata-update` checks that Suricata accepts the new rules
before installing them, then Suricata reloads them without stopping. If the check fails, the
old rules stay and the sensor's status says the update failed. Every 10 minutes
`signalith-sensor-tuning.timer` also fetches the rule tuning set on Signalith. See
[Keeping rules up to date](#keeping-rules-up-to-date) and
[Rule tuning from Signalith](#rule-tuning-from-signalith).

### Status

Every 5 minutes the sensor sends a status line (`sourcetype=sensor:status`): the versions,
whether Zeek and Suricata run, how old the rules are, which rule tuning it runs and how its
last fetch went, the capture port's link, the share of packets dropped, free disk, and what
looks wrong (`sensor_warnings`, such as `capture_link`, `rules_old` or `tuning_failed`).
**Settings > Network sensors** turns it into a checklist (see
[Settings > Network sensors](#settings-network-sensors)); the **Endpoints** page shows it on
the sensor's row and in its details, and the **Health** page counts the sensors that send,
went silent, drop more than 5% of packets or run on rules more than 3 days old.

A sensor the script built is **silent** after 15 minutes without anything from it (three
status lines missed); a sensor you set up yourself, which sends no status line, after an
hour. Both pages count the same way.

### Running it again, and uninstalling

Run the line again to repair, or to upgrade: Zeek (within its long-term support line),
Suricata and Fluent Bit get their publishers' newest packages, and the sensor's own files
those of the Signalith version that made the line. The script changes only what differs,
restarts only what it changed, and says **Nothing to change** when nothing does. A new line
from Add data also gives the sensor a new token. With Docker, the images are the ones the
Signalith version pins: update Signalith, then run its line.

To remove the sensor, run the copy of the script it keeps:

```sh
sudo sh /usr/lib/signalith-sensor/install.sh --uninstall
```

It stops and removes the units, puts the capture port back as it was, removes the files it
wrote (putting back any it replaced), the packages and repositories it added, and the `zeek`,
`suricata` and `signalith-sensor` accounts; packages that were there before stay, and their
own `suricata` or `fluent-bit` service starts again if it ran before. The logs stay unless you
add `--purge`. Then revoke the sensor's token on Signalith: **Settings > Agent tokens**.

### Docker

With **Install with: Docker** (`--docker`), the script runs Zeek, Suricata and Fluent Bit in
containers with Docker Compose, from their publishers' official images, each pinned by
digest (`zeek/zeek`, `jasonish/suricata`, `fluent/fluent-bit`). It needs Docker Engine 24 or
later with Compose v2 on Linux; Docker Desktop cannot capture from a physical port. The
Compose file is `/etc/signalith-sensor/docker/docker-compose.yml`.

- The containers use the host's network, so they see the capture port. Only Zeek and
  Suricata get the rights to capture (Zeek only `NET_RAW`, so it cannot change the network
  settings); every container drops all others, has a read-only file system and cannot gain
  privileges. Fluent Bit reads their logs read-only.
- The token is in `/etc/signalith-sensor/token.env` (root only), which Compose hands to the
  Fluent Bit container as an environment variable: anyone who can run `docker inspect` on the
  sensor can read it, so only administrators should be in the `docker` group.
- Zeek runs as one process in its container, which suits up to a few hundred Mbit/s; for more
  traffic, use the packages.
- The rules update and the status line run from the host's systemd timers, as with packages.

### Signing keys

The script trusts a repository only when its signing key's fingerprint is the one pinned in
the script (`KEY_FPR_*` near the top of `deploy/sensor/install.sh`):

| Repository | Fingerprint | Where the publisher shows it |
| --- | --- | --- |
| Fluent Bit (packages.fluentbit.io) | `C3C0 A285 34B9 293E AF51 FABD 9F9D DC08 3888 C1CD` | Fluent Bit's documentation, Linux downloads |
| Suricata, OISF PPA | `1215 04AD E276 E141 AD70 4A75 AC10 378C F205 C960` | the PPA's page on Launchpad, "Signing key" |
| Zeek, openSUSE Build Service | not pinned yet | the project's `Release.key` on download.opensuse.org |
| Suricata, OISF COPR | not pinned yet | the COPR project's `pubkey.gpg` |

While a fingerprint is not pinned, the script will not add that repository: on Ubuntu and
Debian a sensor with Zeek needs the Zeek one, on Rocky and Alma Linux Suricata needs the COPR
one. Its checklist says so before anything is installed, and so does the Add data page. Use
`--docker` meanwhile, or leave Zeek out with `--no-zeek` on Ubuntu or Debian.

All the fingerprints are in one place near the top of the script. CI's `sensor-script` job
checks every one against what its publisher serves (`.github/scripts/sensor-keys.sh` prints
them), and fails while one is empty (`TestSensorKeyFingerprintsSet` with
`SIGNALITH_SENSOR_KEYS=required`). Before filling one in, check it against the publisher's
own page too.

### By hand

On a system the script does not support, build the sensor by hand, then send its logs with
the **I already run Zeek or Suricata** tab:

1. Leave the capture port up with no IP address (for netplan: `dhcp4: false`, `dhcp6: false`,
   `link-local: []`, `optional: true`).
2. Install Zeek from Zeek's signed packages (<https://docs.zeek.org/en/current/install.html>);
   in `/opt/zeek/etc/node.cfg` set `interface=` to the capture port, list your networks in
   `networks.cfg`, add `@load policy/tuning/json-logs` and
   `@load policy/protocols/conn/community-id-logging` to `site/local.zeek`, and run
   `zeekctl deploy`. Add `*/5 * * * * /opt/zeek/bin/zeekctl cron` to root's crontab.
3. Install Suricata from OISF's packages; in `suricata.yaml` set the `af-packet` interface,
   `community-id: true` under `eve-log`, and `run-as` to the `suricata` user.
4. Run `sudo suricata-update`, restart Suricata, and add a daily
   `suricata-update && suricatasc -c ruleset-reload-nonblocking` to root's crontab.
   With `run-as` set, `suricata-update`'s test of the rules drops to that user and
   fails; give it `--suricata-conf` with a copy of the settings without `run-as`, as the
   script's `signalith-sensor-test.yaml` is.

Done this way, `zeekctl` runs Zeek's workers as root: keep the sensor patched and give it no
other job.

## What you get

### Data models

Zeek and Suricata events are mapped onto data models with the usual field names, so one
search covers both tools (and, for Network_Traffic and Network_Resolution, firewalls and
Sysmon too).

| Zeek log | Suricata event | Data model | Main fields |
| --- | --- | --- | --- |
| `conn` | `flow`, `netflow` | Network_Traffic | `src`, `src_port`, `dest`, `dest_port`, `transport`, `app`, `bytes`, `bytes_in`, `bytes_out`, `packets_in`, `packets_out`, `duration`, `direction`, `conn_state`, `action`, `vlan`, `src_mac`, `dest_mac` |
| `dns` | `dns` | Network_Resolution | `src` (who asked), `dest_ip` (the DNS server), `query`, `query_type`, `answer`, `reply_code`, `reply_code_id`, `ttl` |
| `http` | `http` | Web | `http_method`, `url`, `url_domain`, `uri_path`, `uri_query`, `status`, `http_user_agent`, `http_referrer`, `http_content_type`, `bytes_in`, `bytes_out`, `user` |
| `ssl`, `x509` | `tls` | Certificates | `ssl_server_name`, `ssl_version`, `ssl_cipher`, `ssl_subject`, `ssl_issuer` and their common names, `ssl_serial`, `ssl_hash`, `ssl_start_time`, `ssl_end_time`, `ssl_validation_status`, `ssl_self_signed`, `ja3`, `ja3s`, `ja4`, `ja4s` |
| `files` | `fileinfo` | File_Transfers | `file_name`, `file_size`, `file_hash` (SHA-256), `file_md5`, `file_sha1`, `file_sha256`, `mime_type`, `app`, `src` (sender), `dest` (receiver), `url` |
| `notice` | `alert` | Intrusion_Detection | `signature`, `signature_id`, `category`, `severity`, `severity_id`, `action`, `mitre`, `dest_host`, `url`, `reason`, `local_host` |
| `ssh`, `rdp`, `kerberos`, `ntlm` | | Authentication | `app` (`ssh`, `rdp`, `kerberos`, `ntlm`), `action` (`success`, `failure` or `unknown`), `user`, `user_domain`, `src`, `src_host`, `dest`, `dest_port`, `dest_host`, `authentication_method`, `reason`, `kerberos_service`, `ticket_encryption_type` |
| `smb_files` | | Filesystem | `action` (`read`, `modified`, `opened`, `closed`, `deleted`, `renamed`), `app` (`smb`), `file_path`, `file_name`, `file_size`, `share_name`, `share_target`, `pipe_name`, `src` (client), `dest` (file server) |

Every sensor event also has:

- `host` and `dvc`: the sensor's name.
- `vendor_product`: `Zeek` or `Suricata`; `sourcetype`: `zeek:<log>` or
  `suricata:<event type>`, such as `zeek:conn` or `suricata:alert`.
- `session_id`: Zeek's connection `uid` or Suricata's `flow_id`; `community_id` when it is
  turned on.
- `direction`: `outbound`, `inbound`, `internal` or `external`. Zeek's own view of which
  side is local is used when it logs it (`local_orig`, `local_resp`); otherwise private
  addresses (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7, loopback and link-local)
  count as yours.
- `_raw`: the line as Zeek or Suricata wrote it, without the parts that are never stored
  (see [Security](#security)).

Some details worth knowing:

- **Severity** of Suricata alerts: rule severity 1 is `high`, 2 `medium`, 3 `low`, 4 and
  above `informational`; an Emerging Threats rule whose metadata says
  `signature_severity Critical` is `critical`. Zeek notices are `medium`.
- **Action**: a connection that was answered is `allowed`; one that was refused or got no
  answer (Zeek `S0`, `REJ`, ...; a Suricata TCP flow without packets back) is `failed`. A
  sensor only listens, so it cannot tell a firewall drop from a closed port and never says
  `blocked`. Suricata alerts are `blocked` only when Suricata runs inline and dropped the
  packet.
- **DNS**: on sensor events `src` is the computer that asked. On Sysmon events `dest` is
  the host that looked up, as before, so search `src` for "who looked this up" on network
  data. Suricata logs each lookup twice, the question and the answer; only the answer (which
  holds the question too) is in Network_Resolution, so lookups are not counted twice. The
  question is kept in Other with `signature="DNS request"`.
- **IPv6 addresses** are stored in their short form (`2001:db8::10`), whichever tool saw
  them, so one search finds a host in both.
- **Alerts** also have `local_host`, your network's end of the traffic (see
  [The Network dashboard](#the-network-dashboard)).
- **Web status** is text (`status=404`), as elsewhere in Signalith.
- **Sign-ins** (Authentication): Zeek sees the sign-in on the wire, not on the host, so
  `action` is what it can tell. SSH is `success` or `failure` from Zeek's guess
  (`auth_success`, from the sizes of the encrypted packets), `unknown` when it made none;
  Zeek cannot see the user name. RDP's `user` is the name the client offered before
  signing in (Windows cuts it to 9 characters) and its `src_host` the client's computer
  name. RDP is always `unknown`: the sign-in itself is encrypted (Zeek's result is
  `encrypted` with network level authentication, `authentication_method=HYBRID`), and the
  other results (`reason`, such as `HYBRID_REQUIRED_BY_SERVER`) say only how the connection
  was negotiated. Anyone who reaches the port chooses that name, so it never counts as a
  failed sign-in. Kerberos is `success`, `failure` for an error about the client's
  credentials (`KDC_ERR_PREAUTH_FAILED`, `KDC_ERR_C_PRINCIPAL_UNKNOWN`,
  `KDC_ERR_CLIENT_REVOKED`, `KDC_ERR_KEY_EXPIRED`, `KRB_AP_ERR_BAD_INTEGRITY`), and
  `unknown` for every other error (`reason` is the KDC's error): `KDC_ERR_PREAUTH_REQUIRED`,
  the usual first step of every sign-in, a service without an SPN
  (`KDC_ERR_S_PRINCIPAL_UNKNOWN`), referrals, clock skew, expired tickets. NTLM is
  `success` or `failure`, with the workstation name the client sent as `src_host` (never
  the sensor's name) and the server's name as `dest_host`. Failures count in the brute
  force and password spray detections like any other; a host whose own logs you also
  collect is counted from both, so its thresholds are reached sooner.
- **SMB file activity** (Filesystem): each file used on a share, with the share as
  `share_name` (`\\FILE-01\Finance`) and the path inside it as `share_target`, as on a
  Windows share access (Security 5145). Named pipes opened over `IPC$` (as a pipe, or as a
  file on the `IPC$` share, as Zeek usually logs them) have `pipe_name` instead of `file_path`.
  `smb_mapping` (a share connected to) stays in Other with `share_name`.
- **Inventory**: `known_hosts`, `known_services`, `software` and `dhcp` stay in Other, with
  the host as `dest` (for a DHCP lease, the address the server assigned as `src`, the
  client's MAC as `src_mac` and the name it gave as `src_host`); they fill the asset list (see
  [Hosts in the asset list](#hosts-in-the-asset-list)).
- **Zeek's own field names** stay too, for every log above but conn, dns, http, ssl, x509,
  files and notice: each value is also kept as `zeek_<name>` (`zeek_cipher`,
  `zeek_auth_attempts`), as Sigma's Zeek rules name them.
- **Other Zeek logs** (dce_rpc, weird and the rest) go to Other with
  `sourcetype=zeek:<log>`, `src`, `src_port`, `dest`, `dest_port`, and up to 64 of their
  other values as `zeek_<name>` fields. **Other Suricata events** (anomaly, ssh, smb and
  the rest) go to Other with `sourcetype=suricata:<type>` and their details as text in
  `suricata_detail`.
- **Sensor health**: Zeek's `capture_loss` and `stats` logs and Suricata's `stats` events go
  to Other with `capture_loss_percent`, `packets_received`, `packets_dropped`,
  `drop_percent` and `uptime_seconds`. Suricata's statistics hold hundreds of counters; only
  these are kept, and `_raw` is a one-line summary.
- **Sent twice**: each event's ID comes from its log line, so if Fluent Bit sends a batch
  again (after a network error or a busy server), lines already stored are not stored twice.

### The Network dashboard

**Dashboards > Network** shows, for the last 24 hours by default: IDS alerts and hosts with
high alerts, connections, data sent to the internet, alerts over time by severity, the top
alert signatures, the hosts with the most alerts, the top talkers and destinations on the
internet, the top DNS lookups and the hosts with the most failed lookups, web requests by
status, the top user agents, files by type, servers with self-signed certificates, the
commonest and the rarest TLS client fingerprints, sign-ins seen on the network (by protocol
and outcome), files changed on shares, and the sensor's packet loss. See
[Dashboards](dashboards.md).

The alert panels count `local_host`: your network's end of each alert. Suricata keeps the
direction of the packet that matched, so for most malware and command and control rules your
computer is `src` and the outside server `dest`; `local_host` is `src` for traffic that went
out, `dest` for traffic that came in, and both for traffic that stayed inside. The panels
about connections, DNS, web and files count only Zeek and Suricata events, so Sysmon or
firewall data does not mix in.

### TLS fingerprints (JA3, JA4)

A TLS client says hello the same way wherever it connects, so a fingerprint of its hello
names the program: every browser of one version shares one, and a piece of malware has its
own, whatever address it calls. `ja3` and `ja4` are the client's fingerprints, `ja3s` and
`ja4s` (Zeek's ja4 package) the server's answer. Suricata logs JA3 and JA3S when `ja3-fingerprints` is on in `suricata.yaml`
(and JA4, on versions that have it, with `ja4-fingerprints`); Zeek logs them once its
[ja3](https://github.com/salesforce/ja3) or [ja4](https://github.com/FoxIO-LLC/ja4)
package is installed (`zkg install ja4`, then `zeekctl deploy`), which the install script
does not do for you.

To pivot on one, click it in a search result (they show under each TLS event) and choose:

- **Search every event with this TLS client fingerprint**: every session of that program,
  from every host, over the time range picked;
- **List the clients with this TLS client fingerprint**: the hosts that run it, with how
  many servers each reached (for `ja3s` and `ja4s`, the servers that answered that way).

A connection's `community_id` offers **Show this connection in every log**: what Zeek and
Suricata both logged of it. On the Network dashboard, the fingerprints in the two TLS
fingerprint panels open the same search; the rarest ones, seen on a single host, are the
ones to look at first.

### Threat intel matches

Every address, domain, URL and file hash the sensor sees is checked against your threat
intel feeds by the built-in `threat-activity` detection: `src`, `dest`, `dest_ip`,
`dest_host`, `query`, `url`, `url_domain` and the file hashes. A lookup of a known-bad
domain, a connection to a known command and control address or the download of a known
malware file becomes a finding. See [Threat intel](threat-intel.md).

### Hosts in the asset list

The sensor's Zeek learns which hosts of your network are up, which services they offer and
which software they run (its `known_hosts`, `known_services` and `software` logs, which the
install script turns on), and which names your DHCP server hands out (`dhcp.log`). Every
server reads these from the last 7 days every 10 minutes and adds each address to the asset
list (**Assets & identities**) as a found host, with category `discovered` and
`service:<name>` for each service seen (`service:ssh`, `service:smb`, at most 8), and the
DHCP name the client gave as its host name (for the address the DHCP server assigned it,
never one the client claims). Searches, `enrich` and findings then show those hosts with
asset context.

Only events sent with a token made for a network sensor (**Agents > Network sensor**) are
read: Signalith records each event's token purpose (`signalith_token_purpose`), which no
sender can set, so a Linux or Windows agent's token, an OpenTelemetry sender or syslog
cannot add hosts to the list by sending an event that looks like a Zeek log. A sensor set
up with a shared token from the configuration (no purpose) adds no hosts: give it a sensor
token.

Like the osquery hosts of the [Endpoints page](endpoints.md) and the hosts
[scans](vulnerabilities.md) find, these are never written to your list: they are kept in
memory, go when the sensor has not seen the host for 7 days, and your own rows always win.
A host your list names (by host name or address) is described by your row; one inside a
network (CIDR) row of your list is looked up as that row, and is still listed as found, so
you can see it. The order is your list, the sample data, then the osquery hosts, the scanned
hosts and the hosts the sensor saw; a host name goes to the first of them that has it, so a
device that announces another host's name in its DHCP request does not take that name
over. To describe a discovered host (owner, priority), add a
row for it to your list.

DNS is never added as a service, nor anything named a domain controller: the DNS detections
leave out hosts whose category contains `dns` or `domain controller` (see
[Network detections](#network-detections)), which only you should decide. Service names are
Zeek's analyzer names (letters, digits, `_` and `-`); anything else is left out. Zeek
logs these only for the networks it knows as yours (`Site::local_nets`, from the script's
`--networks`), so internet hosts do not fill the list.

### The ids-alert-high detection

The built-in `ids-alert-high` detection (on by default) turns every high or critical IDS
alert into a finding, every 5 minutes. The same signature between the same two hosts raises
one finding an hour. It adds risk to both hosts.

Rules in the Emerging Threats INFO and POLICY categories are mostly medium or low and do not
raise findings; search `datamodel=Intrusion_Detection` to see them. If one high rule is noisy
on your network, add an exception on its `signature_id` (from one of its findings,
**Don't alert on this again**; see [Exceptions](detections.md#exceptions)), or turn the
rule off on every sensor in **Settings > Network sensors > Rule tuning** (see
[Rule tuning from Signalith](#rule-tuning-from-signalith)).

## Settings > Network sensors

Admins see every sensor on **Settings > Network sensors**: how many there are, how many are
healthy, need attention or are silent, and a card for each sensor, worst first.

- **Healthy**: it sends, and nothing on its checklist needs fixing.
- **Needs attention**: it sends, but something on its checklist failed, such as Suricata
  stopped, the capture port's link down, no packets, old or failed rules, a nearly full disk,
  rule tuning that failed its test, or a revoked token.
- **Silent**: nothing arrived for 15 minutes (an hour for a sensor you set up yourself).

Each card lists the sensor's facts (Zeek and Suricata, the capture port, packets dropped,
free disk, the rules, the rule tuning it runs, how it was installed and its token), then the
checks that failed, each saying in plain words what to do, with the command to run on the
sensor and a copy button. The checks that pass fold into a line such as **11 checks pass**.
A sensor you set up yourself sends no status line, so only whether it sends and its token can
be checked; install it with the line from **Add data > Network sensor** to see the rest.

The page also holds the [rule tuning](#rule-tuning-from-signalith) every sensor fetches, and
the **sensor tokens**: which sensor uses each, when it was last used, and **Revoke**. A token
no sensor has used for 30 days is marked **Not used**: revoke it if the sensor is gone. A
revoked sensor stops sending, and fetching the tuning, within seconds on every server.

The built-in detection `network-sensor-unhealthy` (on by default, medium) raises a finding
when a sensor reports Zeek or Suricata stopped, its capture port down or idle, rules or rule
tuning failing or old, or a full disk, and when it goes silent: one finding per sensor and
problem a day. A search cannot find what did not arrive, so the server that runs the
background jobs writes a `sensor:health` event ("Sensor silent") when a sensor with a status
line stops sending, and again each day it stays silent. It believes only status lines sent
with a network sensor's token and the silent events Signalith writes itself, so another
agent's token cannot raise findings for hosts of its choosing. Packet loss has its own
detection, `network-sensor-packet-loss`.

## Rule tuning from Signalith

Rather than editing files on each sensor, set the rule tuning once on **Settings > Network
sensors > Rule tuning**. Every sensor the script built with Suricata fetches it within 10
minutes (and with its daily rules update), tests it, and only then uses it. Three boxes, each
in the format Suricata already uses:

| Box | File | One per line |
| --- | --- | --- |
| **Rules to turn off** | `disable.conf` | A rule's SID (`2013504`), `gid:sid` (`1:2013504`), `re:` and a pattern matched against the rule (`re:ET POLICY Dropbox`), `group:` and a rules file name (`group:emerging-games.rules`), or `metadata:` with a key and value. A pattern may not repeat a group that itself repeats, such as `(a+)+`, nor refer back to a group (`\1`): `suricata-update` could take hours on it. |
| **Limits and suppressions** | `threshold.config` | `suppress`, `threshold`, `event_filter` or `rate_filter`, such as `suppress gen_id 1, sig_id 2010935, track by_src, ip 10.0.5.20`. |
| **Your own rules** | `local.rules` | One whole Suricata rule, each with a `sid` of its own, best from 1000000 to 1999999 (the range set aside for local rules), such as `alert tls any any -> any any (msg:"Old TLS"; tls.version:1.0; sid:1000001; rev:1;)`. |

Lines starting with `#` are comments. When you save, Signalith checks every line and points
at the first that is wrong (the box, the line and why), so nothing that cannot work reaches
the sensors. It warns, without refusing, when one of your rules has a `sid` outside the local
range, where it may clash with a published rule. If
another admin saved in the meantime, the page says so and keeps your changes, so you can load
theirs and save again.

**How a sensor gets it.** `signalith-sensor-tuning.timer` asks `GET /api/sensor/tuning`
every 10 minutes, over HTTPS, checking Signalith's certificate, with the sensor's own token:
only a sensor token can read it. The answer carries a hash; when nothing changed, Signalith
answers "not modified" and the sensor does nothing. A new tuning is written to
`/var/lib/signalith-sensor/tuning` (which only root writes), and the rules are rebuilt with
it: `suricata-update` has Suricata test them first, from its last download when it has one.
If the test passes, Suricata reloads them without stopping. If it fails, the sensor puts back
the files it had and builds the rules again without the new tuning: when that passes, the
tuning was at fault, the sensor keeps running on the files it had, and its card says **The
rule tuning failed its test**, with Suricata's reason. Fix the line and save: the sensor
tries the new tuning within 10 minutes, and does not try a failed tuning again until it
changes. When the rules fail without the tuning too (say the rules download failed), nothing
is said against the tuning: the sensor tries it again on its next run. A run that takes
longer than 15 minutes is stopped and counts as a failed test. Nothing in the tuning is ever
run as a command: it is only written to these files.

Suricata's test checks the rules to turn off and your own rules. A line of **Limits and
suppressions** that Suricata cannot read is only logged by Suricata, not refused, so for that
box Signalith's own check at save time is what stands between a typo and the sensors: it
accepts only the forms in the table above.

The card shows **Fetching the new rule tuning** for up to 20 minutes after a save, then
**Runs an old rule tuning** if the sensor still has not got it (its last error says why, such
as Signalith being out of reach).

**Your files on the sensor still count.** What you put by hand in `/etc/suricata/disable.conf`
and `threshold.config` (with Docker, `/etc/signalith-sensor/docker/suricata/`) and in
`/etc/signalith-sensor/local.rules` is kept; Signalith's lines are added after yours, in
`/var/lib/signalith-sensor/tuning/disable.conf` and `threshold.config` and in
`server.local.rules`. After a hand edit, run
`sudo systemctl start signalith-suricata-update`.

**Sensors built before rule tuning** don't fetch it: their card says **Can't fetch rule
tuning**. Run the install line again on them (from **Add data > Network sensor**); it keeps
their settings and adds the timer.

**Refused in your own rules**: the keywords `lua`, `luajit`, `luaxform`, `dataset`,
`datarep`, `datajson`, `iprep`, `filemd5`, `filesha1`, `filesha256` and `filestore`, also
in a rule that is commented out (`suricata-update` reads one as a turned-off rule, which an
`enable.conf` on the sensor can turn on). They run scripts or read and write files on the
sensor, which a line typed on Signalith should never be able to do. Load rules that need them
with `--local-rules` on the sensor itself. Signalith checks the tuning again each time a
sensor fetches it, so one written to OpenSearch some other way, without these checks, reaches
no sensor: they keep the tuning they have, and Signalith logs it for the audit trail.

Limits: 256 KB a box and 8 KB a line; at most 5,000 rules to turn off, 2,000 limits and
5,000 rules of your own.

### Network detections

Besides `threat-activity` and `ids-alert-high`, the sensor's data lights up built-in
detections written for it (all on by default except the last):

- **DNS**: DNS tunnelling (many long encoded names from one host) and bursts of lookups
  of names that do not exist (a domain generation algorithm). Your DNS servers are left
  out: give them the asset category `dns-server` (or `domain-controller`) in the
  asset list (**Assets & identities**), since a sensor on the internet link sees them ask upstream
  for every client.
- **Scanning**: an internal host whose connections to many other internal hosts or ports
  fail, and Zeek's own `Scan::*` notices.
- **Downloads and credentials**: a program or script downloaded over plain HTTP, and
  passwords sent in clear text (HTTP basic authentication, FTP, Telnet).
- **Risk only** (they add risk to the host, and raise a risk incident when they add up):
  TLS to a server with a self-signed or expired certificate, more than 1 GB sent to one
  outside address, and connections out to the internet on reverse shell ports.
- **Sensor health**: Zeek missing, or Suricata dropping, more than 5% of the traffic.
- **Off by default**: a host inside answering the internet on a port it had not answered
  on in 30 days, and beaconing to one outside address (turn it on after adding
  exceptions for the services all your hosts talk to).

See [Network detections](detections.md#network-detections) for each one's rule and
threshold. The content packs also have rules for this data, off until you turn them
on: 45 SigmaHQ rules (Zeek SMB, DCE-RPC, Kerberos, RDP and certificate rules, DNS
rules such as mining pools and Cobalt Strike names, and web proxy rules such as
malicious user agents and paste sites) and 9 Splunk network rules (Cisco Smart Install,
the F5 iControl REST exploit, ngrok, protocol on an unusual port, Tor, Kerberos
coercion through DNS, long DNS queries, the 3CX supply chain attack's domains and
remote management tools' user agents). The web rules
of both packs, written for web server logs, also search the sensor's web requests (see
[Network rules](detections.md#network-rules-zeek-dns-proxy-and-firewall) and
[Content packs](detections.md#content-packs)).

The [sample data](sample-data.md) includes a DNS tunnelling story and a clear-text
sign-in story seen only by the sensor, so you can see these fire before your own sensor
is running.

## Keeping rules up to date

Suricata only knows what its rules describe, so they are updated every day. On a sensor the
script built, `signalith-suricata-update.timer` does it; on your own, add the daily
`suricata-update` of [By hand](#by-hand). `suricata-update` checks that Suricata accepts the new
rules before installing them; if they fail the check, the old rules stay. Run an update now
with `sudo systemctl start signalith-suricata-update`.

To turn off a rule on every sensor at once, use
[Rule tuning from Signalith](#rule-tuning-from-signalith). To turn one off on one sensor, put
its SID in `/etc/suricata/disable.conf` (one per line, such as `2014520`; with Docker,
`/etc/signalith-sensor/docker/suricata/disable.conf`) and run the update again.
`threshold.config` beside it limits how often a rule may alert.

Your own rules go in `/etc/signalith-sensor/local.rules`, with packages or Docker (or give a
file with `--local-rules` in the line, which the script copies there). With packages, load
them with `sudo systemctl start signalith-suricata-update`; with Docker, run the line again.
Running the line again with a changed `--local-rules` file loads them straight away. Don't
edit the copy in `/etc/signalith-sensor/docker/suricata/`: the next run replaces it.

Air-gapped networks can load rules from a file: `suricata-update --local /path/to/rules`.

## Security

- **Only outbound HTTPS.** The sensor sends to Signalith over HTTPS and checks Signalith's
  certificate with the CA saved on it (or your own certificate's root), like every agent. It
  opens no ports and needs nothing from Signalith except the address.
- **One token per sensor.** Name the token after the sensor on the Add data page and each
  sensor gets its own (purpose `sensor`), shown once, stored on Signalith only as a hash, and
  revocable on its own. On a sensor the script built it is in
  `/etc/signalith-sensor/token.env`, which only root can read, and only Fluent Bit's service
  gets it; set up by hand, it is in `/etc/fluent-bit/fluent-bit.conf` (mode 600).
- **Rule tuning.** Sensors fetch it with their own token, over HTTPS only; an admin's
  sign-in, another kind of token or no token at all gets nothing. Only admins can read or
  change it on Signalith, and each save is in the audit log, with who saved it and the lines
  added to and removed from each box. Why a sensor refused the tuning (which can quote it)
  shows to admins only, on **Settings > Network sensors**. The sensor
  checks the answer's hash, writes it to files only root can change, and never runs any of
  it; Signalith refuses rule keywords that run scripts or touch files (see
  [Rule tuning from Signalith](#rule-tuning-from-signalith)). It is stored with Signalith's
  other settings in OpenSearch, protected the same way.
- **A sensor is not a server.** It is an agent, not a member of Signalith's servers: it holds
  no OpenSearch password, no CA key and no settings, only its token and the CA certificate,
  which is public.
- **Never stored.** Signalith never stores fields named `password` (Zeek logs HTTP and FTP
  passwords if someone turns that on), the password of an FTP `PASS` command in Suricata's
  ftp events (it becomes `(hidden)`), the challenge and response of a VNC sign-in in its rfb
  events (from which a password can be cracked), nor Suricata's `payload` and `packet`
  (copies of the traffic) or HTTP bodies. Suricata's `payload_printable`, when turned on, is cut to 2 KB.
  They are removed from `_raw` too. Better still, keep them off on the sensor: in
  `suricata.yaml` leave `payload`, `packet` and `http-body` set to `no` (the default).
- **Query strings in web addresses.** The part of a web address after the `?` can carry
  tokens, session IDs and even passwords (`/reset?key=...`). **Settings > General > Query
  strings in web addresses** (`ingest.url_query`) decides what Signalith stores of them as
  events arrive: **Keep them** (the default), **Hide values** (`redact`: the parameter names
  stay, each value becomes `REDACTED`, as in `/login?user=REDACTED&token=REDACTED`) or
  **Remove them** (`drop`: the address stops at the `?`). See
  [Query strings in web addresses](#query-strings-in-web-addresses).
- **The capture port has no IP address.** It only listens. A capture port with an address
  would let traffic on the mirrored network reach the sensor itself.
- **Hostile input.** The traffic a sensor sees can come from attackers, and so can parts of
  its logs. Signalith refuses lines over 1 MB or nested more than 32 levels deep, and every
  parser is fuzz tested. It maps known fields; a Zeek log it has no mapping for keeps at most
  64 `zeek_*` fields per event, within the daily budget of new field names. On the sensor,
  Fluent Bit skips lines over 500 KB, and keeps at most 4 GB waiting on disk while Signalith
  cannot be reached (the oldest is dropped after that).
- **At rest.** On Signalith, sensor events are stored and encrypted like all other events
  (see [Encryption](encryption.md)) and kept as long as the [retention](retention.md)
  settings say. On the sensor, turn on full-disk encryption when you install Linux (in the
  Ubuntu installer: **Encrypt the new Ubuntu installation**), and let Zeek and Suricata keep
  only a few days of logs: Signalith holds the history.
- **The token in the line.** It keeps working until you revoke it. The line starts with a
  space, which keeps it out of bash's history on Ubuntu and Debian; elsewhere, clear the
  history after running it (see [Building a new sensor](#building-a-new-sensor)).
- **Least rights.** With the script, Zeek no longer runs as root: it runs as its own `zeek`
  user with only the rights to capture packets, Suricata drops to its `suricata` user, and
  Fluent Bit runs as `signalith-sensor` with none (see [Who runs as whom](#who-runs-as-whom)).
- **Updates.** Zeek, Suricata and Fluent Bit come only from their signed package
  repositories, each key pinned by fingerprint (see [Signing keys](#signing-keys)). Keep the
  operating system updated (`sudo apt upgrade`, or turn on unattended upgrades, which leave
  the publishers' repositories alone); running the line again upgrades Zeek, Suricata and
  Fluent Bit, and the sensor's own files.

### Query strings in web addresses

With **Hide values** or **Remove them**, Signalith changes every event that holds a web
address before it is stored, whatever sent it: the sensor's web requests (Zeek's `http.log`,
Suricata's `http` events), Suricata alerts and file downloads (with or without a Host
header), web server access logs (Apache, Nginx), proxy logs in CEF over syslog (Zscaler,
Forcepoint, Blue Coat: `request` and `requestContext`) and OpenTelemetry's web attributes.
It changes:

- the fields that hold a web address: `url`, `http_referrer`, `http_redirect` (Suricata's
  Location header, where sign-in redirects carry codes and tokens), OpenTelemetry's
  `url_original`, `http_url` and `http_target`, and a generic JSON record's `uri` and
  `request`: the query is hidden or removed (and `url_length` follows);
- `uri_query` and `url_query`: hidden, or removed;
- `_raw`, Suricata's `payload_printable`, an unmapped Suricata event's details and every
  Zeek `zeek_*` field: each query string a field held is replaced wherever it appears, as it
  is or written as JSON, CEF (`\=`) or Apache (`\"`) text, up to where it ends there (so
  one longer than a field keeps, 4 KB, goes whole). Then every other query string of a web
  address there (a path or address, then `?`) goes too, so one that no field holds, such as
  in a Zeek or Suricata log Signalith has no mapping for, is not kept either.

The raw text of events that hold no web address field and come from neither a network
sensor, a web server nor a CEF or LEEF sender (a Windows event, a script) is left as it was
sent. The [sample data](sample-data.md) follows the setting too.

In `signalith.yaml`:

```yaml
ingest:
  url_query: redact   # keep (the default), redact or drop
```

A change applies at once, on every server, to events that arrive from then on; events
already stored keep what they had (delete them with [retention](retention.md) if they must
go). The trade-off: detections that look at query values, such as the web attack rules of
the content packs (SQL injection, path traversal, web shells called with `?cmd=`), see only
`REDACTED` with **Hide values** (parameter names still match) and nothing with **Remove
them**. A query string written percent-encoded in `_raw` where a field holds it decoded
is still found by the second step, as long as it follows a web address.

## Licences

Signalith only reads what these programs write. They run on the sensor as separate programs;
Signalith does not include, link or ship any of them, and does not copy or pass on any rules.

| Program or content | Licence | How it is used |
| --- | --- | --- |
| Zeek | BSD 3-Clause | Installed on the sensor from Zeek's packages. Signalith reads its JSON logs. |
| Suricata, suricata-update | GPL version 2 | Installed on the sensor from the Open Information Security Foundation's packages. Signalith reads its EVE JSON. |
| Emerging Threats Open rules | Proofpoint's ET Open licence (BSD-style; some older rules GPL version 2); the licence text comes with each download | Downloaded by `suricata-update` on the sensor, straight from Proofpoint. The sample data uses made-up rules with SIDs from 9100000 up, not Emerging Threats text. |
| Fluent Bit | Apache 2.0 | The Signalith agent, as on every other machine. |
| Docker images (`zeek/zeek`, `jasonish/suricata`, `fluent/fluent-bit`) | as the programs above | With `--docker`, pulled by your Docker from their publishers, not rebuilt or passed on by Signalith. |

The sensor install script and its Compose file are Signalith's own; they install or pull
these programs from their publishers and download the rules on the sensor. The Emerging
Threats Open rules' licence text is the `LICENSE` file in each download, in
`/var/lib/signalith-sensor/suricata/update/cache` on the sensor (with Docker, in the
`suricata-rules` volume).

## Troubleshooting

**Nothing arrives.** Open the **Endpoints** page: the sensor should be listed as **Network
sensor**, with when it last sent. If it is not there, check Fluent Bit's log on the sensor:

- on a sensor the script built: `sudo journalctl -u signalith-fluent-bit -n 50`;
- with Docker: `sudo docker compose -f /etc/signalith-sensor/docker/docker-compose.yml logs fluent-bit`;
- on a sensor you set up yourself: `journalctl -u fluent-bit -n 50`.

Common causes are a wrong address under **Agents send to**, a firewall blocking the agent port (7779), a
revoked token, or a wrong log path (Fluent Bit says it found no files). The **Health** page
shows problems with incoming data.

**The script says OISF's Suricata repository could not be read.** On Ubuntu, Suricata
comes from OISF's PPA, because Ubuntu's own older Suricata has no `suricata-update` and so
never loads rules. When the PPA does not answer, the script tries three times and then
stops before installing anything from Ubuntu instead. Run the line again later, or install
with `--docker`. A sensor already running keeps its Suricata.

**Zeek events are in `sourcetype=zeek:unknown`.** Zeek is writing tab-separated logs: turn
on JSON logs (see [Zeek's JSON logs](#zeeks-json-logs)). Lines written before the change stay
as they are.

**Zeek and Suricata both show the same connections.** You ticked **Also Suricata protocol
logs**, or changed the generated filter. Untick it and copy the configuration again, or
search one tool: `vendor_product=Zeek`.

**The packet loss panel shows more than a few percent.** The sensor misses part of the
traffic, so it may miss attacks too. Common causes: a sensor too small for the traffic (see
the sizing table), a busy disk, or network card offloading. Check the mirror port too: a
mirror port slower than the ports it copies drops packets before they reach the sensor.

**The script says "Signalith refused the token".** The token was revoked, or is not a sensor
token, or the line was cut when it was copied. Make a new line on **Add data > Network sensor
> Set up a new sensor** and run it.

**The script says "This Signalith's certificate authority is not the one the line names".**
The machine reached something else at that address (a proxy that inspects HTTPS, or another
server), or Signalith's certificate authority changed since the line was made. Copy the line
again from Add data; if it still fails, check that the address reaches your Signalith.

**The status says no traffic, or the capture link is down.** Check the cable from the
switch's mirror (SPAN) port or tap, and that the switch copies the right ports to it:
`sudo tcpdump -ni ens192 -c 20` on the sensor should print packets.

**The status says the sensor drops packets.** It is too small for the traffic (see the sizing
table), or the disk is busy. Run the line again with more Zeek workers or Suricata threads
(`--zeek-workers`, `--suricata-threads`) if it has cores to spare, or mirror less traffic.
Offloads are turned off by `signalith-sensor-capture.service`; check it ran with
`systemctl status signalith-sensor-capture`.

**A service does not start.** `journalctl -u signalith-zeek -u signalith-suricata -u
signalith-fluent-bit -n 100` says why. Run the line again: it repairs what differs.

**The card says the rule tuning failed its test.** Suricata refused a line Signalith let
through: the card shows its reason, such as an unknown keyword. Fix or remove the line in
**Rule tuning** and save. On the sensor, `sudo journalctl -u signalith-sensor-tuning -n 50`
shows the whole test.

**The card says "Runs an old rule tuning".** The sensor could not fetch it: check that it
reaches Signalith (its events arrive, so the address is right) and see
`sudo journalctl -u signalith-sensor-tuning -n 50`. Start a fetch now with
`sudo systemctl start signalith-sensor-tuning`.

**No alerts at all.** Check that Suricata has rules: the sensor's row on **Endpoints** shows
how many and how old; `sudo systemctl start signalith-suricata-update` updates them now, and
`journalctl -u signalith-suricata-update` says how it went.

To see what arrives:

```
vendor_product IN (Zeek, Suricata) | stats count by sourcetype, datamodel
```
