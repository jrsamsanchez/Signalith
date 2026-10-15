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
- **Linux**: Ubuntu Server 24.04 LTS is the easiest choice; Debian 12 and Rocky, Alma or Red
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
- **Outbound HTTPS** from the sensor to Signalith (port 8080 by default), and to the package
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

A one-line sensor install is coming. Until then, these are the steps on a fresh
**Ubuntu Server 24.04** machine with two network ports. In the commands, `ens192` is the
capture port (the one on the mirror port); use your own port's name (`ip link` lists them).

1. **Leave the capture port without an IP address.** Keep the address on the other port. Tell
   Ubuntu to bring the capture port up at every start with no address, in a new file
   `/etc/netplan/90-capture.yaml`:

    ```yaml
    network:
      version: 2
      ethernets:
        ens192:
          dhcp4: false
          dhcp6: false
          link-local: []
          optional: true
    ```

    Then apply it: `sudo chmod 600 /etc/netplan/90-capture.yaml && sudo netplan apply`. Zeek
    and Suricata switch the port to promiscuous mode themselves, so it hears all the copied
    traffic.

2. **Install Zeek** from Zeek's signed packages (the openSUSE Build Service repository Zeek
   documents at <https://docs.zeek.org/en/current/install.html>):

    ```sh
    sudo install -d -m 755 /etc/apt/keyrings
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key | gpg --dearmor | sudo tee /etc/apt/keyrings/security_zeek.gpg > /dev/null
    echo 'deb [signed-by=/etc/apt/keyrings/security_zeek.gpg] http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
    sudo apt update && sudo apt install zeek
    ```

    The repository is signed, so the plain `http` address is safe: apt checks every package
    against the key. The key is trusted for Zeek's repository only (`signed-by`), not for
    every package on the machine.

3. **Point Zeek at the capture port**: in `/opt/zeek/etc/node.cfg` set `interface=ens192`.
   In `/opt/zeek/etc/networks.cfg` list your own networks (by default the private ranges),
   so Zeek knows which side of a connection is yours. Then turn on JSON logs and Community ID,
   and start Zeek:

    ```sh
    echo '@load policy/tuning/json-logs' | sudo tee -a /opt/zeek/share/zeek/site/local.zeek
    echo '@load policy/protocols/conn/community-id-logging' | sudo tee -a /opt/zeek/share/zeek/site/local.zeek
    sudo /opt/zeek/bin/zeekctl deploy
    ```

    Add `*/5 * * * * /opt/zeek/bin/zeekctl cron` to root's crontab (`sudo crontab -e`) so
    Zeek is restarted if it stops and its old logs are cleaned up.

4. **Install Suricata** from the Open Information Security Foundation's package archive:

    ```sh
    sudo add-apt-repository ppa:oisf/suricata-stable
    sudo apt update && sudo apt install suricata
    ```

    In `/etc/suricata/suricata.yaml`, set the `af-packet` interface to `ens192` and, under
    `eve-log`, `community-id: true`. Suricata reads traffic from attackers, so let it drop
    root once it has opened the port: in the same file set

    ```yaml
    run-as:
      user: suricata
      group: suricata
    ```

    The package creates that user; if `id suricata` says it does not exist, add it with
    `sudo useradd --system --no-create-home --shell /usr/sbin/nologin suricata`, and let it
    write its logs: `sudo chown -R suricata:suricata /var/log/suricata /var/lib/suricata`.

5. **Get the rules and keep them up to date.** `suricata-update` (it comes with Suricata)
   downloads the Emerging Threats Open rules from Proofpoint, checks that Suricata accepts
   them, and only then installs them:

    ```sh
    sudo suricata-update
    sudo systemctl enable suricata && sudo systemctl restart suricata
    ```

    `restart` (not just `enable --now`) makes sure Suricata loads the settings from step 4
    and the new rules, even if the package had already started it.

    Add a daily update to root's crontab, at a minute of your choice:
    `17 3 * * * suricata-update && suricatasc -c ruleset-reload-nonblocking`.

6. **Send the logs**: on Signalith, open **Add data**, pick **Network sensor** and follow the
   steps, as above.

**Zeek runs as root in these steps.** `zeekctl` starts Zeek's workers as root, so a bug in
Zeek's parsing of hostile traffic would run as root on the sensor. The one-line sensor
install will run Zeek as its own `zeek` user with only the rights to capture packets. Until
then, keep the sensor patched (`sudo apt upgrade`), give it no other job, and let only
administrators sign in to it.

When the logs arrive, the **Endpoints** page lists the sensor as **Network sensor**, and the
**Network** dashboard fills in.

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
| `ssl`, `x509` | `tls` | Certificates | `ssl_server_name`, `ssl_version`, `ssl_cipher`, `ssl_subject`, `ssl_issuer` and their common names, `ssl_serial`, `ssl_hash`, `ssl_start_time`, `ssl_end_time`, `ssl_validation_status`, `ssl_self_signed`, `ja3`, `ja3s`, `ja4` |
| `files` | `fileinfo` | File_Transfers | `file_name`, `file_size`, `file_hash` (SHA-256), `file_md5`, `file_sha1`, `file_sha256`, `mime_type`, `app`, `src` (sender), `dest` (receiver), `url` |
| `notice` | `alert` | Intrusion_Detection | `signature`, `signature_id`, `category`, `severity`, `severity_id`, `action`, `mitre`, `dest_host`, `url`, `reason`, `local_host` |

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
- **Other Zeek logs** (ssh, rdp, smb, kerberos, dhcp, weird and the rest) go to Other with
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
status, the top user agents, files by type, servers with self-signed certificates, and the
sensor's packet loss. See [Dashboards](dashboards.md).

The alert panels count `local_host`: your network's end of each alert. Suricata keeps the
direction of the packet that matched, so for most malware and command and control rules your
computer is `src` and the outside server `dest`; `local_host` is `src` for traffic that went
out, `dest` for traffic that came in, and both for traffic that stayed inside. The panels
about connections, DNS, web and files count only Zeek and Suricata events, so Sysmon or
firewall data does not mix in.

### Threat intel matches

Every address, domain, URL and file hash the sensor sees is checked against your threat
intel feeds by the built-in `threat-activity` detection: `src`, `dest`, `dest_ip`,
`dest_host`, `query`, `url`, `url_domain` and the file hashes. A lookup of a known-bad
domain, a connection to a known command and control address or the download of a known
malware file becomes a finding. See [Threat intel](threat-intel.md).

### The ids-alert-high detection

The built-in `ids-alert-high` detection (on by default) turns every high or critical IDS
alert into a finding, every 5 minutes. The same signature between the same two hosts raises
one finding an hour. It adds risk to both hosts.

Rules in the Emerging Threats INFO and POLICY categories are mostly medium or low and do not
raise findings; search `datamodel=Intrusion_Detection` to see them. If one high rule is noisy
on your network, add an exception on its `signature_id` (from one of its findings,
**Don't alert on this again**; see [Exceptions](detections.md#exceptions)), or turn the
rule off on the sensor (see [Keeping rules up to date](#keeping-rules-up-to-date)).

### Network detections

Besides `threat-activity` and `ids-alert-high`, the sensor's data lights up built-in
detections written for it (all on by default except the last):

- **DNS**: DNS tunnelling (many long encoded names from one host) and bursts of lookups
  of names that do not exist (a domain generation algorithm).
- **Scanning**: an internal host whose connections to many other internal hosts or ports
  fail, and Zeek's own `Scan::*` notices.
- **Downloads and credentials**: a program or script downloaded over plain HTTP, and
  passwords sent in clear text (HTTP basic authentication, FTP, Telnet).
- **Risk only** (they add risk to the host, and raise a risk incident when they add up):
  beaconing to one outside address, TLS to a server with a self-signed or expired
  certificate, more than 1 GB sent to one outside address in an hour, and connections on
  reverse shell ports.
- **Sensor health**: Zeek missing, or Suricata dropping, more than 5% of the traffic.
- **Off by default**: a host inside answering the internet on a port it had not answered
  on in 30 days.

See [Network detections](detections.md#network-detections) for each one's rule and
threshold. The SigmaHQ and Splunk content packs also have network rules for this data
(Zeek, DNS, firewall and proxy rules), off until you turn them on; see
[Content packs](detections.md#content-packs).

The [sample data](sample-data.md) includes a DNS tunnelling story and a clear-text
sign-in story seen only by the sensor, so you can see these fire before your own sensor
is running.

## Keeping rules up to date

Suricata only knows what its rules describe, so update them every day (see step 5 of
[Building a new sensor](#building-a-new-sensor)). `suricata-update` checks that Suricata
accepts the new rules before installing them; if they fail the check, the old rules stay.

To turn off a rule that is wrong for your network, put its SID in
`/etc/suricata/disable.conf` (one per line, such as `2014520`) and run `suricata-update`
again. `threshold.config` limits how often a rule may alert. Air-gapped networks can load
rules from a file: `suricata-update --local /path/to/rules`.

## Security

- **Only outbound HTTPS.** The sensor sends to Signalith over HTTPS and checks Signalith's
  certificate with the CA saved on it (or your own certificate's root), like every agent. It
  opens no ports and needs nothing from Signalith except the address.
- **One token per sensor.** Name the token after the sensor on the Add data page and each
  sensor gets its own (purpose `sensor`), shown once, stored on Signalith only as a hash, and
  revocable on its own. On the sensor it
  is in `/etc/fluent-bit/fluent-bit.conf`, which only root can read (the install step sets
  mode 600).
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
- **Updates.** Install Zeek, Suricata and Fluent Bit only from their signed package
  repositories, and keep the operating system updated (`sudo apt upgrade`, or turn on
  unattended upgrades).

## Licences

Signalith only reads what these programs write. They run on the sensor as separate programs;
Signalith does not include, link or ship any of them, and does not copy or pass on any rules.

| Program or content | Licence | How it is used |
| --- | --- | --- |
| Zeek | BSD 3-Clause | Installed on the sensor from Zeek's packages. Signalith reads its JSON logs. |
| Suricata, suricata-update | GPL version 2 | Installed on the sensor from the Open Information Security Foundation's packages. Signalith reads its EVE JSON. |
| Emerging Threats Open rules | Proofpoint's ET Open licence (BSD-style; some older rules GPL version 2); the licence text comes with each download | Downloaded by `suricata-update` on the sensor, straight from Proofpoint. The sample data uses made-up rules with SIDs from 9100000 up, not Emerging Threats text. |
| Fluent Bit | Apache 2.0 | The Signalith agent, as on every other machine. |

## Troubleshooting

**Nothing arrives.** Open the **Endpoints** page: the sensor should be listed as **Network
sensor**, with when it last sent. If it is not there, check Fluent Bit's log on the sensor:
`journalctl -u fluent-bit -n 50`. Common causes are a wrong address under **Agents send to**,
a firewall blocking port 8080, a revoked token, or a wrong log path (Fluent Bit says it found
no files). The **Health** page shows problems with incoming data.

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

**No alerts at all.** Check that Suricata has rules: `sudo suricata-update` prints how many
it installed, and `/var/log/suricata/suricata.log` says how many were loaded.

To see what arrives:

```
vendor_product IN (Zeek, Suricata) | stats count by sourcetype, datamodel
```
