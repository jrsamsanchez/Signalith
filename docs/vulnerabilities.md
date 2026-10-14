# Vulnerability scanning

Signalith scans the networks you list with [Nmap](https://nmap.org), the free and
open-source network scanner, on a schedule or when you click **Scan now**. Each scan
finds the hosts that are up, their open ports and the software that answers on each
port, then matches the software versions to known vulnerabilities (CVEs) from the U.S.
[National Vulnerability Database](https://nvd.nist.gov) (NVD).

Everything is on the **Vulnerabilities** page (under **Monitor**):

- **Hosts**: every host the latest scans found up, worst first. Hosts with a CVE that
  attackers are known to use come first, then by the highest CVSS score. Open a host to
  see its open ports, the software on each, and the CVEs that apply, with a link to each
  CVE in the NVD.
- **Networks**: what is scanned and when, the scan running now and how far it is, and
  **Scan now** and **Stop**.
- **Scans**: the last 200 scans, how long each took, what it found, and why one failed.
- **Scanner setup** (admins): what scanning needs, whether this server has it, why, and
  how to fix anything missing.

Analysts can see the results. Only admins can add networks, start or stop scans, and see
the scanner setup.

## Getting started

1. Open **Vulnerabilities**. The first time, the page checks the server and lists what
   scanning needs, with the reason for each and how to fix anything marked red.
2. Install Nmap if the check says it is missing (see [What scanning needs](#what-scanning-needs)).
   Click **Check again**; no restart is needed.
3. Click **Add a network**. Give it a name, list its addresses, pick the ports and when to
   scan, and confirm that you may scan it.
4. Click **Scan now**, or wait for its schedule. A /24 network with the 1,000 most common
   ports usually takes a few minutes.

Only scan networks you own or have permission to scan. Scanning other people's networks
can be against the law, and the page asks you to confirm before it adds a network.

## What scanning needs

| What | Why | Needed |
| --- | --- | --- |
| Nmap 7.80 or later on the scanning server | Finds hosts, open ports and software versions | Yes |
| Nmap can run a test scan | Makes sure Nmap works under the account Signalith runs as | Yes |
| Outbound HTTPS to `services.nvd.nist.gov` | Looks software versions up in the NVD to name the CVEs | No: without it, scans still list hosts, ports and software |
| An NVD API key | Makes the first lookups about ten times faster | No |

Install Nmap:

- **Docker quick start**: Signalith's container image includes Nmap. Pull the latest
  image (`docker compose -f deploy/docker/docker-compose.yml pull`, then `up -d`).
- **Debian and Ubuntu**: `sudo apt install nmap`. The `.deb` package recommends it, so
  `apt` installs it with Signalith unless recommended packages are turned off.
- **Red Hat, Rocky, Alma and Fedora**: `sudo dnf install nmap`.
- **Windows**: download the latest stable installer (`nmap-…-setup.exe`) from
  <https://nmap.org/download.html#windows>, run it as an administrator and keep the
  default choices, including Npcap.

Signalith looks for Nmap on the `PATH` and where its installers put it
(`C:\Program Files (x86)\Nmap\nmap.exe` on Windows, `/usr/bin/nmap` and
`/usr/local/bin/nmap` on Linux). If it is somewhere else, set `SIGNALITH_NMAP` to its full
path for the Signalith service.

Nmap's licence (the Nmap Public Source License) does not allow Signalith to ship it inside
its own Windows installer or Linux packages, so it is installed on its own. Signalith only
runs it as a separate program.

### CVE lookups and privacy

For each product a scan finds with a version, such as OpenSSH 8.2p1, Signalith asks the
NVD's CVE API for the CVEs of that product (`openbsd openssh`) and compares the version
with each CVE's affected versions itself. Only product names are sent: never addresses,
host names or anything else about your network. Answers are kept in OpenSearch for a day,
so later scans of the same software ask nothing.

Without an API key the NVD allows 5 requests every 30 seconds, so a first scan that finds
a lot of different software takes a few extra minutes. A free key from
<https://nvd.nist.gov/developers/request-an-api-key> makes it about ten times faster: set it
in the `SIGNALITH_NVD_API_KEY` environment variable of the Signalith service (or put it in
a file and set `SIGNALITH_NVD_API_KEY_FILE` to its path), then restart Signalith. If the
server reaches the internet through a proxy, set `HTTPS_PROXY` for the service.

When the NVD cannot be reached, a scan still lists hosts, ports and software, uses CVE
answers kept from the last 30 days, and says on the **Scans** tab that lookups failed.
Turn lookups off altogether in **Scanner setup**.

The NVD also says which CVEs are in CISA's
[Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
catalog. Those are marked **Exploited** on the page, counted on their own, and raise
their own finding: attackers are using them now, so patch them first.

## Networks

| Setting | What it does |
| --- | --- |
| Addresses to scan | One per line: an address (`192.168.1.20`), a network up to a /16 (`192.168.1.0/24`), a range in the last part of an address (`10.0.5.10-50`) or a host name. IPv6 networks can be up to a /112. |
| Addresses to skip | Addresses, networks or names never to scan, such as fragile devices. |
| Ports | The 100 or the 1,000 most common TCP ports (the default), all 65,535, or a list such as `22,80,443,8000-8100`. |
| When | Every day or every week at an hour you pick, or only when you click **Scan now**. Times are in the scanning server's time zone. The default is every day at 01:00. |
| Gentle mode | Scans slowly, one probe at a time and at most 20 packets a second, with only the likeliest version probes. For networks with fragile devices such as old printers or building controllers. It takes several times longer. |
| Scan on schedule | Off pauses the scheduled scans; **Scan now** still works. |

Each scan replaces its network's hosts with what it found: a host that is no longer up
leaves the list (its earlier results stay in Search). A scan stops after 12 hours; split a
network that takes longer, or scan fewer ports.

### How Nmap is run

Scans use TCP connect scans (`nmap -sT --unprivileged -sV --open`), which work the same on
Windows and Linux, under any account, with no packet capture driver, raw sockets or
administrator rights. `-sV` asks each open port which software and version answers. Hosts
count as up when they answer on any of a few common ports (SSH, SMB, RDP, the web ports),
which also finds Windows hosts that do not answer ping. Only TCP is scanned.

The addresses, ports and options come only from the checked settings above: nothing you
type reaches Nmap's command line as an option.

## Results in Search, detections and assets

Each finished scan writes events to the **Vulnerabilities** data model: one per open port
(`category=open_port`) and one per CVE (`category=vulnerability`), with `dest`, `dest_ip`,
`dest_port`, `app`, `product`, `product_version`, `cve`, `cvss`, `severity`,
`known_exploited` and a `url` to the CVE in the NVD. They carry `signalith_intake=scanner`.
For example:

```
datamodel=Vulnerabilities category=vulnerability known_exploited=true | stats dc(cve) as cves by dest | sort -cves
datamodel=Vulnerabilities category=open_port app=rdp | table dest, dest_ip, product_version
```

The Ask box understands questions such as "hosts with known exploited vulnerabilities" or
"top CVEs".

Three built-in detections use them (see [detections.md](detections.md)): a CVE in the Known
Exploited Vulnerabilities catalog (high), a critical CVE (CVSS 9.0 or more, medium), and
Telnet open (low). Each fires once a week at most for the same host and CVE.

Hosts the scans find are added to the asset list as `category=scanned`, so searches and
findings show them with asset context, unless your own list or the
[Endpoints page](endpoints.md) already has them.

## Several servers

When several Signalith servers share one OpenSearch ([servers.md](servers.md)), scans run
on the server that runs the background jobs, and **Scanner setup** shows that server's
own check of itself. Networks, scans and results are kept in OpenSearch
(`<prefix>_vulns`), so every server shows the same ones. A scanner for each network zone
is planned for later.

## Troubleshooting

- **"Nmap was not found"**: install it as above. On Windows, a service only sees a `PATH`
  change after a restart, which is why Signalith also looks in Nmap's install folder.
- **The test scan fails**: run `nmap -sT -p 1 127.0.0.1` as the account Signalith runs as
  to see the whole error. On Windows, reinstall Nmap as an administrator with Npcap.
- **No hosts were up**: check the addresses, and that the scanning server can reach that
  network (a firewall between them, or Docker's network on a Docker install).
- **Software but no CVEs**: either the version has no known CVEs, Nmap could not tell the
  version, or lookups failed (the **Scans** tab says so).
