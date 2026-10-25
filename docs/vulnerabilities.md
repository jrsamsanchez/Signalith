# Vulnerability scanning

Signalith scans the networks you list with [Nmap](https://nmap.org), the free and
open-source network scanner, on a schedule or when you click **Scan now**. Each scan
finds the hosts that are up, their open ports and the software that answers on each
port, then matches the software versions to known vulnerabilities (CVEs) from the U.S.
[National Vulnerability Database](https://nvd.nist.gov) (NVD).

*This product uses the NVD API but is not endorsed or certified by the NVD.*

Everything is on the **Vulnerabilities** page (under **Monitor**):

- **Hosts**: every host the latest scans found up, worst first. Hosts with a CVE that
  attackers are known to use come first, then by the highest CVSS score. Open a host to
  see its open ports, the software on each, and the CVEs that apply, with a link to each
  CVE in the NVD.
- **Networks**: what is scanned and when, the scan running now and how far it is, and
  **Scan now** and **Stop**.
- **Scans**: the last 200 scans, how long each took, what it found, and why one failed.
- **Scanner setup** (admins): what scanning needs, whether this server has it, why, and
  how to fix anything missing. With several servers, **Settings > Scanners** checks each
  of them (see [Scanning each network zone](#scanning-each-network-zone-from-inside-it)).

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
| Outbound HTTPS to `osv-vulnerabilities.storage.googleapis.com` | Checks the packages installed on Linux hosts that run osquery ([below](#installed-packages-on-linux-hosts)) | No |
| OpenVAS on the scanning server | Deeper tests for the networks that turn it on ([below](#deeper-scans-with-openvas-optional)) | No |

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
<https://nvd.nist.gov/developers/request-an-api-key> makes it about ten times faster. Enter
it as **NVD API key** in [Settings](settings.md), on the **Server** tab under **Vulnerability scans**: it
is kept encrypted, never shown again, and used from the next lookup with no restart. It
can also come from the `SIGNALITH_NVD_API_KEY` environment variable of the Signalith
service (or a file named by `SIGNALITH_NVD_API_KEY_FILE`), or from `vulns.nvd_api_key` in
`signalith.yaml` (`signalith secrets set vulns.nvd_api_key` stores it encrypted). If the
server reaches the internet through a proxy, set `HTTPS_PROXY` for the service.

To look CVEs up in a copy of the NVD's CVE API 2.0 on your own network instead, set
**CVE database address** in the same place (or `SIGNALITH_NVD_URL`).

When the NVD cannot be reached, a scan still lists hosts, ports and software, uses CVE
answers kept from the last 30 days, and says on the **Scans** tab that lookups failed.
Turn lookups off altogether in **Scanner setup**.

### Which vulnerabilities to fix first: KEV and EPSS

A scan of a few hundred hosts can find thousands of CVEs, and most will never be used
against anyone. Signalith ranks them with two free public feeds, so the few that matter
come first everywhere: on the host list, inside each host and in Search.

- **Known exploited.** CISA's
  [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  (KEV) catalog lists the CVEs attackers are using now. Signalith marks them **Exploited**,
  adds **Ransomware** when CISA knows of ransomware campaigns using one, and shows the date
  CISA gave US federal agencies to fix it. Patch these first.
- **Likely exploited.** FIRST's
  [Exploit Prediction Scoring System](https://www.first.org/epss/) (EPSS) gives every CVE a
  daily chance, from 0 to 100%, of being exploited in the next 30 days. Most CVEs score well
  under 1%. Each CVE shows its **EPSS** score, and one that is not known exploited but has
  an EPSS of 10% or more is counted as **Likely exploited**: the next to fix.

Hosts and CVEs are sorted known exploited first, then likely exploited, then by CVSS. The
host list has a **Likely exploited** count next to **Known exploited**.

One server downloads both feeds once a day and keeps them in OpenSearch for the others,
and results already found are re-ranked with no new scan. The download asks for the whole
catalog and the whole score list, so nothing about your network is sent. If it fails, it
is tried again every hour, the last good copy stays in use, and **Scanner setup** shows
what went wrong. Signalith also ships with a copy of the KEV catalog, so known exploited
CVEs are marked even on a server that has never reached the internet. EPSS scores have no
built-in copy: they change every day.

On a network with no internet, download
`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` and
`https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` elsewhere every day, copy
them to the server, and enter their full paths as **Known exploited catalog address** and
**EPSS scores address** in [Settings](settings.md), on the **Server** tab under
**Vulnerability scans** (or set `SIGNALITH_KEV_URL` and `SIGNALITH_EPSS_URL`, or
`vulns.kev_url` and `vulns.epss_url` in `signalith.yaml`). A file must end in `.json`,
`.csv` or `.gz`. The same settings take the address of a mirror on your own network.

## Installed packages on Linux hosts

A scan reads a version from what a port answers, such as `OpenSSH 8.9p1 Ubuntu-3ubuntu0.10`.
Linux distributions fix CVEs in their own builds without changing that version, so a scan
cannot tell whether the fix is in. Those CVEs are marked **Version only** (see
[below](#what-a-real-openvas-scan-finds)).

Linux hosts that run osquery from the [Endpoints page](endpoints.md) can settle it. Every
6 hours each one lists its installed deb and rpm packages, with the exact version its
distribution built (such as `1:8.9p1-3ubuntu0.10`), and its release. Signalith matches
each package to its distribution's own advisories and reports a CVE only when the
installed version is older than the version the distribution fixed it in. Versions are
compared the way `dpkg` and `rpm` compare them, epoch and revision included. A CVE the
distribution has not fixed yet is not reported: no update would fix it.

| Release | Advisories |
| --- | --- |
| Debian (each release) | Debian's security tracker (DSA, DLA and CVE records) |
| Ubuntu (each release, LTS or not) | Ubuntu Security Notices |
| Red Hat Enterprise Linux | Red Hat's security data (RHSA) |
| AlmaLinux | AlmaLinux errata (ALSA) |
| Rocky Linux | Rocky Linux errata (RLSA) |

Other systems, such as CentOS Stream, Amazon Linux, SUSE and Alpine, are not checked
yet. Ubuntu Pro (ESM) fixes are not checked either: a host with ESM updates can show a CVE
that its ESM version has fixed.

The advisories come from [OSV.dev](https://osv.dev), which publishes all of them in one
format. The server that runs the background jobs downloads only the releases your hosts
run (for example `Debian:12/all.zip` or `Ubuntu:22.04:LTS/all.zip` from
`osv-vulnerabilities.storage.googleapis.com`), once a day, and tries again an hour after a
failed download. Nothing about your hosts is sent. A download can be large (about 150 MB
for one Ubuntu release, 45 MB for Debian, at most 512 MB), so the server reads it from a
temporary file. If a download fails, the last results stay. Each data source has its own
license: Ubuntu's notices are CC BY-SA 4.0, Red Hat's data CC BY 4.0, AlmaLinux's MIT and
Rocky Linux's BSD.

The results show on the **Hosts** tab under the network **Installed packages**, one row per
host, with one entry per source package (such as `openssh`) and the version that fixes each
CVE. Each CVE is marked **Package**. They are written as events like a scan's, with
`vuln_confidence=package`, `vuln_source=package`, `vuln_distro` (such as `Ubuntu 22.04`),
`product` and `product_version` (the source package and the installed version),
`endpoint_id`, and `solution` (the version to upgrade to). They have no `dest_port`. A
host's CVEs are written when they change, and once a day while they stay. Package matches
raise the same detections as a scan's CVEs: known exploited, critical (CVSS 9 or more) and
likely exploited. Red Hat, AlmaLinux and Rocky Linux rate their advisories as
Critical, Important, Moderate or Low; when an advisory has no CVSS score, that rating sets
the severity, and the critical detection, which needs a CVSS score, does not fire.

```
datamodel=Vulnerabilities vuln_confidence=package | stats dc(cve) as cves by dest, product | sort -cves
datamodel=Vulnerabilities vuln_confidence=package known_exploited=true | table dest, product, product_version, cve, solution
```

It runs while **Look up CVEs in the National Vulnerability Database** is on in **Scanner
setup**, and needs no scan network. **Scanner setup** shows how it stands. To stop it, set
**Distribution advisories address** in [Settings](settings.md), on the **Server** tab under
**Vulnerability scans**, to `off` (or `SIGNALITH_OSV_URL=off`, or `vulns.osv_url: off` in
`signalith.yaml`). The same setting takes a mirror's address, or, on a network with no
internet, the full path of a folder on the server that runs the background jobs that holds
each release's file, as `Debian:12/all.zip`.

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

## Deeper scans with OpenVAS (optional)

Nmap reads the software versions on open ports, and Signalith matches them to CVEs.
[OpenVAS](https://www.openvas.org) (Greenbone Community Edition, open source) goes
further: it tests each host for thousands of known weaknesses by probing them, such as
missing patches, default passwords, anonymous FTP and weak TLS settings. It is much
slower and sends far more traffic, so a network uses it only when you turn on **Also scan
with OpenVAS** for it.

A network with OpenVAS on is scanned with Nmap first, then with OpenVAS's *Full and fast*
configuration, on the server that scans the network. Its findings join Nmap's: on the open
port they concern, or on the host itself. A CVE both found is listed once. Results OpenVAS
is unsure of (quality of detection under 70%) and plain information are left out. If
OpenVAS is not set up on that server, or fails, the scan keeps Nmap's results and says why.

To set it up on a scanning server:

1. Install Greenbone Community Edition where that server can reach it
   (<https://greenbone.github.io/docs/latest/>; the Docker containers are the quickest).
   Let it finish loading its feed before the first scan: on a new install that takes
   about 40 minutes after the containers start, and **Settings > Scanners** says
   "still loading its feed" until then.
2. Make a gvmd user for Signalith: `gvmd --create-user=signalith --password='a long password'`.
   With the Greenbone containers, run it inside the gvmd one:
   `docker compose exec -u gvmd gvmd gvmd --create-user=signalith --password='a long password'`.
3. Give Signalith gvmd's address and that user, on that server only:

    | Setting in `signalith.yaml` (under `vulns:`) | Environment variable | What |
    | --- | --- | --- |
    | `openvas_address` | `SIGNALITH_OPENVAS_ADDRESS` | gvmd's Unix socket, such as `/run/gvmd/gvmd.sock`, or `host:9390` for its TLS port |
    | `openvas_username` | `SIGNALITH_OPENVAS_USERNAME` | The gvmd user |
    | `openvas_password` | `SIGNALITH_OPENVAS_PASSWORD` (or `_FILE`) | Its password; `signalith secrets set vulns.openvas_password` keeps it encrypted |
    | `openvas_ca_file` | `SIGNALITH_OPENVAS_CA_FILE` | For a TLS port, the certificate authority of gvmd's certificate; empty uses the system's |

    In Docker, also mount the volume that holds gvmd's socket into the Signalith container.

4. Restart Signalith. **Settings > Scanners** shows whether OpenVAS answered.
5. Edit a network on the Vulnerabilities page and turn on **Also scan with OpenVAS**.
6. Optional but worth it: give OpenVAS logins to sign in to the hosts with
   ([Credentialed OpenVAS scans](#credentialed-openvas-scans)).

Signalith makes a target and a task in OpenVAS for each scan and removes both when the
scan ends; stopping the scan in Signalith stops it in OpenVAS too. OpenVAS findings are
written as events like the others, with `vuln_source=openvas`, `openvas_oid`, `solution`
and, when the test names one, `cve`.

### What a real OpenVAS scan finds

A weekly CI job ([greenbone.yml](https://github.com/jrsamsanchez/Signalith/blob/main/.github/workflows/greenbone.yml))
runs Greenbone Community Edition (GMP 22.7, about 190,000 tests) and scans two deliberately
weak containers through Signalith: Apache 2.4.49 and Redis with no password, ports 80 and
6379. The scan takes about 6 minutes once the feed has loaded. On 2026-10-15 it found:

| Host | Port | Severity | Finding |
| --- | --- | --- | --- |
| Redis | 6379/tcp | high (7.5) | Redis Server No Password |
| Apache | 80/tcp | medium (5.8) | HTTP Debugging Methods (TRACE/TRACK) Enabled |
| Both | host | low (2.6) | TCP Timestamps Information Disclosure |
| Both | host | low (2.1) | ICMP Timestamp Reply Information Disclosure |

OpenVAS did not list Apache 2.4.49's path traversal (CVE-2021-41773): the stock image does
not expose it, and OpenVAS rates version-only Apache checks as unsure (Linux distributions
patch without changing the version), so they fall under the 70% cut. Signalith's Nmap
scan reads the version and matches it to the NVD's CVEs, which list CVE-2021-41773 for
Apache 2.4.49, so it flags that upstream build. It has the same limit as OpenVAS on a
distribution's build, though: when the banner names one (`OpenSSH 8.9p1 Ubuntu-3ubuntu0.10`,
`Apache httpd 2.4.52 (Ubuntu)`), Signalith marks its CVEs **Version only** on the
Vulnerabilities page and `vuln_confidence=version_only` in their events, since the
distribution may have fixed them without changing the version, and the detections for
critical and likely exploited vulnerabilities leave them out (known exploited ones still
raise a finding). A signed-in OpenVAS scan reads the installed packages and settles it,
and so does osquery's list of [installed packages](#installed-packages-on-linux-hosts).
The two find different things, which is why a network can use both.

### Credentialed OpenVAS scans

From outside, OpenVAS sees only what a host's open ports show. Signed in, it reads the
installed packages, patches and settings, and finds far more: missing security updates,
old kernels, weak configuration. Give it a login for each kind of host on a network: Linux
and Unix (SSH), Windows (SMB), VMware ESXi, and network devices such as switches, routers,
firewalls and industrial gateways (SNMP):

1. Make a scan account on the hosts, with the least access it needs (below).
2. Open **Settings > Scanners**, find **Scan logins for OpenVAS** and click **Add a login**.
   Pick the kind, enter a name, the user name and the key or passwords, and save.
3. On **Vulnerabilities > Networks**, edit the network, keep **Also scan with OpenVAS** on,
   and pick the logins under **Sign in to Linux hosts with**, **Sign in to Windows hosts
   with**, **Sign in to VMware ESXi hosts with** and **Sign in to network devices (SNMP)
   with**. Leave any you don't need at None.
4. Click **Scan now**. In the results, OpenVAS findings from the signed-in checks are named
   for the package or patch, such as "Ubuntu: Security Advisory (USN-…)".

#### A Linux scan account (SSH key)

A plain user is enough: the package checks read `dpkg`, `rpm` and `uname` output, which
any user can. Do not add it to `wheel`, `sudo` or `adm`. If a check you need does want
more, allow only those exact read-only commands in a `sudoers` file, never `ALL`.

```sh
# On the scanning server, make a key pair just for scanning.
ssh-keygen -t ed25519 -f signalith-scan -C signalith-scan -N ''

# On each Linux host (or with your configuration tool):
sudo useradd --create-home --shell /bin/sh signalith-scan
sudo install -d -m 700 -o signalith-scan -g signalith-scan ~signalith-scan/.ssh
echo 'from="10.0.5.20",no-port-forwarding,no-agent-forwarding,no-X11-forwarding '"$(cat signalith-scan.pub)" |
  sudo tee ~signalith-scan/.ssh/authorized_keys
sudo chown signalith-scan: ~signalith-scan/.ssh/authorized_keys
sudo chmod 600 ~signalith-scan/.ssh/authorized_keys
```

`useradd` gives the account no password, so it cannot sign in with one. Put the scanning
server's address in `from=`, so the key works from there only. Paste the
private key file, `signalith-scan`, into the login and then delete that file: Signalith
keeps it encrypted. An `ed25519` key is best; RSA keys of 3072 bits or more work too. A key
with a passphrase works; enter the passphrase with it. An SSH password works where keys
cannot be used, but avoid it: OpenVAS sends the login to every host it scans, so a host
in the range that is not what it seems (a compromised one, or one an attacker put there)
can keep a password and use it on the others. It only ever sees a key's signature.

#### A Windows scan account (SMB)

Windows keeps the patch and software lists that OpenVAS checks in the registry and WMI,
which only members of the local Administrators group can read remotely. So the account must
be a local administrator on the hosts it scans, and nothing more:

1. In Active Directory, make a user such as `svc-signalith-scan` with a long random
   password, and a group such as `Signalith scanners` with only that user in it. Do not add
   it to Domain Admins or any other admin group. On the account, tick **Account is
   sensitive and cannot be delegated**. Do not put it in **Protected Users**: that turns
   off NTLM, which the scan signs in with.
2. With a Group Policy Object linked to the computers to scan (not to the domain
   controllers), add `Signalith scanners` to the local Administrators group
   (**Computer Configuration > Preferences > Control Panel Settings > Local Users and Groups**).
3. In the same GPO, under **User Rights Assignment**, add the group to **Deny log on
   locally**, **Deny log on through Remote Desktop Services**, **Deny log on as a batch
   job** and **Deny log on as a service**: it signs in over the network only.
4. Under **Security Options**, set **Microsoft network server: Digitally sign
   communications (always)** to Enabled, and **Network security: LAN Manager
   authentication level** to **Send NTLMv2 response only. Refuse LM & NTLM**.
5. Allow **File and Printer Sharing (SMB-In)** (TCP 445) in Windows Defender Firewall
   from the scanning server's address only, and set the **Remote Registry** service to
   Manual so it can start when asked.

Every Windows host the scan reaches receives this account's sign-in, so a host that is
not what it seems can try to relay it to another host or crack it offline. The settings
above make both much harder; also make one account per network zone, each an
administrator only on that zone's computers, rather than one for the whole domain, so a
captured sign-in reaches no further. Change its password after any sign that one of the
hosts was compromised.

Enter the user name as `CORP\svc-signalith-scan`. For a computer outside a domain, a
local account works too (its name alone), but Windows then also needs
`LocalAccountTokenFilterPolicy` set to 1 for remote admin access, which weakens that
computer's defenses; prefer a domain account. Change the password every few months: edit
the login and enter the new one.

#### A VMware ESXi scan account

OpenVAS reads the ESXi version and build over the vSphere API (HTTPS, TCP 443) and matches
them to VMware's advisories. A read-only account is enough; never use `root`:

1. In the ESXi Host Client, open **Host > Manage > Security & users > Users** and add a
   user such as `signalith-scan` with a long random password.
2. Right-click **Host**, choose **Permissions**, and add the user with the **Read-only**
   role.
3. If the host is in lockdown mode, add the user to its **Exception Users** list.
4. Allow TCP 443 to the host from the scanning server.

Every ESXi host the scan reaches receives this password, so use one account per network
zone, and change its password after any sign that a host was compromised.

#### An SNMP scan account (network devices)

OpenVAS reads a device's model, firmware version and settings over SNMP (UDP 161). A network
with an SNMP login is scanned on all TCP ports and Nmap's top 100 UDP ports (161 among
them) instead of the usual TCP list, or on your own ports plus UDP 161, so its scans take
longer.

Use **SNMPv3** wherever the device supports it. Signalith signs in with SHA authentication
and AES privacy (encryption), so neither the password nor what the device sends can be
read on the way. On the device, make a v3 user that can only read, at the `authPriv`
security level, and allow it from the scanning server's address only. On Cisco IOS, for
example (put your own passwords in place of the two values; the scanning server here is
10.0.5.20):

```text
access-list 10 permit 10.0.5.20
snmp-server view SIGNALITH-RO iso included
snmp-server group SIGNALITH v3 priv read SIGNALITH-RO access 10
snmp-server user signalith-scan SIGNALITH v3 auth sha AUTH-PASSWORD priv aes 128 PRIVACY-PASSWORD
```

Both passwords must be at least 8 characters and different from each other; use long
random ones.

**SNMPv1/v2c communities** are for older devices that have nothing better. A community
crosses the network unencrypted to every device scanned, so anyone on the path can read it,
and on many devices a community can also change settings. If you must use one: make a
read-only community just for scanning (long and random: Signalith refuses `public`,
`private` and other well-known defaults), allow it from the scanning server's address only,
and put the devices that need it on a network of their own in Signalith, so the community
is sent to them alone.

#### How Signalith keeps the logins

- Keys, passphrases, passwords and SNMP communities are encrypted (AES-256-GCM) before they are stored, each
  bound to its login, and never sent back to the browser, written to a log or put in an
  event. Editing a login keeps the saved key or password unless you enter a new one.
- Only admins can see the list of logins, add, change or remove them, or pick them for a
  network. Each change is in the audit log (`vulnerability scan login saved` or
  `removed`), with the login's name, user name and whether its key or passwords changed.
- A login is decrypted only on the server that scans the network, when a scan starts. It is
  handed to OpenVAS for that scan alone and removed from OpenVAS when the scan ends, on a
  connection of its own. If that fails (OpenVAS restarted, or the server stopped
  mid-scan), the next scan removes what was left, and the server log says so.
- Saving or changing a login, and saving the networks to scan, asks for your password
  again (see [Confirming it's you](users.md#confirming-its-you)). The audit log records
  each network's addresses, scanner and logins as they change.
- Servers that share their settings encrypt the logins with the cluster key, so every
  scanner can use them; every server of the cluster can therefore decrypt every login.
  Rotating the cluster key, or removing a server, encrypts them again with the new key. A login saved on a single server, before it joined a cluster, is
  encrypted with that server's own key: the list then marks it **Enter again**, and scans
  run without OpenVAS until you edit it and enter its key or password again.
- A login in use by a network cannot be removed: pick another one, or None, for the network
  first. Remove the account from your hosts as well when you no longer need it.

## Results in Search, detections and assets

Each finished scan writes events to the **Vulnerabilities** data model: one per open port
(`category=open_port`) and one per CVE (`category=vulnerability`), with `dest`, `dest_ip`,
`dest_port`, `app`, `product`, `product_version`, `cve`, `cvss`, `severity`,
`known_exploited` and a `url` to the CVE in the NVD. They carry `signalith_intake=scanner`.
Known exploited CVEs add `known_ransomware` (`true` or `false`) and `kev_due` (CISA's
fix-by date), and CVEs with an EPSS score add `epss` (0 to 1) and `epss_percentile`.
For example:

```
datamodel=Vulnerabilities category=vulnerability known_exploited=true | stats dc(cve) as cves by dest | sort -cves
datamodel=Vulnerabilities category=vulnerability epss>=0.5 | table dest, cve, epss, cvss
datamodel=Vulnerabilities category=open_port app=rdp | table dest, dest_ip, product_version
```

The built-in **Vulnerabilities** dashboard ([dashboards.md](dashboards.md#vulnerabilities))
sums them up over the last 7 days.

The Ask box understands questions such as "hosts with known exploited vulnerabilities",
"likely exploited vulnerabilities" or "top CVEs".

Five built-in detections use them (see [detections.md](detections.md)): a known exploited
CVE (high), a known exploited CVE on a critical or high priority asset (critical), a likely
exploited CVE (medium), a critical CVE (CVSS 9.0 or more, medium), and Telnet open (low).
Each fires once a week at most for the same host and CVE, and each adds risk to the host,
so a host with exploitable vulnerabilities climbs the risk list. Risk on an asset you
marked critical or high priority in the asset list ([detections.md](detections.md#risk)) counts double or one and
a half times.

Hosts the scans find are added to the asset list as `category=scanned`, so searches and
findings show them with asset context, unless your own list or the
[Endpoints page](endpoints.md) already has them. A [network sensor](network-sensor.md#hosts-in-the-asset-list)
adds the hosts it sees the same way, as `category=discovered`.

## Scanning each network zone from inside it

A scan only sees the hosts and ports its server can reach. For a network behind a
firewall, such as a plant floor, a lab or a guest network, run a Signalith server inside
it and let that server scan it:

1. Add a scanner inside the zone: **Settings > Servers > Add a server**, and pick
   **Vulnerability scanner** (see [Adding servers](multi-server.md#cluster-servers-and-scanners)).
   It only needs to reach OpenSearch and the network it scans. A scanner never runs the
   background jobs, and the Servers page and Settings > Scanners show it with a **Scanner**
   badge.
2. Install Nmap on it, as above.
3. On **Vulnerabilities > Networks**, edit the network and pick that server under
   **Scanned by**. The list shows each server's state: ready, needs setup, or offline.
   Once a scanner exists, a new network is scanned by it unless you pick another.

With more than one server, **Vulnerabilities > Networks** starts with a **Scanners** list:
each server, whether it is ready, the networks it scans, and **Scan now** to scan them all,
or **Add a network** for a scanner with none yet. A server that no network uses shows
**Not needed**: it does not need Nmap until you pick it to scan something.

Networks that name no scanner are scanned by the server that runs the background jobs.
Every server runs the scans of its own networks and writes the results to the shared
OpenSearch, so the **Vulnerabilities** page, the dashboard, detections, findings and the
asset list show the hosts every scanner found, whichever server you open.

**Settings > Scanners** (admins) lists every server as a scanner: the networks it scans,
whether it has what scanning needs, and how it reaches each of its networks:

- **On this server's own network**: the server has an address on that network.
- **Through a router**: the scan leaves from the address shown and crosses routers and
  firewalls, which decide which hosts and ports it sees. Allow that address through, or
  pick a server inside the zone.
- **Not reached**: the server has no route to it, or a host name was not found.

The reach check reads the server's own interfaces and routing table; it sends nothing to
the network. Each server checks itself every two minutes, every 30 seconds while something
is missing, and at once when it is given a network or one is taken away. **Check again**
checks the server you are signed in to right away.

A scheduled scan runs in the time zone of the server that scans it. **Scan now** refuses a
network whose scanner is stopped or removed. A queued scan that its scanner has not
started after 10 minutes, while that server has not checked in, fails with a message that
names the server. Moving a network to another scanner takes effect from its next scan.

The Docker quick start's container reaches other networks through the host, so scans leave
from the host's address.

## Troubleshooting

- **"Nmap was not found"**: install it as above. On Windows, a service only sees a `PATH`
  change after a restart, which is why Signalith also looks in Nmap's install folder.
- **The test scan fails**: run `nmap -sT -p 1 127.0.0.1` as the account Signalith runs as
  to see the whole error. On Windows, reinstall Nmap as an administrator with Npcap.
- **No hosts were up**: check the addresses, and that the scanning server can reach that
  network (a firewall between them, or Docker's network on a Docker install). **Settings >
  Scanners** shows how each server reaches its networks; pick a server inside the zone if
  needed.
- **Software but no CVEs**: either the version has no known CVEs, Nmap could not tell the
  version, or lookups failed (the **Scans** tab says so).
