# Security checks

The **Security** page (**Configure > Security**) and the `signalith security` command
check how this server is set up: what is encrypted on the network and on disk, who can
sign in, how passwords and keys are kept, and how Signalith runs on this computer. They
say what to fix first and how, and they are honest about what Signalith can't see.

- [How the checks run](#how-the-checks-run)
- [What the states mean](#what-the-states-mean)
- [In transit](#in-transit)
- [At rest](#at-rest)
- [In use](#in-use)
- [Accounts and sign-in](#accounts-and-sign-in)
- [This server](#this-server)
- [Standard or strict certificate authority](#standard-or-strict-certificate-authority)
- [Always on](#always-on)
- [Not checked here](#not-checked-here)
- [The signalith security command](#the-signalith-security-command)
- [API](#api)

## How the checks run

- The server checks itself 30 seconds after it starts, then every hour, and after each
  step of a [change of certificate authority](https.md#switching-to-a-new-certificate-authority).
  **Re-check** on the page runs the checks again, at most once every 10 seconds.
- A whole run takes 15 seconds at most. Each part has its own time limit, so a slow disk
  or a slow OpenSearch never holds up the server or a page. A part that runs out of time
  shows **Can't tell** with "Signalith couldn't finish this check in time."
- The server logs a line when what is at risk changes: `security check: at risk` (a
  warning, with the ids of the checks) or `security check: nothing at risk`.
- Only admins can see the page and the report. It names files, folders and this
  server's addresses, but never shows a password, token or key.
- Every server that shares the same OpenSearch checks itself, whether or not it runs the
  jobs (see [docs/servers.md](servers.md)). The page shows the counts of the others
  too, with a link to each one's own page.
- Many checks look at the computer itself: its disks, its files and the process.
  `signalith security` run on the server as root or Administrator can see more than the
  service can; see [The signalith security command](#the-signalith-security-command).

## What the states mean

| State | Meaning |
| --- | --- |
| **At risk** | Right now, someone on the network or another account on this computer could read or change Signalith's data, or sign in, without anything special. |
| **Needs attention** | Weaker than it should be, or a step was left half-done. Nobody gets in because of it today. |
| **Can't tell** | Signalith can't see this from where it runs. This is never counted as a problem. The check says how to look by hand. |
| **Good** | Set up safely. Some good checks have a **Make it stronger** tip. |

A check that doesn't apply is left out, rather than shown as "not applicable". For
example, **Directory sign-in** appears only while directory sign-in is on.

A check with several problems shows the worst one, and lists the others under it.

**Fix first** lists everything at risk, then everything that needs attention, in the
order that matters most: OpenSearch open to the network and HTTPS first, then
passwords and tokens anyone can look up, then how keys are kept, then the rest. The page
shows the top three; `signalith security` lists them all.

## In transit

Whether data is encrypted as it crosses the network.

### HTTPS

**Looks at:** the **HTTPS** setting (`server.tls.mode`), the listen address
(`server.listen`) and **Trusted reverse proxies** (`server.trusted_proxies`). While HTTPS
is off behind a proxy, the server also notes computers that signed in, and agents that
sent events, directly over plain HTTP in the last day, not through the proxy. It keeps
up to 50 addresses of each, in memory only. Computers and agents on the server itself
aren't counted: what they send doesn't cross the network.

- Good: HTTPS is on; or HTTPS is off but Signalith answers only on this computer
  (such as `127.0.0.1:8080`); or a trusted reverse proxy serves HTTPS.
- Needs attention: a proxy serves HTTPS, but people signed in, or agents sent events,
  to Signalith directly over plain HTTP; or HTTPS is left to a reverse proxy that
  Signalith believes only because `signalith.yaml` was written before HTTPS was the
  default (an `https://` public address and no `server.tls` section). List that proxy
  under **Trusted reverse proxies**.
- At risk: HTTPS is off, and Signalith answers other computers directly.

**To fix:** turn on HTTPS, as in
[Upgrading from plain HTTP](https.md#upgrading-from-plain-http). Behind a proxy, set
the listen address so only the proxy reaches Signalith
([Behind a reverse proxy](https.md#behind-a-reverse-proxy)).

**How to check by hand:** from another computer,
`curl -sI http://siem.example.com:8080/` prints `Location: https://...` when Signalith
serves HTTPS itself.

### HTTPS certificate

**Looks at:** the certificate Signalith serves, for HTTPS or syslog over TLS: when it
expires, its key and signature, and the names it covers. With your own files, it also
looks at whether they cover the host in `server.public_url` and include the
certificate of the authority that issued them. With Signalith's own certificate, it
looks at when the certificate authority expires.

- At risk: the certificate has expired.
- Needs attention: it expires soon (30 days for your own files; 21 days for Signalith's
  own, which means renewal failed), it leaves out names people or agents use, it uses a
  key or signature that is too weak (RSA under 2048 bits, or SHA-1), your own
  certificate covers only IP addresses (so agents have no host name to check it
  against, see [Agents and syslog](https.md#agents-and-syslog)), or Signalith's
  certificate authority expires within 180 days.

**To fix:** see [Use your own certificate](https.md#use-your-own-certificate), or
[Names the certificate can cover](https.md#names-the-certificate-can-cover). Signalith
renews its own certificate by itself 30 days before it expires; if it can't, it says why
in its log when it starts.

**How to check by hand:**

```sh
openssl s_client -connect siem.example.com:8080 -servername siem.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -enddate -ext subjectAltName
```

### Certificate authority

Shown with Signalith's own certificate (**HTTPS** set to Automatic).

**Looks at:** how far the certificate authority in use may vouch, what
**Certificate authority reaches** (`server.tls.ca_scope`) is set to, and whether a
change of certificate authority is in progress. After a switch, it counts the computers
that refused the new certificate (from failed TLS handshakes, over HTTPS and syslog).

- Good: a standard or a strict certificate authority, whichever you chose. Neither is
  better for everyone; see
  [Standard or strict certificate authority](#standard-or-strict-certificate-authority). One made by an earlier version
  also vouches for the names under this server's names, such as `x.siem-1`; the line
  says so, and a new one covers each name exactly.
- Needs attention: a new certificate authority is ready but not switched to yet; the
  previous one is still kept after a switch; the one in use was made by an older version
  and can vouch for any website; the one in use was made by an older version and isn't
  limited to websites, so a stolen key could sign programs or email that computers
  trusting it accept; or the one in use isn't the kind you chose.

**To fix:** follow
[Switching to a new certificate authority](https.md#switching-to-a-new-certificate-authority).

**How to check by hand:**

```sh
sudo openssl x509 -in /var/lib/signalith/tls/ca.pem -noout -subject -enddate -ext nameConstraints,extendedKeyUsage
```

A standard one lists private names such as `.local` and `.corp` and private ranges. A
strict one lists only this server's names and addresses. Under **Excluded**, the
server's names with a dot in front keep the names under them out. No name constraints at
all means it was made by an older version. **X509v3 Extended Key Usage** should read
`TLS Web Server Authentication` alone; without it, it was made before the website-only
limit.

### Agents on plain HTTP

Shown while HTTPS is on.

**Looks at:** **Agents on plain HTTP** (`server.tls.plaintext_ingest`), and which agents
sent events over plain HTTP in the last day. An agent on the server itself is counted
apart: its events don't cross the network.

- Good: agents can only send over HTTPS.
- At risk: agents on other computers still send over plain HTTP.
- Needs attention: plain HTTP is still accepted, though only agents on this computer,
  or none, use it.

**To fix:** give each agent a new configuration from **Add data**, then choose
**Refuse them**. An agent that was missed keeps its events, and the **Health** page
names it. See [Upgrading from plain HTTP](https.md#upgrading-from-plain-http).

**How to check by hand:** the **Health** page lists agents that send over plain HTTP.

### Syslog

Shown when a syslog listener is on (`syslog.udp`, `syslog.tcp` or `syslog.tls`).

**Looks at:** which listeners are on and the addresses they listen on, `syslog.allow`,
and how many devices sent over each protocol in the last day. A listener on a loopback
address, such as `127.0.0.1:5514`, takes syslog only from this computer, so only the
others count.

- Good: syslog arrives only over TLS; or plain syslog is accepted only from this
  computer, or only from the addresses in `syslog.allow`. Plain syslog isn't encrypted,
  which is normal for devices that can't use TLS.
- Needs attention: plain syslog is accepted from any computer that can reach the port.
  Anyone could send fake events.
- Can't tell: in Docker Desktop, every device seems to come from the same address, so
  Signalith can't limit who sends. Limit who reaches the port with this computer's
  firewall instead.

**To fix:** list the addresses or ranges of the devices that send syslog under
`syslog.allow`, such as `10.0.0.0/8`. Devices that can use TLS, such as rsyslog,
syslog-ng and many firewalls, can send over TLS instead
([Agents and syslog](https.md#agents-and-syslog)).

**How to check by hand:** `sudo ss -lntup | grep signalith` shows the ports Signalith
listens on, and on which addresses. Check the computer's firewall for those ports.

### Connection to OpenSearch

**Looks at:** the OpenSearch address (`opensearch.url`), whether Signalith checks
OpenSearch's certificate (`opensearch.tls_skip_verify`, `opensearch.ca_file`), whether
it sends a password, and the certificate OpenSearch presents. The demo certificate that
OpenSearch ships with is issued by **Example Com Inc. Root CA**; its key is public.

- Good: HTTPS with the certificate checked; or plain HTTP to OpenSearch on this
  computer.
- Needs attention: plain HTTP to OpenSearch on the same Docker network; or, for
  OpenSearch on this computer, the demo certificate or certificate checks turned off.
- At risk: certificate checks are off for OpenSearch on another computer; events or the
  password cross the network over plain HTTP; or OpenSearch on another computer uses
  the demo certificate.

**To fix:** see
[Point Signalith at it](opensearch-security.md#4-point-signalith-at-it) and
[Make the certificates](opensearch-security.md#1-make-the-certificates).

**How to check by hand:**

```sh
openssl s_client -connect opensearch.example.com:9200 </dev/null 2>/dev/null | openssl x509 -noout -issuer -enddate
```

### AI assistant and threat intel

Shown when the AI assistant is set up or a threat intel feed is on.

**Looks at:** whether the AI assistant (`assistant.url`) and each feed are reached over
`https://`, and whether a key, password or header is sent with them.

- Good: everything is reached over HTTPS, or the assistant runs on this computer.
- Needs attention: a feed is downloaded over plain HTTP, so someone on the network could
  change what it says.
- At risk: an API key or a feed's password crosses the network over plain HTTP.

**To fix:** use the `https://` address of the assistant (**Settings**) or the feed
(**Threat intel**), if it has one.

### Trusted reverse proxies

Shown when **Trusted reverse proxies** is set, or when Signalith believes a proxy only
because `signalith.yaml` was written before HTTPS was the default.

**Looks at:** each entry in `server.trusted_proxies`, and the proxies believed for the
older reason in the last day.

- Good: only the listed proxies are believed.
- Needs attention: an entry is wider than a /16 (IPv4) or /48 (IPv6), so any computer in
  it can claim a browser used HTTPS; or a proxy is believed only because of the older
  config.

**To fix:** list only the proxies' own addresses. See
[Behind a reverse proxy](https.md#behind-a-reverse-proxy).

## At rest

Whether stored passwords, keys and events are protected on disk.

### Master key

**Looks at:** where the master key comes from (a file, a systemd credential, Windows
protection, a Docker volume or secret, or the `SIGNALITH_MASTER_KEY` environment
variable), who can read the key file, and whether an older key or an unused copy is
still kept. On Windows it reads the file's access list; it never trusts file modes
there.

- Good: only Signalith's account can read the key, or Windows protects it.
- Needs attention: a group can read it, it belongs to another account, it is in an
  environment variable, or an older key or unused copy is still kept.
- At risk: every account on this computer can read the key.

**To fix:** see [The master key](encryption.md#the-master-key),
[Keeping the key elsewhere](encryption.md#keeping-the-key-elsewhere) and
[Changing the key](encryption.md#changing-the-key).

**How to check by hand:** `sudo signalith secrets status` says where the key is. On
Linux, `sudo ls -l /var/lib/signalith/keys` should show `-rw-------` and Signalith's
account. On Windows,
`icacls C:\ProgramData\Signalith\keys\master.key.dpapi`.

### Stored passwords and keys

**Looks at:** the passwords and keys in `signalith.yaml`, `settings.yaml`,
`directory.json` and `intel_feeds.yaml`: whether each is encrypted with the master key,
and who can read a file that holds one as plain text. Values that come from environment
variables aren't stored, so they aren't counted.

- Good: every stored password and key is encrypted.
- Needs attention: some are plain text; a password is written into an address, where it
  can't be encrypted; some are still encrypted with the previous master key; or some
  can't be decrypted.
- At risk: plain text values are in a file other accounts can read.

Signalith's HTTPS keys and the Docker setup's generated secrets are protected by file
permissions, not by the master key (see [File permissions](#file-permissions)).

**To fix:** `sudo signalith secrets encrypt` (see
[What Signalith encrypts](encryption.md#what-signalith-encrypts) and
[Commands](encryption.md#commands)).

**How to check by hand:** `sudo signalith secrets status` lists each value and how it is
stored, without showing it.

### Disk encryption

**Looks at:** the disks that hold Signalith's state folder, its lookups folder and its
config file. Each disk is reported once.

- On Linux, it reads `/proc/self/mountinfo` and `/sys` to find the disk under each
  folder, and looks for an encryption layer such as LUKS (dm-crypt), eCryptfs or
  gocryptfs. It needs no access to `/dev`. Self-encrypting drives don't show this way.
- On Windows, only administrators may ask whether BitLocker is on. Run
  `signalith security` in a PowerShell opened as Administrator: it asks Windows and saves
  the answer for the page. The page uses a saved answer for 30 days.
- It also notes a virtual machine (QEMU, KVM, VMware, Hyper-V, Xen, VirtualBox,
  Parallels and the big clouds), a network share, memory, ZFS and containers.

- Good: the disk is encrypted, or Signalith's files are kept in memory only.
- Needs attention: a physical disk with no encryption, as far as the system can tell;
  or BitLocker is off or suspended.
- Can't tell: a virtual disk (its host may encrypt it), a container, a network share,
  ZFS, or Windows without a saved answer.

**To fix:** encrypt the disk, or move Signalith's folders to an encrypted one; see
[Disk encryption](encryption.md#disk-encryption).

**How to check by hand:**

- Linux: `lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINTS`. A `crypt` line above the disk means
  it is encrypted.
- Windows, as Administrator: `manage-bde -status C:`, or
  `& "$env:ProgramFiles\Signalith\signalith.exe" security`, which also saves the answer
  for the page.
- Docker Desktop: check the drive of the computer it runs on, with
  `manage-bde -status C:` on Windows or `fdesetup status` on macOS.
- ZFS: `zfs get encryption <dataset>`.
- A virtual machine or cloud server: check the disk's settings in the provider's
  console, or ask whoever runs the host.

### Archived days

Shown when the archive folder holds archives, or a retention policy archives days.

**Looks at:** the archive folder (`retention.archive_dir`): how many days it holds and
their size, who can read it, and the disk under it, as for
[Disk encryption](#disk-encryption). Signalith doesn't encrypt archives itself.

- Good: on an encrypted disk, readable only by Signalith.
- Needs attention: other accounts can read the archives, or the disk isn't encrypted.
- Can't tell: Signalith can't see the disk or share under them.

**To fix:** keep the archive folder on an encrypted disk, readable only by Signalith; see
[Archives](retention.md#archives). Copies of archives you move elsewhere are only as safe
as where you put them.

### Where OpenSearch keeps events

**Looks at:** when OpenSearch runs on this computer and Signalith isn't in a container,
it asks OpenSearch for its data folder (`path.data`), with Signalith's own account, and
checks the disk under it, as for [Disk encryption](#disk-encryption). A folder that
doesn't exist here (OpenSearch in a container of its own reports the container's
folder) isn't checked.

- Good: an encrypted disk, or a folder kept in memory only.
- Needs attention: a disk that isn't encrypted, as far as the system can tell.
- Can't tell: OpenSearch runs on another computer or in its own container; its folder
  isn't on this computer's disks as Signalith sees them; Signalith's account may not
  look inside a folder on the way (such as `/home` under the systemd unit); or OpenSearch
  didn't answer.

**How to check by hand:** on the computer OpenSearch runs on, find `path.data` in
`opensearch.yml` and check the disk that holds it, with the commands under
[Disk encryption](#disk-encryption). In the Docker quick start, events are in the
`opensearch-data` volume, on the disk of the computer Docker runs on.

### Who can read OpenSearch

**Looks at:** whether OpenSearch answers a search with no sign-in at all. Signalith
sends one request with no user name, password or client certificate, to count the
events in its own indices, and gives it 5 seconds. When OpenSearch is on this computer,
it also tries the same port on this computer's other addresses, to see whether
OpenSearch listens on the network. If OpenSearch keeps an audit log, it records this as
a refused request.

- Good: OpenSearch turns away anyone who doesn't sign in.
- Needs attention: anyone on this computer can read events, but OpenSearch doesn't
  listen on the network.
- At risk: anyone who can reach OpenSearch can read events without signing in.
- Can't tell: OpenSearch couldn't be reached just now. The **Health** page shows why.

**To fix:** turn on OpenSearch's security plugin with your own certificates, as in
[OpenSearch on Linux or Windows](opensearch-security.md#opensearch-on-linux-or-windows)
(or [Docker quick start](opensearch-security.md#docker-quick-start)).

**How to check by hand:** this should print `401`, not `200`:

```sh
curl -s -o /dev/null -w '%{http_code}\n' --cacert root-ca.pem 'https://localhost:9200/signalith-*/_count'
```

## In use

Whether secrets stay private while Signalith runs.

### Memory

**Looks at:** on Linux, whether the process may write a crash dump (its core limit and
whether it is dumpable), and whether swap could hold its memory. On Windows, whether
Windows is set to keep full memory dumps of crashing programs.

- Good: Signalith's memory can't be saved in a crash dump. A tip says when swap is on
  and not encrypted, and when a confidential VM would protect memory from the host too.
- Needs attention: a crash dump could hold passwords.

**To fix:** restart Signalith with this version, which turns crash dumps off; under
systemd, keep `LimitCORE=0` in the unit. On Windows, leave `signalith.exe` out of the
**LocalDumps** setting. See [In use](encryption.md#in-use).

**How to check by hand:**

- Linux: `grep 'core file' /proc/$(systemctl show -p MainPID --value signalith)/limits`
  shows `0`, and `swapon --show` lists swap.
- Windows:
  `reg query "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" /s`.

### Confidential virtual machine

Shown only when found, on Linux: AMD SEV-SNP (`/sys/class/misc/sev-guest`) or Intel TDX
(`/sys/class/misc/tdx_guest`, or `tdx_guest` in `/proc/cpuinfo`). Such a machine is built
to keep even its host from reading its memory. Some platforms hide these markers, so
not finding one proves nothing, and Signalith doesn't report it as a problem.

**How to check by hand:** your cloud provider's console says whether the VM is
confidential.

## Accounts and sign-in

Who can sign in, and how well passwords and tokens are kept.

### Built-in admin's password

**Looks at:** whether the built-in admin still has the public example password, the
first password the Docker setup made, a password set in the `SIGNALITH_ADMIN_PASSWORD`
environment variable, or one read from the file in `SIGNALITH_ADMIN_PASSWORD_FILE`; and
how strongly it is hashed.

- Good: it has a password of its own.
- Needs attention: the Docker setup's first password, which is kept as plain text in a
  Docker volume; a password in an environment variable, or in a file named by one; or
  an older, weaker hash.
- At risk: the example password `change-me-please`, which anyone can look up.

**To fix:** `sudo signalith passwd`, then restart Signalith; see
[The built-in admin](users.md#the-built-in-admin).

### Everyday sign-in

**Looks at:** when the built-in admin last signed in, and how many other people have
admin accounts.

- Good: people sign in with their own accounts, or only the built-in admin exists so far
  (with a tip to give yourself an account, so the audit log shows who did what).
- Needs attention: the built-in admin signed in during the last 7 days, though others
  have admin accounts. Keep it for emergencies.

**To fix:** see [The built-in admin](users.md#the-built-in-admin).

### Temporary passwords

Shown when there are local users.

**Looks at:** enabled local users who still have the temporary password they were given
more than 7 days ago.

**To fix:** remind them to sign in and choose a password, or disable their account until
they need it ([Managing local users](users.md#managing-local-users)).

### Directory sign-in

Shown while directory sign-in is on.

**Looks at:** the directory addresses (main and failover): `ldaps://`, or `ldap://` with
StartTLS, and whether Signalith checks the directory server's certificate.

- Good: passwords go to the directory encrypted, and its certificate is checked.
- At risk: `ldap://` without StartTLS, so passwords cross the network unencrypted; or
  certificate checks are off, so someone could pose as the directory and collect
  passwords.

**To fix:** use an `ldaps://` address or turn on StartTLS, give the directory's CA
certificate, and turn off **Skip certificate check**
([Set it up](users.md#set-it-up)).

**How to check by hand:**
`openssl s_client -connect dc1.corp.example.com:636 </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer`.

### Sign-in sessions

**Looks at:** **Sign out after** (`auth.session_timeout`, 12 hours by default): how
long a sign-in lasts without use. An open tab's own refreshes (the Health card,
dashboards and other timers) don't count as use, so a tab left unattended still signs
out. Someone who ticks **Keep me signed in** isn't signed
out for being idle; every sign-in ends after 7 days at most.

- Good: 24 hours or less.
- Needs attention: longer than 24 hours.

**To fix:** set **Sign out after** to 12h or less on the **Settings** page.

### Agent tokens

Shown when agent tokens are set (`ingest.tokens`).

**Looks at:** whether a token is the public example token, and how long each token is.
All agents share a token, so one taken from any agent works for all of them until it is
replaced.

- Good: every token has 24 characters or more. Tokens Signalith makes have 48.
- Needs attention: a token is shorter than 24 characters.
- At risk: the example token `change-this-ingest-token`, which anyone can look up. On a
  Docker quick start upgraded from an older version, whose agents all have it, Signalith
  accepts it from them over plain HTTP while **Agents on plain HTTP** accepts them, even
  when it isn't in `ingest.tokens`. Choose **Refuse them** once every agent has its
  configuration from **Add data**; that ends it for good.

On the Docker quick start the check also says why the old example token is refused: the
install started new, it was upgraded and agents on plain HTTP were refused since a date,
or Signalith couldn't yet ask OpenSearch which it is. See
[The Docker quick start's old example token](https.md#the-docker-quick-starts-old-example-token).

**To fix:** add a new token with `sudo signalith secrets set ingest.tokens` (press Enter
to have one made), give each agent a new configuration from **Add data**, then remove the
old token. See [Commands](encryption.md#commands).

### Signalith's OpenSearch account

Shown when OpenSearch requires sign-in and has its security plugin.

**Looks at:** what OpenSearch says Signalith's account may do
(`/_plugins/_security/authinfo`), and whether Signalith signs in as `admin` with the demo
password `admin`. The password is compared in memory and never shown.

- Good: an account without admin rights.
- Needs attention: an account that can do anything in OpenSearch (`all_access`,
  `security_manager` or the `admin` backend role).
- At risk: `admin` with the password `admin`.
- Can't tell: OpenSearch couldn't be reached, or didn't say.

**To fix:** give Signalith its own account with the `signalith_server` role, ideally
signing in with a certificate
([Load the security settings](opensearch-security.md#3-load-the-security-settings)).

**How to check by hand:**

```sh
curl -s --cacert root-ca.pem --cert signalith.pem --key signalith-key.pem 'https://localhost:9200/_plugins/_security/authinfo?pretty'
```

## This server

How Signalith runs on this computer.

### Account Signalith runs as

**Looks at:** the account of the Signalith process: root or not on Linux and in
containers, and on Windows whether it is Local System, an administrator, or its own
service account.

- Good: its own account (`signalith` under systemd, `NT SERVICE\Signalith` on Windows),
  or an unprivileged account in a container.
- Needs attention: root, Local System or an administrator, so a flaw in Signalith could
  reach the whole computer.
- Can't tell: on Windows, the service runs as an account Windows couldn't say is an
  administrator or not, such as a domain account while the domain can't be reached.

**To fix:** on Linux, install the systemd unit from [Linux](../README.md#linux); on
Windows, run `install.ps1` from this version again ([Windows](../README.md#windows)). In
Docker, remove a `user:` line that overrides the image's account.

**How to check by hand:**

- Linux: `ps -o user= -p $(systemctl show -p MainPID --value signalith)`.
- Windows: `sc.exe qc Signalith` shows `SERVICE_START_NAME`.
- Docker: `docker compose -f deploy/docker/docker-compose.yml exec signalith id`.

### Service protections

Shown on Linux. On Windows, [Account Signalith runs as](#account-signalith-runs-as)
covers the service.

**Looks at:** the protections the systemd unit in `deploy/systemd` sets up, as the
process sees them: no new privileges, a system-call filter, no extra capabilities, a
read-only system, hidden processes, a private `/dev` and private new files. In a
container: no new privileges, no capabilities, a read-only system and no core dumps.

- Good: all of them are in place. Linux before 5.8 can't hide processes, so there it
  isn't counted as missing.
- Needs attention: some are missing, or Signalith doesn't run as a systemd service.

**To fix:** install the current unit and restart, as in [Linux](../README.md#linux). If
you changed the unit on purpose, compare it with `systemctl cat signalith`. In Docker,
keep `read_only: true`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]` and
`ulimits: core: 0` in `docker-compose.yml`.

**How to check by hand:** `systemd-analyze security signalith`.

### File permissions

**Looks at:** who may read or change Signalith's keys (the HTTPS keys in `tls/`, a key
file for OpenSearch, and the files named by `SIGNALITH_*_FILE` variables), its private
files (`users.json`, `directory.json`, `settings.yaml`, `intel_feeds.yaml`, the admin
password hash), its folders, and `signalith.yaml` with its folder. The master key is
left to [Master key](#master-key). On Windows it reads each file's access list; on Linux
and macOS, the owner and mode.

- Good: only Signalith's account (and administrators) can change them, and only they
  can read the keys and private files. For `signalith.yaml` and the folders, it looks
  only at who can change them. Whether others can read plain passwords in
  `signalith.yaml` is part of [Stored passwords and keys](#stored-passwords-and-keys).
- Needs attention: a group or other accounts can read private files, or a group can
  change a folder; or the state folder is on a network share, so keys cross the network
  each time they are read.
- At risk: every account can read a key, or change the config or a folder.

**To fix:** the check gives the exact commands for each file. On Linux,
`sudo chmod -R go-rwx /var/lib/signalith` covers the state folder. On Windows, running
`install.ps1` from this version again resets access in `C:\ProgramData\Signalith`. Keep
the state folder on a local disk ([Identity](servers.md#identity)).

**How to check by hand:**

- Linux: `sudo ls -la /var/lib/signalith /var/lib/signalith/tls /etc/signalith`.
- Windows: `icacls C:\ProgramData\Signalith /t`.

## Standard or strict certificate authority

With Signalith's own certificate, computers that trust its certificate authority accept
any certificate it makes. **Certificate authority reaches** (`server.tls.ca_scope`)
chooses how far that goes. Neither choice lets it vouch for other public websites: of
public names, only this server's own, each exactly.

- **Standard**, the default, can also vouch for private network names and addresses,
  such as `intranet.corp` or `192.168.1.5`. A new address for this server works right
  away.
- **Strict** can vouch only for this server's own names and addresses. A stolen key
  then lets someone pose only as this server's website, but a new name or address later means a
  new certificate authority, which every browser and agent must trust again.

Strict suits a server whose name and address won't change, especially when many
computers trust it. Both are **Good** on the page. The setting only applies to a
certificate authority made from now on; see
[How far the certificate authority reaches](https.md#how-far-the-certificate-authority-reaches)
and [Switching to a new certificate authority](https.md#switching-to-a-new-certificate-authority).

## Always on

The report also lists protections that can't be turned off, as they apply to this
server:

- With HTTPS on, passwords, API sign-ins and sessions are refused over plain HTTP, and
  the sign-in cookie is sent over HTTPS only.
- With HTTPS on, browsers that reach Signalith by name are told to use HTTPS only
  (HSTS).
- Every page has a strict Content Security Policy and can't be shown inside another
  site.
- Guessing passwords is slowed: after 10 wrong tries for one account from one address in
  15 minutes, sign-in pauses for 15 minutes. The API is limited the same way.
- Sign-ins end after 7 days at most, even with **Keep me signed in**.
- Passwords are stored only as bcrypt hashes.
- Logs, pages and the API never show stored passwords or keys.
- With HTTPS on, agents set up from **Add data** check the server's certificate before
  sending.
- Sign-ins, sign-outs and every change to users and settings go to the audit log.

## Not checked here

Signalith can't see these, so it says so once rather than showing **Can't tell** for
them every time:

- **Firewalls**: which computers can reach Signalith's ports (8080 by default, and the
  syslog ports) and OpenSearch's (9200 by default). Check the firewall of this computer
  and of the network.
- **Backups**, and whether the master key is kept apart from them (see
  [Backing up the key](encryption.md#backing-up-the-key)).
- **Updates** for Signalith, OpenSearch and the operating system. Signalith doesn't
  contact the internet to check.
- **Two-step sign-in**. Signalith has none of its own.
- **The computers agents run on**.
- **Copies of events outside Signalith**, such as exports, moved archives and OpenSearch
  snapshots.

## The signalith security command

```sh
sudo signalith security            # Linux
sudo signalith security -json      # the same report as JSON
```

```powershell
& "$env:ProgramFiles\Signalith\signalith.exe" security    # Windows, as Administrator
```

```sh
docker compose -f deploy/docker/docker-compose.yml exec signalith signalith security
```

It runs the same checks as the page, from the files and processes on this computer, and
prints the report as plain text: a summary, **Fix first** with the commands for this
kind of install, then every check by group. Docs links are printed in full.

- On Linux it uses the folders, files and master key the service is given in its systemd
  unit, like `validate`, `settings` and `secrets` do, and looks at the running service's
  process. In Docker it looks at the container's first process. When it finds no
  running service for the config file (it is stopped, or was started another way), the
  checks of the process say so. The Security page checks them either way.
- On Windows, run as Administrator, it also asks whether BitLocker is on and saves the
  answer for the page. It says so on standard error, so the report itself stays the
  same.
- It can't see what only the running server sees: agents and devices that sent in the
  last day, sign-ins over plain HTTP, and computers that refused a new certificate. The
  checks that need those say so, rather than claiming "none". The page has them.
- Without root or Administrator, it may not be able to read the config file. It then
  stops and says to run it with `sudo` or as Administrator. A folder or file it can't read
  makes that check **Can't tell**.
- `-json` prints the same JSON as `GET /api/security`, without what only the running
  server sees (`others`, `seen_names` and `refusals`). Notes go to standard error, so the
  output stays JSON.

Exit codes, for scripts and monitoring:

| Code | Meaning |
| --- | --- |
| `0` | Nothing is at risk. |
| `2` | Something is at risk. |
| `1` | The command couldn't run, for example the config file couldn't be read. |

**Needs attention** and **Can't tell** never change the exit code.

## API

Both routes are for admins only.

- `GET /api/security` returns the last report as JSON. It never waits for a new run,
  unless there is no report yet. `?recheck=1` runs the checks again first (at most once
  every 10 seconds). `?format=text` returns the plain text report, and `&download=1`
  saves it as a file.
- `POST /api/security/ca` takes the steps of a change of certificate authority:
  `{"action": "prepare"}` (with `"scope": "standard"` or `"strict"` to change
  `server.tls.ca_scope` too), `switch`, `rollback`, `discard` or `prune`. It returns the
  new report. See
  [Switching to a new certificate authority](https.md#switching-to-a-new-certificate-authority).

The report has `checked_at`, `server`, `summary` (counts by state), `fix_first` (check
ids), `groups`, `checks`, `always_on`, `not_checked`, and, with Signalith's own
certificate, `ca`. Each check has its `id`, `group`, `title`, `state` (`risk`,
`attention`, `unknown` or `good`), `line`, `details`, and a `fix` or `tip` with steps,
a setting, a page, commands and a docs link.
