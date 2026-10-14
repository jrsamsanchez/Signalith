# Endpoints (osquery)

Signalith can manage hosts that run [osquery](https://osquery.io), the open-source
endpoint agent. Signalith is osquery's management server: hosts enroll with an ingest
token, fetch what to collect from Signalith, and send their results back. Nothing else is
set up on the host, and changes on the **Endpoints** page reach every host within five
minutes.

Each host reports:

| What | Data model | When |
| --- | --- | --- |
| Files created, changed, renamed or deleted in the watched folders, with their SHA-256 on Linux and macOS | Filesystem | within a minute |
| Listening ports and the program behind each | Inventory (`inventory_type=port`) | every 10 minutes |
| Operating system, installed software, accounts, services and startup items, as they are added or removed | Inventory (`inventory_type=os`, `software`, `user`, `service`, `startup`) | every hour (adjustable) |
| Configuration checks, when a result changes | Configuration_Check | every hour (adjustable) |

Inventory and checks are sent the first time in full, then only what changed, so an
unchanged host sends nothing. osquery runs them on the hour, so a newly enrolled host's
inventory and check results appear within the hour; a live query shows anything sooner.

Hosts found this way are also added to the asset list (**Risk and context**), as
`category=endpoint` with their platform, unless your own list already has them.

## Adding hosts

1. Open **Add data**, pick **osquery**, and choose the platform the hosts run.
2. Install osquery 5 on each host from <https://osquery.io/downloads>.
3. Download the setup script and run it on each host:
   - Linux and macOS: `sudo sh signalith-osquery-setup.sh`
   - Windows, in an elevated PowerShell:
     `powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\Downloads\signalith-osquery-setup.ps1"`
4. On macOS, give osqueryd Full Disk Access (System Settings, Privacy & Security, Full Disk
   Access, add `/opt/osquery/lib/osquery.app`).

The script saves three files next to osquery (`/etc/osquery` on Linux, `/var/osquery` on
macOS, `C:\Program Files\osquery` on Windows): Signalith's CA certificate, the enroll
secret (readable only by root, or SYSTEM and Administrators), and `osquery.flags`, which
points osquery at Signalith. It then restarts osquery. The host appears on the
**Endpoints** page within a minute.

The script holds an [agent token](agent-tokens.md) of its own, made when you copy or
download it on Add data, so keep it private. osquery always checks Signalith's
certificate. It checks it against the address it connects to, so use a host name the
certificate covers; an IP address works only with the certificate Signalith makes itself.

Each host is one row, keyed by its hardware UUID, even when osquery is reinstalled.

## The Endpoints page

Analysts and admins can open **Endpoints**:

- **Hosts** lists every host with its status (online when seen in the last three minutes),
  failing checks, address and osquery version. Open one for its hardware, addresses,
  configuration fetch, osquery's own errors, and every check result with how to fix it.
  Links there open the host's file changes and inventory changes in Search.
- **Configuration checks** lists every check with how many hosts pass and fail, and which
  hosts fail.
- **Live query** (admins) runs osquery SQL on hosts now: all hosts, one platform, or one
  host, optionally only those online. Online hosts answer within about ten seconds.
  Results can be saved as CSV. A query stays open for ten minutes, returns at most 1,000
  rows and 4 KB per value per host, and is recorded in the audit log. The table
  reference is at <https://osquery.io/schema/>.

Admins also have:

- **What hosts collect**: turn file monitoring and checks on or off, edit the watched
  paths and the paths left out per platform, and set how often inventory and checks run
  (5 minutes to 24 hours). Paths use osquery's patterns: `%` matches within one folder
  level and `%%` matches everything below. Saving warns when someone else saved since you
  opened it.
- **Remove**: deletes the host's record so its key stops working. A host still running
  osquery enrolls again at its next contact, unless you also choose **Block**: then it is
  refused until you unblock it. Events it already sent stay in Search.

### Watched paths by default

| Platform | Paths |
| --- | --- |
| Linux | `/etc`, `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/local/bin`, `/usr/local/sbin`, `/boot`, `/root/.ssh`, `/home/*/.ssh`, `/var/spool/cron` (leaving out `/etc/mtab` and `/etc/ld.so.cache`) |
| Windows | `drivers\etc`, `System32\Tasks`, `System32\GroupPolicy`, and the all-users and per-user Startup folders |
| macOS | `/etc`, `/Library/LaunchDaemons`, `/Library/LaunchAgents`, `~/Library/LaunchAgents`, `/usr/local/bin`, `~/.ssh`, `/var/root/.ssh` |

These are the places attackers change to stay on a host or gain rights. Watching large,
busy folders makes osquery work harder; add only what you need.

## Configuration checks

91 checks ship with Signalith: 45 for Linux, 26 for Windows and 20 for macOS. Each says
what a passing host does, why it matters, and how to fix it.

- The Linux checks are based on rules in the [SCAP Security Guide](https://github.com/ComplianceAsCode/content)
  (BSD-3-Clause), and name the rule and its NIST SP 800-53 controls. Search finds them with
  `datamodel=Configuration_Check benchmark="SCAP Security Guide"`.
- The Windows and macOS checks follow the vendors' own hardening guidance.

A result is `pass`, `fail`, `n/a` (the check does not apply, such as SSH settings on a
host without an SSH server) or `error`. Each change of result is an event, so
`datamodel=Configuration_Check result=fail | stats count by check, dest` shows what fails
where.

## Searching

```
datamodel=Filesystem dest=web1 action=modified
datamodel=Filesystem file_path="/etc/sudoers*"
datamodel=Inventory inventory_type=software action=added | stats count by name, version
datamodel=Inventory inventory_type=port dest_port=3389
datamodel=Configuration_Check result=fail severity=high
```

Every osquery event has `vendor_product=osquery`, `sourcetype=osquery:<query>` and
`endpoint_id`, the host's ID on the Endpoints page.

## How it works

osquery uses its TLS remote API with these routes on Signalith's HTTPS port:

| Route | Use |
| --- | --- |
| `POST /api/osquery/enroll` | The host sends the enroll secret (an [agent token](agent-tokens.md)) and gets its own node key |
| `POST /api/osquery/config` | The host fetches what to collect, every five minutes |
| `POST /api/osquery/log` | Results and osquery's own status messages |
| `POST /api/osquery/distributed/read` | The host asks for live queries, every ten seconds |
| `POST /api/osquery/distributed/write` | Live query answers |

They take a token or node key instead of a signed-in user. Node keys are random; Signalith
stores only their hash. Hosts and settings are kept in OpenSearch (the `<prefix>_endpoints`
index), so every Signalith server knows every host, and a host sending to another server
runs each live query once.

Revoking the agent token a host enrolled with, or choosing **Stop accepting** on a shared
token, removes every host enrolled with it, on every server, and their next request is
refused at once. A host whose shared token was deleted from signalith.yaml or the
environment is refused too. They enroll again with an active token. See
[agent-tokens.md](agent-tokens.md#osquery-hosts).
