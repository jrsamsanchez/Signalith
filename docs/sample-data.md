# Sample data

Sample data fills Signalith with a realistic week of security activity for a
fictional company, with a handful of attacks hidden in it, so you can try the
SIEM on data that makes detections fire, fills the triage queue, builds risk on
users and hosts, matches threat intel and lights up the dashboards. Load it in
one click, look around, and remove it in one click when you are done.

Everything is made up and safe to load next to real data:

- the company is fictional and its domain is `corp.example` (a reserved
  documentation name, RFC 6761);
- every address, the company's own hosts included, is from the documentation
  ranges (RFC 5737): its hosts use `192.0.2.0/24`, and the outside world
  `198.51.100.0/24` and `203.0.113.0/24`. None of them can be a host on your
  network, so the sample's asset list never describes one of your machines;
- the generator is deterministic and offline: it reads nothing from the
  network or disk.

Every document the sample writes carries a hidden marker field,
`signalith_sample`, holding the load's ID. Removal deletes exactly what has
the marker and nothing else. The marker is kept out of search results and
field lists, so it never clutters what you see.

Only the sample-data load can set the marker. Signalith removes it from every
event that agents and syslog senders send, so nobody can hide their own events
from the detections, or have them deleted with the sample data, by adding it.

## Load and remove it

**In the browser (admins):** open **Add data** under Configure. The **Try it
with sample data** card loads the week, shows its progress, then lists things
to try (each opens a view covering the whole week) and removes it again behind
a confirm. While it loads, the detections run over the week so findings and
risk appear at once. On a server with no events in the last seven days,
Dashboards and Search show admins a one-line pointer to it.

**From the shell** (or in Docker):

```sh
signalith sample-data load               # a full week (about 27,000 events)
signalith sample-data load -size small   # the same attacks with less background
signalith sample-data status             # whether it is loaded, and the counts
signalith sample-data remove             # take all of it out

# In Docker:
docker compose -f deploy/docker/docker-compose.yml exec signalith signalith sample-data load
```

Loading twice is refused: remove the set first, then load again. Loading and
removing are logged as admin actions and run in the background. Only one runs
at a time, across the web page, the command line and every server that shares
your OpenSearch: a load started from the shell, or on another server, shows its
progress on the card, with where it runs.

`signalith sample-data status` needs to reach OpenSearch, like `load` and
`remove`: the record of what is loaded is kept there (see
[Several servers](#several-servers)).

If a load stops part way (an error, a restart, or Ctrl-C), what it wrote so
far is recorded. The card says **The last load did not finish** and offers
**Remove what was loaded**; `signalith sample-data remove` does the same. A
new load is refused until it is removed. A removal that stops part way works
the same way: the card says **The last removal did not finish** and offers
**Finish removing**, and `signalith sample-data remove` finishes it too.

When you stop or restart a server (or its container) in the middle of a load
or removal, it notes that the job did not finish before it exits, so the card
says so as soon as the server is back. If `signalith sample-data remove` finds
a load or removal recorded as running somewhere else, it first checks, for up
to a minute, whether that is still going: it waits for it if so, and finishes
the job if not.

## What it contains

- **A fictional organisation:** about 50 users and 40 hosts: finance, IT and
  operations workstations, a few Linux servers (web, app, database, jump host),
  two domain controllers and a file server.
- **A week of background activity** with a working-hours and weekday rhythm:
  sign-ins, process starts, network connections, firewall traffic and DNS
  lookups: ordinary noise for the attacks to hide in, plus a benign look-alike
  to practise closing as a false positive.
- **An OT flavour:** an engineering workstation, two HMIs and three PLCs, with
  the HMIs polling the PLCs over Modbus (TCP 502) and writing to a historian.
  It is all normal; no detection targets OT, it just shows the plant floor in
  the data.
- **Context and intel:** asset and identity entries for the company (with
  priorities, categories and a watchlist entry), and seven threat-intel
  indicators (three attacker addresses, a malware update domain, a phishing
  domain and two malware hashes), each of which the events match.
- **A sample investigation**, *Sample: phishing intrusion on ws-fin-07*,
  holding the phishing story's findings in the order they fired, to open and
  practise on.

Two sizes load the same attacks; only the volume of background activity
differs. **Standard** is a full week, about 27,000 events. **Small** keeps two
days of light background, a few hundred events in all.

## A guided tour of the attacks

Five stories are woven into the week. Four are intrusions designed so that
every built-in detection that is on fires; the fifth is benign activity that
trips a detection as a false positive.

Some detections raise a **finding** on the Findings page. Others only add
**risk** to the users and hosts involved, which shows on the Risk page and
counts toward the risk findings below. The table keeps them apart.

| Story | What happens | Raises findings | Adds risk only |
| --- | --- | --- | --- |
| **SSH brute force from the internet** | An external host (`203.0.113.45`) password-sprays SSH on the database server `db-01`, breaks the account `bob.okafor`, logs in as root and reads `/etc/shadow`. | auth-brute-force, auth-password-spray, auth-brute-force-success, auth-shadow-file-access, threat-activity | auth-ssh-root-login, auth-sudo-failures |
| **Phishing to credential theft and C2** | A finance workstation (`ws-fin-07`, Alice Nguyen) looks up a look-alike sign-in site, opens a malicious invoice that launches encoded PowerShell, downloads a tool with `certutil`, dumps credentials with Mimikatz, runs discovery, installs persistence and beacons to a C2 that is in the sample intel. | endpoint-office-child-shell, endpoint-encoded-powershell, endpoint-credential-dumping, threat-activity | endpoint-lolbin-download, endpoint-discovery-burst, endpoint-scheduled-task, endpoint-service-created, network-shell-port |
| **Hidden admin account on the domain controller** | On `dc-01` the attacker creates `svc-helpdesk` and adds it to Domain Admins, then deletes a stale contractor account. | change-admin-group-add | change-account-created |
| **Ransomware preparation on the file server** | Using the stolen domain-admin account, the attacker reaches `file-01` over SMB and deletes the volume shadow copies and recovery configuration. | endpoint-shadow-copy-delete | |
| **Benign activity that looks malicious** | A backup job on `file-01` runs encoded PowerShell, and IT fetches a tool with `certutil`. | endpoint-encoded-powershell on `file-01`: one finding to close as benign | endpoint-lolbin-download on `ws-it-02` |

The risk that builds up then raises two more findings on its own:

- **risk-threshold-exceeded**: a user or host passed the risk threshold;
- **risk-multiple-tactics**: risk from several ATT&CK tactics on one entity.

So 20 of the 22 built-in detections fire from the sample, all of them on.
Each detection adds its risk once per thing it found, so the totals on the
Risk page and the dashboards are the same every time you load.

### Detections that do not fire

Two built-in detections are **off by default**, so the load does not run them.
The sample has data for both. To see them fire, turn them on on the
**Detections** page, then remove the sample data and load it again (the load
runs the detections over the whole week; once it is loaded, a detection you
turn on only looks at the last few minutes):

- **change-account-deleted**: the contractor account the domain-persistence
  story deletes.
- **network-remote-admin-port**: the SMB connection the ransomware story makes
  from the workstation to the file server (port 445). It is off by default
  because it needs tuning for your own admin tools.

## How it stays apart from your data

- **Detections.** The load runs the detections over the sample's own events
  only, so nothing real is ever marked as sample. The live detections leave
  the sample's events and risk out, so they raise nothing from them while it
  is loaded, however long it stays.
- **Assets and identities.** The sample's entries live in their own files next
  to your lists (`sample-data-assets.csv` and `sample-data-identities.csv` in
  the lookups folder). Your `assets.csv` and `identities.csv` are never
  rewritten. Where one of your entries and a sample entry share a name, yours
  always wins. The Assets page shows the sample's entries after yours, with
  the business unit `Sample data`; your CSV download and uploads hold only
  your own.
- **Threat intel.** The indicators have the source `Sample data`, which no
  feed can have, so your feeds and the sample never mix.
- **Source health.** The sample stays out of source health on the dashboards,
  because it is loaded and removed all at once and would otherwise show as a
  source that goes stale the moment you remove it.

## How removal works

Removal deletes exactly what has the load's marker, and nothing else:

- the sample **events**, across every data model, and its **risk events**;
- the **findings** the load raised;
- the sample **investigation**. A case of your own that holds a sample
  finding is kept: the sample finding is unlinked from it, and your notes and
  timeline stay;
- the sample **threat intel** (source `Sample data`);
- the sample **asset and identity** entries (its own two files).

Your own events, findings, cases, detections, intel feeds and lists are never
changed, even where they mention a host or user with the same name as a sample
one. If retention has already made a day that holds sample events read-only,
removal lifts that for the delete and puts it back.

The load's ID is kept in a record in OpenSearch (see
[Several servers](#several-servers)). If that record does not say which load it
was (it was damaged, or changed by hand), Signalith cannot tell the sample's
events, findings and investigation from yours, so it deletes none of them. It
removes only the sample threat intel and the sample asset and identity entries,
then clears the record, and the card (or `signalith sample-data remove`) says
so. What an earlier load made stays:

- Its findings and its investigation, *Sample: phishing intrusion on ws-fin-07*,
  stay on the **Findings** and **Cases** pages. Close them there by hand.
- Its events stay until retention deletes them on its usual schedule. Detections
  ignore them, as they ignore all sample events.

You can then load the sample data again. **Remove** later deletes what that new
load adds, but not what the earlier load left.

## Several servers

When several Signalith servers share one OpenSearch (see
[servers.md](servers.md)), they share one set of sample data:

- **Upgrade every server first.** The server that runs the background jobs
  must run a version that knows about sample data: an older one's scheduled
  detections would raise findings from the sample that removal cannot tell
  from yours, and its threat intel downloads would delete the sample's
  indicators. While it runs an older version, a load is refused with a message
  that names it.
- **Load or remove it on any of them.** It is not one of the background jobs,
  so it does not wait for the server that runs those. The detections the load
  runs over the sample's week run on the server you loaded from, and only over
  the sample's own events. The scheduled detections, on the server that runs
  the jobs, leave the sample out as always.
- **Every server shows the same thing.** The record of what is loaded, and of
  a load or removal that is running, is kept in OpenSearch, in the
  `<prefix>_runtime` index where the servers find each other. So the card shows
  the same set on every server, a second load is refused wherever you try it,
  and a load running on one server shows its progress on the others.
- **Threat intel, asset and identity entries follow.** Each server keeps the
  threat intel in memory, and the sample's two lookup files in its own lookups
  folder. The server you load from has them at once. The others read the
  threat intel again, and add the lookup files, as soon as their card shows the
  load (within a minute when nobody has the card open), and take them out the
  same way after a removal, wherever it was made.

If a server stops in the middle of a load or removal without saying so (it
crashed, or lost touch with OpenSearch), the others wait until its record has
not changed for a minute, then treat the job as stopped: the card offers
**Remove what was loaded** or **Finish removing**, on any server. That minute
is timed by each server's own clock from the last change it saw, so a
computer whose clock is wrong cannot make a running job look stopped.

## Notes

- All events fall within the last six days, ending a few minutes before you
  load. The load keeps their own times even if your server's maximum event age
  is shorter. If retention keeps a kind of data for fewer days, it deletes the
  older sample days on its usual schedule; nothing else changes.
- After an upgrade, the findings and investigations indices learn the sample's
  marker field from the server that runs the background jobs. Loading sample
  data adds that one field itself if it is not there yet, so you need not wait
  for that server to get to it. Every server must still run the new version
  (see [Several servers](#several-servers)).
