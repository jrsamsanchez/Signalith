# Servers

Several Signalith servers can share one OpenSearch, for example two servers
behind a load balancer. Each one is a whole Signalith: it serves the web pages,
receives agent and syslog data, and searches. They find each other through
OpenSearch, so there is nothing to connect between them.

One thing they do not all do: the **background jobs**. Exactly one server at a
time runs them. The **Servers** page shows which one.

## The Servers page

Open **Servers** in the navigation, under Health, or press Ctrl+K and type
"servers". The page is for admins. When something stops for everyone, such as no
server running detections or OpenSearch's disk being full, every signed-in person
sees a red banner at the top of every page, and the Health card in the sidebar
turns red.

The line above the list says how many servers there are, which one runs the jobs,
which version they run and how OpenSearch is doing. The page updates itself every
few seconds.

| Column | What it shows |
| --- | --- |
| Server | The server's name (`cluster.node_name`), **This server** on the one you are signed in to, and its address (`server.node_url`) |
| Status | **Running**, **Starting**, **Stopping**, **Stopped** (shut down on purpose), **Not answering** (no sign of life for 30 seconds), **Couldn't start** (a restart after a settings change failed with the new settings and the old ones: it receives nothing, runs no jobs and tries again every 30 seconds; its log says why), **Identity in use** (see [Identity](#identity)), or, on this server only, what keeps it from using OpenSearch, such as **Can't reach OpenSearch** (see [When this server can't use OpenSearch](#when-this-server-cant-use-opensearch)). Below it: how long it has been up, or when it was last seen, counted by the server that answered the page, so neither the other server's clock nor yours matters. A clock more than 2 seconds off is shown here too |
| Background jobs | **Runs jobs** on the server that runs them. **Standby** on a server that would take them over, or why it would not. **Doesn't run them** on a server that may not, with the reason |
| Settings | How it uses the [shared settings](#shared-settings-and-the-cluster-key): **Shared** when it uses the settings every server shares; **Its own files** when it is not part of the cluster (amber when it misses the cluster key, or could not reach OpenSearch when it started); **Saved copy** when it cannot read the shared settings now and works from its copy; **Missed a key change** or **Settings gone** when it needs `signalith cluster` (see [signalith cluster](cluster-cli.md)). Hover over it for what to do. Below it, a shared setting that was changed outside Signalith or by a newer version (the server keeps its last good copy), the settings in its signalith.yaml or environment that differ from the shared ones, how many settings wait for its restart, and how many shared values it could not use |
| Version | The Signalith version it runs |

A server's name opens a panel with its settings: those that wait for its restart, the
shared values it could not use (it keeps its own value of each, see
[Settings on several servers](settings.md#when-a-server-cannot-use-a-shared-value)), how
its last restart went, what differs in its own files, and, for 7 days after the
settings became shared, the values its own Settings page had that differ from the
shared ones. **Open its settings** opens the Settings page at that server.

With one server, the page shows that server and nothing to set up. To add one, see
[Adding a server by hand](#adding-a-server-by-hand). Servers that run a version of
Signalith from before this one are not listed: they do not write a sign of life
(see [Upgrading servers you set up by hand](#upgrading-servers-you-set-up-by-hand)).

A server stopped on purpose stays in the list, after the running ones, as
**Stopped** with when it stopped, and is not counted. It leaves the list 7 days
after it stopped. A server that got a new identity shows up once under its new
identity and once, stopped, under its old one until then.

Alerts above the list appear only when something needs attention: amber when it
should be looked at, red when something is not running. Each one names the server
and says what to do. Problems another server finds with itself, such as a state
folder that was moved from another computer, are shown here too.

While this server cannot use OpenSearch, its status says why, a red alert says what to
do, and the other servers stay as it last saw them.

## When this server can't use OpenSearch

A server that can't use OpenSearch runs no background jobs. On its own Servers page,
its status says why and a red alert says what to do. It tries again by itself every few
seconds, so it never needs a restart once the cause is fixed. The Health page shows the
same for OpenSearch itself.

Some of the steps below send you to OpenSearch's log. With the Docker quick start, show
it from the Signalith folder with
`docker compose -f deploy/docker/docker-compose.yml logs opensearch`. Otherwise it is in
`/var/log/opensearch`, or in the `logs` folder where you unpacked OpenSearch.

| Status | What it means | What to do |
| --- | --- | --- |
| **Can't reach OpenSearch** | Nothing answers at OpenSearch's address: OpenSearch is stopped, the address is wrong, or a firewall is in the way | Check that OpenSearch is running. **Test connection** on the Settings page says what is wrong with the address |
| **OpenSearch didn't answer in time** | OpenSearch took the request but answered too late, usually because its computer is short of memory or CPU | Nothing at first: Signalith keeps trying. If it lasts more than a few minutes, check that OpenSearch's computer has enough memory and CPU, and what OpenSearch's log says |
| **OpenSearch security not loaded** | OpenSearch runs its security plugin, but its security settings (who may sign in, and what each may do) aren't loaded, so it refuses every request. OpenSearch loads them by itself only as it starts with none stored yet, and tries just once, which can fail on a slow computer; they then stay unloaded, also after OpenSearch restarts | If OpenSearch started only a few minutes ago, wait. Otherwise, with the Docker quick start, run `docker compose -f deploy/docker/docker-compose.yml up -d` again from the Signalith folder: it re-runs the step that loads OpenSearch's security settings. If that doesn't load them, follow [If OpenSearch's security settings aren't loaded](opensearch-security.md#if-opensearchs-security-settings-arent-loaded). Without Docker, load them with `securityadmin.sh`, as [Load the security settings](opensearch-security.md#3-load-the-security-settings) shows |
| **OpenSearch too busy** | OpenSearch answered that it could not do the request in time | Nothing at first: Signalith keeps trying. If it lasts more than a few minutes, check that OpenSearch's computer has enough memory and CPU, and what OpenSearch's log says |
| **OpenSearch refuses the sign-in** | OpenSearch does not accept the user name and password, or the client certificate, Signalith signs in with | Check them on the Settings page |
| **OpenSearch refuses Signalith** | Signalith's OpenSearch user may not use `<prefix>_runtime` | Give it the right to create, read and write `<prefix>_runtime` (or `<prefix>_*`) |
| **OpenSearch refuses writes** | A block stops OpenSearch from taking writes. OpenSearch sets one by itself when its disk is full, and an admin can set one, such as `cluster.blocks.read_only` | Give OpenSearch more disk, or remove the block |
| **OpenSearch not ready** | OpenSearch is starting, or its nodes can't find each other | Wait a few minutes. If it lasts, OpenSearch's log says why |
| **OpenSearch answers with an error** | Any other error, such as a closed `<prefix>_runtime` index. The alert quotes it | OpenSearch's log may say more |

## The background jobs

These run on one server only:

- detections on their schedule,
- threat intel feed downloads,
- [notifications](notifications.md#which-server-sends) about new findings,
- [playbooks](playbooks.md#which-server-runs-playbooks) for new findings, and the approved steps,
- data retention, including the disk guard and archiving,
- index upgrades after a new version.

Searching, dashboards, investigations and receiving data work on every server, and
so does loading or removing the [sample data](sample-data.md#several-servers).

**Working on the same finding or case from two servers.** Analysts on different
servers (or in two browser tabs) can comment on, triage and add to the same finding
or investigation at the same moment: each change is saved on top of the others, so
none is lost. In the rare case that many people change one item in the same instant,
one of them sees "Someone else changed this investigation at the same moment. Try
again." Nothing was saved for that person; doing it again works.

**How they move.** The server that runs the jobs confirms every 10 seconds, in
OpenSearch, that it still does. If it stops confirming (it crashed, its computer
stopped, or it lost OpenSearch), another server takes the jobs over within about
40 seconds. When a server is stopped on purpose, it hands them over first, so
another server has them within seconds. Two servers do not run them at once: a
server that cannot confirm for 20 seconds stops its jobs by itself, on a timer of
its own, before anyone else may start them after 30 seconds. Detections, feed
downloads, notifications and playbooks also check, before each run, send or step, that their server still
runs the jobs.

**Detections after a takeover.** The server that takes the jobs over makes up the
detection runs that were missed while no server ran them, oldest first and up to
`detections.catch_up` back (6 hours unless changed). A run the previous server had
already done, or started, does not raise its findings or risk a second time. See
[Schedules and missed runs](detections.md#schedules-and-missed-runs). The run state
is kept in OpenSearch, so every server shows the same Detections page, detection
health and warnings, and **Run now** works on any of them.

**Which servers may run them.** Every server, unless **Run detections on schedule**
(`detections.scheduler`) is turned off on its Settings page; once the servers share
their settings it is called **May run background jobs** (`cluster.leader_eligible`,
or `SIGNALITH_LEADER_ELIGIBLE`), one of each server's own settings. Leave it on: the
servers take turns by themselves. Turn it off only on a server that should never
run the jobs, for example one that only receives data. A change applies at the
server's next restart.

**Changing retention and feeds.** Once the servers are a cluster (see
[Shared feeds and retention policies](#shared-feeds-and-retention-policies)), the Data retention
and Threat intel feed settings can be changed on any server. Notifications and Playbooks settings,
and both on a server that is not part of the cluster yet, can be changed only on the server that
runs the jobs.

## When a server will not take over

Notifications, playbooks and custom detections are still kept in files on each server, and so are
retention policies and threat intel feeds on a server that is not part of the cluster yet (on
the servers of the cluster they are shared, so they never differ). A server whose files differ from those of the server that
runs the jobs does not take the jobs over by itself: it would delete, download or
alert differently. The list shows it as **Standby** with "Won't take over" and the
reason, and an alert says what to copy:

| What differs | What to make the same |
| --- | --- |
| Retention policies | `retention.yaml` in the lookups folder, and `retention` in signalith.yaml |
| Threat intel feeds | `intel_feeds.yaml` in the lookups folder, and `intel` in signalith.yaml |
| Notification channels | `notifications.yaml` in the lookups folder (only once a channel or rule is set up) |
| Playbooks | `playbooks.yaml` in the lookups folder (only once a playbook is set up) |
| Detections folder | The custom detection files in `detections.dir` |
| Archive folder | Only while a retention policy archives: every server must use one shared archive folder. Set `retention.archive_dir` to the same shared folder on each server. Signalith names the folder with a small file in it, `.signalith-archive-id`; leave it there |

Copy the files from the server that runs the jobs, then restart the server you
copied them to. The alert goes away within a minute.

If the server that runs the jobs stops while no other server may take over, a red
alert says that nothing runs detections, threat intel downloads or retention.
Start the server that ran them again, or fix the other server's files and restart
it.

## When OpenSearch's disk is full

When OpenSearch runs out of disk, it refuses new events. The page shows a red
alert, and the server that runs the jobs keeps only the **disk guard** running:
unless it was turned off on the Data retention page, it deletes the oldest days
until there is room. Detections and feed downloads wait. New events are stored
again by themselves once there is room; agents keep theirs until then. To make room
sooner, give OpenSearch more disk.

While the disk is full, servers cannot write their sign of life, so the list keeps
showing them as they were last seen instead of marking them all as not answering.

## Clocks

Detections are scheduled by the clock. The list warns when a server's clock is more
than 2 seconds off OpenSearch's. A server more than 30 seconds off leaves the jobs
to a server whose clock is right while one is up; a server on its own runs them
anyway, with the warning. Keep every server's clock in sync with NTP (Windows Time
on Windows).

## Identity

Each server keeps its identity in its state folder (`node.id`). Never copy a state
folder to another server, for example by cloning a virtual machine. Two servers with
one identity are found out within seconds. The one that started last stops (it
refuses to start), and the one that was running goes on and shows an alert. A
server that finds another one using its identity later shows **Identity in use**,
runs no jobs, and tells load balancers to send it nothing.

To give a server a new identity, stop it, delete `node.id` from its state folder
and start it again. In Docker the state folder is the data volume, and the image
has no shell, so, from the folder you cloned Signalith into:

```
docker compose -f deploy/docker/docker-compose.yml stop signalith
docker run --rm -v docker_signalith-data:/d busybox rm /d/node.id
docker compose -f deploy/docker/docker-compose.yml up -d
```

`docker volume ls` shows the volume's name (here `docker_signalith-data`).

**The state folder.** Signalith keeps the files it makes for itself in one folder:
its master key (`keys`), its HTTPS certificate and certificate authority (`tls`),
`admin-password-hash` when the admin password was changed with `signalith passwd`
(not used while the server shares the users of its cluster), `admin-password-local`
with the break-glass password `signalith passwd -local` sets on a member of a cluster,
the key for the cookie that recognizes browsers that signed in before
(`signin.key`, see [failed sign-in limits](users.md#signing-in)), and this server's
identity (`node.id`, and `cluster/lock` while it runs). The
server and every command (`signalith secrets`, `signalith initial-password`,
`signalith settings` and the others) pick the same folder:

1. `SIGNALITH_STATE_DIR` when it is set. The systemd unit and the Docker image set
   it to `/var/lib/signalith`.
2. Otherwise a local folder Signalith used before instead of the folder that holds
   `lookups.dir` (it notes this in a `used_instead_of` file there). If files turn
   up in the usual folder later, for example from a command run without the
   service's settings, the server stays where it is, and `signalith validate` and
   the log name the files it does not use.
3. Otherwise the folder that holds `lookups.dir`, when it already holds any of those
   files. An upgrade therefore keeps using the folder it used before, wherever that
   is, and leaves nothing behind.
4. Otherwise the folder that holds `lookups.dir`, when it is on a local disk and the
   service's user can write in it.
5. Otherwise a local folder: the systemd `StateDirectory`, then `/var/lib/signalith`
   on Linux, `C:\ProgramData\Signalith` on Windows. A folder that already holds
   another install's identity, certificate or admin password, or that another
   install noted as its own, is skipped, so two installs never share one. The log
   says why, and Signalith keeps using that folder from then on. Signalith makes the
   folder private when it creates it (on Windows only SYSTEM, Administrators, the
   Signalith service and the account that made it can open it).
6. Otherwise the folder that holds `lookups.dir` anyway. The server then does not
   start, and says what is wrong: set `SIGNALITH_STATE_DIR` to a local folder.

Only the server, and `signalith passwd` when it keeps the password there, write the
`used_instead_of` note. Commands that only look (`signalith validate`,
`signalith secrets status` and the others) change nothing. Commands run by hand read
the service's settings (`systemctl show signalith`, including its `StateDirectory`)
so they find the same folder.

The folder should be on a local disk, never on a network share, since the identity's
lock cannot be trusted there. A folder on a network share that already holds a master
key or a certificate is still used, so nothing is lost, and the log warns: move its
files to a local folder and set `SIGNALITH_STATE_DIR` to it. Servers that share
`lookups.dir` on a network share must each set their own `SIGNALITH_STATE_DIR`. On
Docker Desktop and WSL bind mounts, which may not lock files, Signalith starts with a
warning. `signalith validate` says when the folder is not the usual one, and what is wrong
with it, if anything.

## Adding a server by hand

Until servers can be added from the Servers page:

1. Install Signalith on the new computer as usual.
2. Give it the same OpenSearch settings as the first server: `opensearch.url`, its
   user and password, and `opensearch.index_prefix`.
3. Agent tokens made on **Add data** are kept in OpenSearch, so the new server
   accepts them as soon as it starts, and a token revoked on one server is refused by
   all of them within seconds (see [agent-tokens.md](agent-tokens.md)). Shared tokens
   from older setups (`ingest.tokens`) are in each server's own configuration: give the
   new server the same ones, so agents that still use them can send to either server. Each server has its own master key, so passwords and tokens stored
   encrypted (`enc:` values) cannot be copied as they are: set them on the new
   server with `signalith secrets set`, or put them there in plain text and run
   `signalith secrets encrypt` (see [docs/encryption.md](encryption.md)).
4. Give it the cluster key (see
   [Shared settings and the cluster key](#shared-settings-and-the-cluster-key)):
   `signalith cluster export-key` on a server that has it, `signalith cluster
   import-key` on the new one. If the cluster was made with a key file
   (`SIGNALITH_CLUSTER_KEY_FILE`), the same file on the new one does it too.
   It then uses the shared feeds and retention policies, and can take the jobs over.
   Without the key it runs no background jobs. Copy the notification, playbook and
   detection files listed above too. Never copy `node.id`, the `cluster` folder or the `keys` folder. In
   Docker they are in the data volume; copy files into the new server's volume
   rather than copying the whole volume.
5. Set up its users. Each server keeps users in `users.json` in its lookups folder.
   - **Separate lookups folders** (the usual case): add the same users on its
     **Users** page, and set up directory sign-in there again.
   - **One lookups folder shared by the servers**: skip adding users, because they
     already share `users.json`. A user added, changed, disabled or deleted on one
     server is the same on the others within a second or so, and a changed password
     signs that user out on every server. For directory sign-in, put the settings
     under `auth.ldap` in each server's `signalith.yaml` (see
     [Setting it in signalith.yaml](users.md#setting-it-in-signalithyaml)) instead of
     using the Users page: the Users page saves them in `directory.json` in the same
     folder, with the service account password encrypted by that one server's master
     key, so the other servers could not use it.
6. Give it its own name with `cluster.node_name`. In Docker, set
   `SIGNALITH_NODE_NAME` in the compose file (it is `signalith-1` there), and set
   its address with `SIGNALITH_NODE_URL`, since a container cannot know it. Two
   running servers with one name get an amber alert.
7. Give the OpenSearch user the right to create, read and write
   `<prefix>_runtime` (or `<prefix>_*`), where the servers find each other.
8. If OpenSearch has only one node, consider adding a second one too. With one
   node, every server's events, findings and investigations are on that one
   computer. With **Replicas** at `auto` (the default; see
   [Server settings](settings.md#using-the-page)), OpenSearch keeps a copy of each
   new day's events on a second node as soon as there is one, and a copy of
   findings, investigations and threat intel too. Days stored before then keep the
   copies they had. Set Replicas the same on every server: the servers share one
   index template, and the setting of the server that started last is used.

When it starts, it appears on the Servers page of every server.

## Shared settings and the cluster key

The servers that share one OpenSearch also share settings there, in the
`<prefix>_config` index. Each one is signed with the **cluster key**, which every
server keeps in its state folder (`keys/cluster-<id>.key`, encrypted with that
server's master key) and never in OpenSearch, so someone who can write to OpenSearch
cannot change them unnoticed. They share what makes them one cluster (its name, the
list of servers and their keys), the threat intel feeds and the retention policies
(see [Shared feeds and retention policies](#shared-feeds-and-retention-policies)),
the users and sign-in (see [Shared users and sign-in](#shared-users-and-sign-in)), and
the Settings page (see [Settings on several servers](settings.md#settings-on-several-servers)).

The server that runs the background jobs makes the cluster by itself, the first
time it runs this version: it makes the cluster key and writes the shared settings.
Give the OpenSearch user the right to create, read and write `<prefix>_config` too
(or `<prefix>_*`). Every other server then needs the cluster key:

- on a server that has it, run `signalith cluster export-key -o cluster-key.txt`
  and choose a passphrase;
- copy the file to the other server and run `signalith cluster import-key
  cluster-key.txt` there, with that passphrase. It joins within seconds.

Or, **before the cluster is made**, choose the key yourself: 32 random bytes as
one line of base64 (lines starting with `#` are comments), in a file only Signalith
can read, named in `SIGNALITH_CLUSTER_KEY_FILE` on every server. The server that
makes the cluster then uses that key, and every server that has the file joins by
itself. To make such a file:

```bash
openssl rand -base64 32 > cluster-key
```

```powershell
$b = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
[Convert]::ToBase64String($b) | Set-Content -NoNewline cluster-key
```

A key file only joins a cluster made with that very key: no command writes the key
of an existing cluster in plain form, so for a cluster made without a key file use
`export-key` and `import-key`. Until a server has the key, it keeps working from its
own files but runs no background jobs, and the Servers page says so.

Each server keeps its last copy of the shared settings in `cluster/cache.enc` in
its state folder, encrypted with its master key, so it can start while OpenSearch
cannot be reached (it then answers `/readyz` with `degraded` and pauses changes).
`signalith cluster` helps when something went wrong (see
[signalith cluster](cluster-cli.md) for each command and its options):

| Command | What it does |
| --- | --- |
| `signalith cluster status` | This server's place in the cluster, the servers with the key, and any problem |
| `signalith cluster found` | Makes the cluster from this server's files when no server that runs the background jobs is up |
| `signalith cluster export` | Prints the shared settings as YAML; stored passwords stay encrypted. `-settings` writes the settings of all servers as a file `apply` takes |
| `signalith cluster apply -f` | Changes the settings of all servers to those of a file, such as one kept in version control |
| `signalith cluster import -from-cache` | Writes this server's copy back after the `<prefix>_config` index was deleted; the other servers resume by themselves |
| `signalith cluster export-key`, `import-key` | Gives another server the cluster key, encrypted with a passphrase |
| `signalith cluster reset-key` | When every copy of the key is lost: with every server stopped, shows the shared settings, makes a new key and signs them with it. Passwords stored with the old key must be entered again |
| `signalith cluster accept-restore` | After you restore an OpenSearch snapshot on purpose: makes every server accept the older shared settings, which they would otherwise refuse as changed outside Signalith |

Each change is written to the log as an audit record.

## Shared feeds and retention policies

On the servers of the cluster, the threat intel feeds and the retention policies are
shared: a change on any server's Threat intel or Data retention page applies to all of them
at once, and feed passwords and API keys are stored encrypted with the cluster key. The
server that founds the cluster brings its own: the feeds from `intel_feeds.yaml` and
`intel.feeds` in signalith.yaml, their download status, and the retention policies from
`retention.yaml` and `retention` in signalith.yaml. The other servers' own files are no
longer used for them. A server switches to the shared ones by itself, with a quick restart
in place, when it founds or joins the cluster. While the founder is still moving its files
into OpenSearch, the other servers keep using their own and the Servers page says they wait
for it; if that takes more than 30 minutes, it turns red: the founder finishes only while
it runs the background jobs.

**When the servers' policies differed.** If another server that ran in the last 7 days had
retention policies of its own that differ from the founder's, the shared policies wait to be
confirmed: until an admin confirms them on the Data retention page (or with
`POST /api/retention/policies/confirm`), retention runs only the disk guard and freezes,
archives and deletes nothing else.

**signalith.yaml.** `retention.days`, `retention.default`, `retention.policies`,
`retention.guard` and the feeds in `intel.feeds` still work, but only when they change: a
server that starts with a changed value applies it to the shared one, and the log says so
("retention.days applied from signalith.yaml on siem-b"). An unchanged file never undoes a
change made on a page, and removing a setting from the file changes nothing. A value that
differs from the shared one without having changed is only noted, for information, in that
server's heartbeat (`settings_drift`).

**Downloads and runs.** The server that runs the background jobs downloads the feeds and runs
retention. **Refresh** on a feed, and **Run now** or a policy change on the Data retention
page, on another server ask it to: the request answers `202` with a `request_id`, which
`GET /api/requests/{id}` follows until it is `done` or `failed`. Restoring archived days is
done on the server that runs the jobs; once the cluster keeps audit records, a restore asked
on another server is sent there the same way (see below).

**Changes at the same moment.** `GET /api/retention` and `GET /api/intel/feeds` (for
admins) give each item's version (`ETag`, and `etags` for the feeds). A change sent with
`If-Match` and that version is refused with `412` when someone changed the item meanwhile.
While a server cannot use the shared settings (OpenSearch cannot be reached, or it misses
the cluster key), changes there answer `503`.

## Audit and archives across servers

Once every server of the cluster runs this version, the cluster keeps its audit
records and its archive list in OpenSearch, and `signalith cluster status` shows the cluster at
level 4. The server that runs the background jobs first moves its retention history and
its archive manifests into OpenSearch; the other servers keep their own until it is done.

- **Audit records.** Each server writes its audit log lines (sign-ins, changes to users,
  settings and retention) to monthly indices, `<prefix>_audit-YYYY.MM`, as well as
  to its log. Lines wait in a small spool on disk (`audit-spool` in the state folder, at
  most 50 MB) while OpenSearch is away, so none are lost. Search them on the
  [Audit](audit.md) page. They are kept 400 days by default, by the **Audit records**
  policy on the Data retention page.
- **One retention history.** Retention runs and actions are audit records too, so every
  server shows the same history, with the server that took each action, and it survives
  a takeover.
- **One archive list.** Every server lists the same archives. An archive is listed before
  its file is written and marked complete once the file is checked; an archive left
  unfinished for 6 hours (its server stopped while writing it) is removed with its file.
- **No step taken twice.** Before deleting, archiving, compacting or restoring a day, the
  server that runs retention claims that step in OpenSearch. A server that lost the jobs
  partway through a run cannot repeat a step its successor already took.
- **Restores from any server.** **Restore** on the Data retention page of any server, and
  `signalith archive restore`, ask the server that runs retention to restore, and show its
  progress.

Set `retention.archive_dir` to the same shared folder on every server that may run the
jobs. The Data retention page lists which servers can archive. When the server that runs
retention cannot, it keeps the days it would archive rather than deleting them.

## Shared users and sign-in

Once every server runs this version, the servers also share their users, the built-in
admin's password, the directory sign-in settings and the sign-in sessions, in
OpenSearch (`<prefix>_config` and `<prefix>_sessions`; give the OpenSearch user the
right to create, read and write those too). A user added or changed on any server's
Users page is the same everywhere within a couple of seconds, and a session made on
one server works on every server: a load balancer needs no sticky sessions, and when a
server stops, the people it served carry on on the others without signing in again.
`signalith passwd` on any server changes the built-in admin's password for all of
them, with no restart. See [Users on several servers](users.md#users-on-several-servers)
for how the users are brought in, the built-in admin, directory settings and
failed sign-in limits across servers, and what works while OpenSearch cannot be used.

While some servers still run an earlier version, each server keeps its own users and
sessions as before, and the Servers page and the Users page name the servers to
upgrade.

## Field names when several servers receive events

Each day's events go to one index per data model, and OpenSearch allows at most 2,000
fields in one index. Signalith's own fields always fit; the names senders choose (JSON
keys, syslog structured data, CEF extensions) share what is left (see
[Ingest limits](sending-data.md#ingest-limits)). With several servers:

- The budget of new names per daily index (1,000, and 600 for syslog vendor fields) is
  shared out equally among the servers that stored events in the last 10 minutes, with
  at least 100 for each. Each server's heartbeat says when it last stored an event, so
  the shares follow servers as they start and stop.
- Before adding new names to an index, a server also looks at how many fields the index
  really has (checked at most every 30 seconds) and adds none once it has 1,600.

Fields over the limit are not lost: their values stay in the event's raw message
(`_raw`), and the event says how many were left out in `dropped_fields`. Fields
Signalith produces itself are always kept.

## Agents across servers

The [Endpoints page](endpoints.md#log-agents) lists every log agent once, whichever
servers it sends to: each server notes the agents it hears from and saves that in
OpenSearch once a minute. Agents that need a new configuration, for example because they
trust a certificate authority the servers no longer use, are marked there.

## Upgrading servers you set up by hand

Versions before this one do not take turns: each server with **Run detections on
schedule** on runs the jobs itself, so two of them run detections, threat intel
downloads and retention twice. They also do not appear on the Servers page.

The Servers page says this too, until an admin dismisses the note. When you
upgrade servers that share one OpenSearch, either:

- upgrade them all at the same time, or
- first turn off **Run detections on schedule** (`detections.scheduler: false`) on
  every server except one, upgrade them one by one, and turn it back on once all of
  them run this version.

While servers of different versions share one OpenSearch, the newest one decides
how new days' events are stored (the index template): a server of this version or
later leaves a newer server's template as it is. A server from before this version
does not know to do that and puts its older template back when it starts; the next
start of a newer server puts the newer one back. Upgrade all servers to finish
this.

**The cluster key.** The first server of this version to run the jobs founds the
cluster and makes the cluster key (see
[Shared settings and the cluster key](#shared-settings-and-the-cluster-key)). Every
other server needs that key, with `signalith cluster import-key` or
`SIGNALITH_CLUSTER_KEY_FILE`: until it has it, it keeps using its own files and
never takes the jobs over, so if the server that runs them stops, nothing runs them.
Setting `SIGNALITH_CLUSTER_KEY_FILE` to one key file on every server before the
upgrade avoids this step: the first server then makes the cluster with that key (see
[Shared settings and the cluster key](#shared-settings-and-the-cluster-key) for how to
make the file). Upgrade
every server, not only some: a server of an older version reads and writes its own
files and does not see changes made on the pages of the others.

The first server of this version to run the jobs runs each detection that is on once
straight away, over its lookback, so the time since the old version's last run is
searched. Findings and risk events the old version raised keep holding back repeats
for each detection's throttle window. See
[Schedules and missed runs](detections.md#schedules-and-missed-runs).

**Users and sign-in.** The servers start sharing their users once every server that
ran in the last 24 hours runs this version (see
[When the users become shared](users.md#when-the-users-become-shared)). Until then
nothing changes for users; the Servers page names the servers still to upgrade. When
the users become shared, each server restarts in place by itself and **everyone signs
in once more**, on a single server too. From then on:

- The directory sign-in settings can be changed on the Users page even when they come
  from `auth.ldap` in signalith.yaml; the file applies again only when it changes.
- `signalith passwd` changes the built-in admin's password for every server, with no
  restart. `signalith passwd -local` is the break-glass password of one server, used
  only while OpenSearch cannot be used.
- A server of an earlier version can no longer start on this OpenSearch.

**Settings.** The servers start sharing their Settings page in the same way, once every
server that ran in the last 24 hours runs this version: the founder brings in its
settings, then each server restarts in place by itself and brings in its own, and
nobody needs to sign in again. Settings for all servers then have one value on every
server, each server's own settings can be changed on any server's page, and
`settings.yaml` keeps only each server's connection and folder settings. See
[When the settings become shared](settings.md#when-the-settings-become-shared) for what
changes, and how a value one server's page had is shown for a week.

## Load balancers: /readyz and /livez

Every server answers two addresses without signing in. They say nothing else about
the server.

| Address | Answer | Use it for |
| --- | --- | --- |
| `GET /readyz` | `200 {"ready":true}` when the server should get traffic; `503 {"ready":false,"reason":"…"}` when it should not | Load balancer health checks, Kubernetes readiness probes |
| `GET /livez` | `200 {"live":true}` while the process runs | Restarting a process that hangs, Kubernetes liveness probes |

The reasons `/readyz` gives:

| Reason | Meaning |
| --- | --- |
| `starting` | The server has not finished starting |
| `restarting` | It is applying changed settings; it answers again in a few seconds |
| `down` | It could not start, and tries again every 30 seconds; its log says why |
| `opensearch` | It cannot reach OpenSearch, or OpenSearch refuses its sign of life (the Servers page and the log say why) |
| `identity` | Another server uses its identity (see [Identity](#identity)) |
| `degraded` | It is part of the cluster but cannot use the shared settings in OpenSearch now (see [Shared settings and the cluster key](#shared-settings-and-the-cluster-key)) |
| `gone` | The shared settings in OpenSearch are gone: their index was deleted or replaced |
| `key_missing` | The shared settings are signed with a cluster key this server does not have |
| `stopping` | It is shutting down and handing its jobs over. This takes up to a minute while jobs finish: the systemd unit allows 100 seconds, the compose file 90, and the Windows service waits 90 |

Do not use `/readyz` to restart a server: a server that waits for OpenSearch is
fine, and restarting it does not help. Use `/livez` for that.

HAProxy, for example (with source address affinity, which only servers that do not
share their users yet need; see below):

```
backend signalith
    balance source
    option httpchk GET /readyz
    http-check expect status 200
    server siem-a 10.0.0.11:8080 check
    server siem-b 10.0.0.12:8080 check
```

Both addresses answer over HTTPS and also over plain `http://` on the same port
(everything else on plain HTTP is sent to HTTPS), so the plain `check` above works
while Signalith serves HTTPS, which it does by default. To check over HTTPS instead,
add `check-ssl` and the certificate authority to check it with (`ca-file`, the
server's `tls/ca.pem`; see [docs/https.md](https.md)) to each `server` line. A
Kubernetes container:

```yaml
readinessProbe:
  httpGet: { path: /readyz, port: 8080, scheme: HTTPS }
livenessProbe:
  httpGet: { path: /livez, port: 8080, scheme: HTTPS }
```

Kubernetes does not check the certificate of a probe, and without `scheme: HTTPS`
the probe uses plain HTTP, which works too.

**Each server has its own HTTPS certificate.** With `server.tls.mode: auto`, each
server makes its own certificate authority, so browsers and agents that reach
several servers through one name must trust each server's `ca.pem`. To have one
certificate for all of them, give every server the same certificate with
`server.tls.mode: files` (see [docs/https.md](https.md)), or let the load balancer
add HTTPS and pass the connection on to Signalith.

**No sticky sessions needed.** Once the servers share their users (see
[Shared users and sign-in](#shared-users-and-sign-in)), a sign-in made on one server
works on every server, so the load balancer may send each request anywhere, and a
server that stops loses nobody's session. Until then, while some servers still run an
earlier version, a sign-in is kept by the server it was made on: set the load balancer
to send each person to the same server (sticky sessions, or source address affinity),
and people sign in again on another server when theirs stops. Agents and syslog need
no such setting: any server takes any agent's data.

**Sign in once per address.** The session cookie is a `__Host-` cookie, which a
browser keeps for exactly the address it used. Through one load balancer address,
people sign in once; opening `siem-a.example.com` and `siem-b.example.com` directly
takes a sign-in on each.

## Several servers behind one address

The shared settings are read by every server from OpenSearch, and a change made on one
server reaches the others within a second or so. So that a page never shows the
settings as they were before a change you just made, even when the load balancer sends
the next request to another server, Signalith uses a few headers. Load balancers and
proxies must pass them on unchanged; they need no other setting.

| Header | Sent by | Meaning |
| --- | --- | --- |
| `X-Signalith-Version` | Every answer | The Signalith version of the server that answered |
| `X-Signalith-Config` | Every answer to a signed-in request, and to a successful sign-in, once the server has read the shared settings | How far it has read them, as `<id>.<number>`. The answer to a change says how far a server must have read them to see that change |
| `X-Signalith-Config-Min` | The web pages, on each request to `/api/` | The highest `X-Signalith-Config` the page has seen. A server that has not read that far reads the shared settings once before it answers |
| `X-Signalith-Stale` | A server that is still behind after that | `1`. The page asks again once for a read; a change is checked against OpenSearch anyway, so it is never made on old settings |

Scripts that use the API can do the same: send the `X-Signalith-Config` of the answer
to a change as `X-Signalith-Config-Min` on the next request. Only signed-in requests
wait.

**Upgrading behind a load balancer.** While servers of two versions share one
address, a page from one version can ask a server of the other for its scripts. The
pages therefore load their scripts and stylesheets from paths that name the version,
`/v/<version>/…`, which only a server of that version serves, and which browsers may
keep for a year. If one does not load, the page reloads itself, a few times with
growing pauses, until it gets a server of the version it came from or a page of the
new one; after 5 tries it says that Signalith is being upgraded. A page that sees
another version in `X-Signalith-Version` reloads once to get that version's pages;
if a server of the other version answers again within 2 minutes, the page says that
Signalith is being upgraded instead of reloading again. The plain
paths (`/app.js` and so on) keep working, for pages of earlier versions.
