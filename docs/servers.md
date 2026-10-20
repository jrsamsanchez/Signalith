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

## OpenSearch with several nodes

With one OpenSearch node, losing it stops every server. Run three nodes, give each
server their addresses (**More addresses** on the Settings page, `opensearch.urls`), and
keep Replicas at `auto`: Signalith then spreads its requests over the nodes and skips one
that is down. The Servers page has an OpenSearch card that shows the nodes, their disks,
indices without a copy on another node, and which of this server's addresses are being
skipped. [OpenSearch with several nodes](opensearch-failover.md) explains the setup,
per-node certificates and snapshots.

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
server's next restart. A server added as a **scanner** (its **Server role**,
`cluster.role: scanner`) never runs them, whatever this setting says; see
[Cluster servers and scanners](multi-server.md#cluster-servers-and-scanners).

**Spreading detections over the servers.** With many rules, one server can be too
few to run them all. So with two or more servers that may run the jobs, each runs
a share of each tenant's rules: the rules are split into 64 groups, and the server
running the jobs gives each group to one server, moving as few as it can when a
server joins or leaves. A server that stops has its groups moved to the others,
even when only one is left. This is **Spread detections over servers**
(`detections.spread`, on the Settings page under Detections), on unless you turn
it off; turned off, the server running the jobs runs every rule. It applies within
seconds, and only once every running server is on a version that supports it and
the cluster's features are up to date; until then, one server runs every rule as
before. A server
does not get a share while its detection or lookup files differ from those of the
server running the jobs, while its clock is more than 2 seconds off OpenSearch's,
or while it cannot write its heartbeat for 20 seconds (it then stops its share by
itself). While they are spread, the Servers page says under **Background jobs** how many of the
groups each server runs, and how many it is handing over to another.

Spread or not, the Servers page also shows, under **Background jobs**, how each server keeps up
with the rules it ran last in the past day: how many rules, how long their last runs took (the
median and the 95th percentile), how long after its time slot ended each run started, how many
rules started more than one schedule interval late in the last hour, how many slots were skipped
for being older than the catch-up limit (`detections.catch_up`), and how many runs timed out. A
server is **falling behind** when slots were skipped in the last hour, or when at least 3 of its
rules, and at least 5% of them, started late in the last hour. The page then shows a warning:
look at the slowest rules on the Detections page, or spread detections over more servers.

When a group moves, its new server takes over from where the last run of each rule
ended, so no time is skipped or searched twice. A server that is still running hands
its groups over first: it starts no new run of them, finishes the runs it has going,
and says so in its heartbeat, and only then does the new server start them (or after
6 minutes, longer than any run may take, if it never says so). A server that stopped
or lost contact gives its groups up at once. A server that just started gets groups
only once it has been running for a minute, so one that restarts quickly does not
move them back and forth. Each group also carries a number that grows with every
move, and OpenSearch refuses run state written under an older one, so two servers
never both record a run of the same rule.

Every server's detection searches go to the same OpenSearch, so adding servers adds
room to run rules, not room to search. While detections are spread, all servers
together run at most **Detection searches at once** (`detections.search_budget`)
searches; each server runs the share that matches its groups, at least one, for all
tenants together, taking turns between tenants so a busy one cannot hold more than
half of a server's searches while another waits. Left empty, it is half the
searches OpenSearch's data nodes can run at once. When a tenant's searches are
refused as too busy, do not answer in time, or take twice as long as over the 15
minutes before, that tenant alone runs fewer at once for a while, so one tenant's
heavy rules do not slow the others. When most of the tenants a server runs (at
least two) show it within two minutes, or it runs a single tenant, OpenSearch is
taken to be slow for everyone: the server halves how many it runs and gets one back a minute; the
current runs go first, and missed runs are made up one at a time until it is back
to its share.

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

To give a server a new identity, stop it and run `signalith cluster new-identity` on
it (see [docs/cluster-cli.md](cluster-cli.md#new-identity)). It moves `node.id` aside,
deletes the node key and the copy of the cluster key, and the server makes a new
identity when it starts. Give it the cluster key again to add it to the cluster. In
Docker, from the folder you cloned Signalith into:

```
docker compose -f deploy/docker/docker-compose.yml stop signalith
docker compose -f deploy/docker/docker-compose.yml run --rm signalith signalith cluster new-identity
docker compose -f deploy/docker/docker-compose.yml up -d
```

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

The easiest way: **Add a server** on the Servers page checks OpenSearch is ready and
gives you one line to run on the new computer (see [Adding servers](multi-server.md)).

From the command line, with OpenSearch secured (https and a sign-in), a new server can join with one
command instead of the steps below: make a join token on a member with
`signalith cluster token`, then, on the new computer with Signalith installed, run
`sudo signalith join` and paste the token (see [join](cluster-cli.md#join)). It checks the
member by the certificate the token names, receives the cluster key and the
OpenSearch settings encrypted for it alone, checks it can use OpenSearch from there,
and starts. Or start the new server with the same OpenSearch settings and no key: it
waits with a fingerprint on its sign-in page, and `signalith cluster approve` on a
member gives it the key once the fingerprints match (see
[approve](cluster-cli.md#approve)). Users, settings and detections then come from
the cluster. A server that served alone with users, feeds and retention policies of
its own can add those the cluster lacks with `signalith join --merge`; what differs is
kept in its migration report for you to decide.

By hand:

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
   copies they had. Set Replicas, and Shards, the same on every server: the servers
   share one index template, and the setting of the server that started last is used.

When it starts, it appears on the Servers page of every server.

## Draining and removing a server

Each server's side panel on the Servers page (click its name) has a **Maintenance**
part:

- **Drain** prepares a server for maintenance. It tells load balancers it doesn't want
  traffic (`/readyz` answers 503 with `draining`), hands the background jobs to another
  server and doesn't take them back. It shows as **Draining**, and stays drained across
  restarts until you click **Resume**. Stop it once it shows Draining.
- **Run the background jobs here** moves the background jobs to that server. The server
  that runs them now finishes the work in progress and lets go, and the other servers
  wait a few seconds so the one you chose takes them. It needs a server that is running
  normally and allowed to run the jobs.
- **Remove from the cluster** takes a server out for good: off the list of servers and
  out of the keyring, so it gets no new cluster key. Drain it or stop it first; a
  server that just went offline can be removed after 10 minutes. A server cannot
  remove itself from its own page: use another server's page, or run
  `signalith cluster leave` on it while it is stopped.

Removing a server rotates the cluster key unless you untick **Rotate the cluster key
(recommended)**. The removed server keeps its copy of the old key, and only a rotation
makes that copy useless. A removed server that starts again with its old copy shows
that it was removed and runs no background jobs. To bring it back, give it the cluster
key again with `signalith cluster import-key`.

**Rotating the cluster key.** The **Cluster key** card under the list of servers shows
the key in use and the servers removed, with **Rotate cluster key**. Rotate it after
removing a server, or when a copy of the key may have leaked (an exported key file, a
backup of a state folder). The server that runs the background jobs does it in steps:

1. It makes a new key and gives every server in the keyring a copy, sealed so only
   that server can open it.
2. Once every running server has its copy, every server starts signing with the new key.
3. The passwords and tokens kept in the shared settings, the certificate authority's
   key and the sign-in sessions are sealed and signed again with the new key.
4. The old key is retired. Nobody is signed out: browsers signed in before keep their
   sessions.

A second rotation within 7 days of the last one signs out the browsers that signed in
before the first, and a server offline through both needs the key again.

A server offline for more than 10 minutes isn't waited for. When it comes back within
7 days, it picks up its copy by itself; later than that, give it the key again with
`export-key` and `import-key`. If a step fails, for example because a server doesn't
pick up the key within 10 minutes, the rotation stops where it is, both keys keep
working, and **Finish the rotation** (or `signalith cluster rotate-key`) goes on from
there. The key file of an old key stays in each server's state folder, so archives
sealed with it still open. Rotating needs every server on a version that supports it.

Once a server sees a rotation finish, it marks each key the keyring no longer lists as
retired, in `cluster/retired-<key id>` in its state folder, and never joins a cluster
whose cluster document is signed with a retired key. So a copy of the old key can't
take a server back to it, even after a restart. The same goes for the keys of any
other cluster the server once belonged to. To move a server back to such a cluster,
delete its `retired-<key id>` file first.

The same from the command line: `signalith cluster rotate-key`, `signalith cluster
remove <server>` and `signalith cluster leave` (see
[docs/cluster-cli.md](cluster-cli.md#rotate-key)). Admins can use the API too: see the
cluster routes in [docs/users.md](users.md#roles-of-every-route).

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

## One certificate authority

Every server that serves HTTPS with its own certificate (**HTTPS** set to Automatic)
gets it from a certificate authority (CA), which agents, syslog devices and browsers
trust (see [https.md](https.md#trust-the-certificate)). On a server of its own that CA
is in `tls/ca.pem` and `tls/ca.key` in its state folder. Once every server of the
cluster runs a version that shares one, the servers share **one** CA, so one CA
file works for every server, and an agent set up for one server also sends to the
others.

**What is shared.** The CA's certificate and its key are kept in the `tls` document of
the shared settings, signed like the rest, with the key encrypted with the cluster key.
The key cannot be read from OpenSearch without the cluster key, and it cannot be moved
under another certificate. Each server still issues and renews its own certificate from
it, for its own names, its node address, and the names any server added (an address an
agent was set up with on Add data, up to 32), so no server has to be up for another to
renew. No server keeps `ca.key` on disk any more: it is deleted once the shared copy has
been read back from OpenSearch and the server's copy of the shared settings
(`cluster/cache.enc`) was written. While OpenSearch can't be reached, servers renew
from that copy. A server that has neither keeps serving the certificate it has (or, if
that is gone or expired, a stand-in that agents and browsers refuse, until it can reach
the shared CA) and never makes a new CA.

**A cluster that grew from one server.** The server that makes the cluster shares its
own CA when no other server seen in the last day uses another one of Signalith's own
(a server with your own certificate files doesn't count: it keeps them whatever the
cluster uses). If the servers' heartbeats can't be read at that moment, it shares
nothing and tries again. Nothing changes for
agents and browsers: same fingerprint, same CA file. A server that joins later takes the
shared CA within seconds, issues itself a new certificate from it, and retires its own
CA (below).

**Servers set up separately.** When servers that each made their own CA meet, nothing is
shared until an admin chooses which CA to keep, and each server keeps its own meanwhile.
The **Certificate authority** card on the Servers page lists the CAs in use, one per
server that holds it:

- how many agents trust each one (from the agents' configurations, or, for older agents
  that don't say, the servers they reached over HTTPS in the last week), and which agents
  would need a new configuration if it is kept (agents that only reach servers with your
  own certificate files are never among them);
- the servers whose names it may not vouch for: a standard CA vouches only for private
  names and its own server's names, and a strict one only for its server's
  ([How far the certificate authority reaches](https.md#how-far-the-certificate-authority-reaches)).
  Those servers' certificates would leave such names out, and the Servers page shows
  that in red;
- a suggestion: the one most agents use, then the one of the server that made the
  cluster, then the oldest.

**Keep this one** asks the server that holds it to share it (`signalith cluster tls
choose` does the same from a command line; see [cluster-cli.md](cluster-cli.md#tls)).
Only that server can, only while it runs (a CA whose servers are all offline is marked
so, and can't be kept until one is started), and only while its CA is still the one you
chose. The request is signed with the cluster key, so only a server of the cluster can
ask for it. Once one is shared, choosing another is refused: changing the cluster's CA
comes in a later version.

**Retired CAs.** A server that takes the cluster's CA keeps a copy of its old `ca.pem`
in `tls/retired/<date>-<fingerprint>/` and deletes its old `ca.key`, so the old CA never
signs again. The cluster also lists it, so every server knows it. An agent whose
configuration trusts only a retired CA is marked **Needs a new configuration** on the
[Endpoints page](endpoints.md#log-agents): give it a new configuration from Add data,
which trusts the cluster's CA. An agent whose configuration trusts both is fine.

**What stays per server.**

- A server with your own certificate files (**HTTPS** set to Your own certificate) never
  shares its CA and never takes the cluster's. The Servers page warns when its CA differs
  from the others, since agents set up for the other servers refuse it.
- The Servers page also warns about a server whose certificate doesn't cover the
  cluster's shared address (`server.public_url`), which agents sent there by a load
  balancer would refuse.
- A server in the middle of a change of its own CA (the Security page's steps) takes the
  cluster's only once that change is finished or cancelled; until then the Servers page
  says why it keeps its own. Once a server uses the cluster's CA, the Security page shows
  **Cluster certificate authority** instead of those steps.
- Syslog over TLS uses the same certificate, so devices trust the same CA.

From a script, as an admin: `GET /api/cluster/tls` answers what the card shows (`on`
and `off` say whether the cluster shares a CA yet, then `ca`, `retired`, `servers` with
each one's `warnings`, and, while none is chosen, `candidates` with their agents, at most
200 listed with whole counts in `agent_count` and `break_count`).
`POST /api/cluster/tls/choose` with `{"ca_sha256": "<fingerprint>"}` asks the server
holding that CA to share it and answers `202` with a `request_id` that
`GET /api/requests/{id}` follows; `409` when the cluster already shares one, `400` when
no server seen in the last day uses that CA, `503` when the shared settings can't be
changed now or no server holding that CA runs (each candidate's `up` says). Each choice is written to the audit log.

## Each server's own OpenSearch certificate

When Signalith made OpenSearch's certificates (the Docker quick start, or `signalith
opensearch-certs`), every server first signs in to OpenSearch with the same client
certificate, `CN=signalith`. Hand OpenSearch's certificate authority to the cluster once,
and each server signs in with a certificate of its own instead,
`CN=signalith-server-<name>`, which `roles_mapping.yml` gives the same `signalith_server`
role:

- **Docker:** `docker compose -f deploy/docker/docker-compose.yml run --rm setup bootstrap-docker -export-ca-key`
  (see [Handing the CA key to Signalith](opensearch-security.md#handing-the-ca-key-to-signalith)).
- **Without Docker:** `signalith cluster opensearch-ca import /path/to/ca/root-ca-key.pem`
  on any server, with the `ca` folder `signalith opensearch-certs` wrote. Keep that folder
  offline afterwards.

Signalith checks that the CA is the one in `opensearch.ca_file`, keeps it in the shared
settings with its key encrypted with the cluster key, and deletes the handed-over key
file. Then each server that signs in with a certificate from that CA:

1. makes a new key, which never leaves it, and issues itself a certificate that lasts 90
   days;
2. checks that OpenSearch lets the new certificate in with the `signalith_server` role;
3. only then uses it, without a restart. It is kept in the `opensearch` folder of its
   state folder, and used in place of `opensearch.cert_file` while it is valid.

Each server renews its own certificate 30 days before it expires. A server that no
longer has the cluster key can't renew, so its access to OpenSearch ends when its
certificate expires, or at once with a revocation list (below). A server that signs in with a user name and password, or with a
certificate from another CA, is left as it is.

If OpenSearch's security settings predate `signalith-server-*` in `roles_mapping.yml`,
step 2 fails and the server keeps the shared certificate. Load them again with
`bootstrap-docker -apply-security` and `up -d` (see
[Loading changed security settings](opensearch-security.md#loading-changed-security-settings));
it tries again every 10 minutes.

The **OpenSearch sign-in** card on the Servers page shows who each server signs in as.
Once none uses `CN=signalith`, it suggests removing `"signalith"` from the
`signalith_server` users in `roles_mapping.yml` (in Docker,
`deploy/docker/opensearch/security/roles_mapping.yml`), then loading the security
settings again, so the shared certificate opens nothing any more.

Anyone who holds the cluster key can open this CA and so sign any certificate OpenSearch
trusts, the admin one included. Signalith only ever signs `signalith-server-<name>`
certificates, but keep the cluster key as safe as OpenSearch's admin certificate.

`signalith cluster opensearch-ca` prints the CA and each server's sign-in (see
[cluster-cli.md](cluster-cli.md#opensearch-ca)). From a script, as an admin:
`GET /api/cluster/opensearch-identity` answers what the card shows: `ca` (the
fingerprint, who handed it over and when, and how many certificates are `revoked`;
`null` when the cluster keeps none) and `servers`, each with its `identity` (`cn` or
`user`, `not_after`, `managed`, `shared`, `problem` and `crl`).

### Ending a server's OpenSearch access at once

A certificate stays valid until it expires, up to 90 days. To end a server's access
sooner, Signalith revokes its certificates: removing a server does so, and so does
`signalith cluster opensearch-ca revoke <server>`. The cluster then issues that server
no certificate again unless it joins anew.

OpenSearch only hears of it through a revocation list it checks every client certificate
against, which it reads again on every connection, so a revocation takes effect at once,
without a restart. Each server with `opensearch.crl_file` (or
`SIGNALITH_OPENSEARCH_CRL_FILE`) set writes that list whenever the revoked certificates
change. It is signed with OpenSearch's CA and valid until the CA expires.

- **Docker:** set up already. The `setup` service makes an empty list in the
  `opensearch-crl` volume, OpenSearch checks it once it is there, and Signalith keeps it.
  From then on OpenSearch does not start without the list: if it is deleted, OpenSearch
  waits, restarting, until Signalith or `docker compose ... up -d` writes it again.
  OpenSearch warns at start that the list can be read by others: it holds no secret, and
  Signalith writes it while OpenSearch reads it.
- **Without Docker:** on each OpenSearch node, put the list where OpenSearch can read it
  (`signalith cluster opensearch-ca crl -o crl.pem` writes it) and add to
  `opensearch.yml`:

  ```yaml
  plugins.security.ssl.http.crl.validate: true
  plugins.security.ssl.http.crl.file_path: crl.pem   # relative to OpenSearch's config folder
  plugins.security.ssl.http.crl.disable_ocsp: true
  plugins.security.ssl.http.crl.disable_crldp: true
  plugins.security.ssl.http.crl.prefer_crlfile_over_ocsp: true
  ```

  Then restart the node. When a Signalith server runs on the same computer, set its
  `opensearch.crl_file` to that file (Signalith needs to be able to write it) and it
  keeps it; otherwise copy the list again after each revocation.

**OpenSearch refuses every client certificate, the admin's included, while the list it
checks is missing, unreadable or expired.** Signalith writes it again within a minute
when it can, and says so loudly when it can't: a red banner on every page, the
**OpenSearch sign-in** card on the Servers page, and the
[OpenSearch's revocation list](security.md#opensearchs-revocation-list) check on the
Security page. In Docker, `docker compose -f deploy/docker/docker-compose.yml up -d`
makes it again too.

**A revocation ends the access of a server that follows the cluster, not of its disk.**
A removed server's state folder still holds the cluster key and its copy of the shared
settings (`cluster/cache.enc`), and together they open OpenSearch's CA key: whoever has
that disk can still sign new certificates OpenSearch trusts. For a server that was
compromised or stolen, also make a new OpenSearch CA. In Docker, run
`bootstrap-docker -new-ca`, then `bootstrap-docker -export-ca-key` again, so the cluster
keeps the new CA in place of the old (see
[Replacing the CA](opensearch-security.md#replacing-the-ca)); without Docker, make
OpenSearch's certificates again under a new CA. A revocation does not touch the shared
`CN=signalith` certificate or a user name and password either: whoever holds those keeps
OpenSearch access until `roles_mapping.yml` no longer gives them the `signalith_server`
role (see [Each server's own OpenSearch certificate](#each-servers-own-opensearch-certificate)),
or the password is changed.

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
it runs the background jobs. Between moving a page's files and the restart that switches
to the shared ones (usually a few seconds), a server refuses changes on its Threat intel,
Data retention and Users pages with "This server is moving its … into the cluster; try
again in a moment" (`503` with `Retry-After` from the API), so a change is never saved to
a file that is no longer read; saved again, it goes to the shared settings.

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

## Shared detections, dashboards and asset lists

Once every server runs this version, the servers also share their custom detections, the
choices made for built-in and content pack detections (on or off, and their
[exceptions](detections.md#exceptions)), and their custom dashboards. A detection saved
on any server runs on the server that runs the background jobs at its next scheduled run,
and a dashboard saved anywhere is the same everywhere within a couple of seconds.

The server that founds the cluster brings its own: the files in its detections folder
(and its `state` folder) and its dashboards folder. From then on, each server's folders
are an **inbox**:

- A file added or changed in a folder, by hand or by a `git pull`, is shared with every
  server within 15 seconds. A file that is not valid is logged and left out until it is
  fixed.
- A change made on any server is written back into every server's folders, so the
  folders keep showing what runs and can still be backed up or kept in Git.
- The files a server has when it joins are only its starting point: a stale copy left
  on one server never undoes a change made on another. To share one of them, change or
  save it again.
- Removing a file changes nothing by default; the shared copy is written back. Set
  **Detection and dashboard folders** (`detections.sync`) to **Mirror** on a server to
  have a file removed from its folders remove that detection or dashboard from every
  server.

Each server records what it last saw of its files in `library-seen.json` in its state
folder. Content pack updates stay per server (`detections.content_updates`), so give
every server the same content update setting.

**Changes at the same moment.** `GET /api/detections` and `GET /api/dashboards` give
each item's version (`etag`). A change sent with `If-Match` and that version is refused
with `412` when someone changed the item meanwhile, naming who did it, on which server
and when; the Detections and Dashboards pages then offer to reload or overwrite.
Changes sent without `If-Match`, such as from scripts, apply to the latest version.
While a server cannot use the shared settings, changes there answer `503`.

While some servers still run an earlier version, each server keeps its own detections
and dashboards in its folders, as before.

**Asset and identity lists.** Once every server runs a version that shares them, the
asset and identity lists are shared too: a list uploaded on the **Assets & identities**
page of any server is used for urgency and risk on every server within a few seconds.
The server that founds the cluster brings its `assets.csv` and `identities.csv`. Each
server's lookups folder is then an inbox in the same way as the detections folder: a new
`assets.csv` or `identities.csv` copied there (an export from a CMDB or HR system) is
shared, a list uploaded anywhere is written back into every server's folder, and the
files a server has when it joins are only its starting point. Each server records what
it last saw in `lookups-seen.json` in its state folder. `GET /api/lookups/assets` and
`/api/lookups/identities` give the list's version (`etag`) for `If-Match`, as above. The
rows the sample data adds stay on the server that loaded it, and lists of up to
1,000,000 rows are kept in parts, so a server reading a list while it is replaced gets
the old list or the new one, never a mix.

**Notes on compliance controls.** The notes admins add on the
[Compliance](compliance.md#controls-handled-elsewhere) page are kept in the shared
settings too, so every server shows them and puts them in its reports. The server that
founds the cluster brings the notes in its `compliance-notes.json`. While a server cannot
use the shared settings, saving a note there answers `503`.

## Field names when several servers receive events

Each day's events go to one index per data model, and Signalith lets one index hold at
most 2,400 fields. Signalith's own fields always fit; the names senders choose (JSON
keys, syslog structured data, CEF extensions) share what is left (see
[Ingest limits](sending-data.md#ingest-limits)). With several servers:

- The budget of new names per daily index (1,000, and 600 for syslog vendor fields) is
  shared out equally among the servers that stored events in the last 10 minutes, with
  at least 100 for each. Each server's heartbeat says when it last stored an event, so
  the shares follow servers as they start and stop.
- Before adding new names to an index, a server also looks at how many fields the index
  really has (checked at most every 30 seconds) and adds none once it has 2,000.

Fields over the limit are not lost: their values stay in the event's raw message
(`_raw`), and the event says how many were left out in `dropped_fields`. Fields
Signalith produces itself are always kept.

## Agents across servers

The [Endpoints page](endpoints.md#log-agents) lists every log agent once, whichever
servers it sends to: each server notes the agents it hears from and saves that in
OpenSearch once a minute. Agents that need a new configuration, for example because they
trust a certificate authority the servers no longer use, are marked there.

## Upgrading servers you set up by hand

### Rolling upgrade, one server at a time

Upgrade the servers one after the other, so the others keep receiving events and
users stay signed in:

1. Before each server, run `signalith cluster upgrade-check` on any server (see
   [upgrade-check](cluster-cli.md#upgrade-check)), or open **Upgrade the servers** on
   the Servers page, which shows the same check as a checklist for each server and
   says which server to upgrade next. Wait while it says it is not safe yet.
2. **Drain** the server on the Servers page (see
   [Draining and removing a server](#draining-and-removing-a-server)).
3. Install the new version on it: the new package on Linux (or by hand, as the
   [README](https://github.com/jrsamsanchez/Signalith/blob/main/README.md#linux) says),
   the new MSI or `install.ps1` on
   [Windows](https://github.com/jrsamsanchez/Signalith/blob/main/README.md#windows)
   (with apt, run `sudo apt update` first). In Docker, in the Signalith folder,
   `git pull && docker compose -f deploy/docker/docker-compose.yml up -d`; for a
   server added with **Add a server**, set `SIGNALITH_VERSION` in
   `deploy/docker/join.env` to the new version, then
   `docker compose -f deploy/docker/docker-compose.server.yml --env-file deploy/docker/join.env up -d`.
4. Wait until the Servers page shows it on the new version: **Draining**, since a
   drained server stays drained across the restart (or **Ready** if you did not drain
   it). Upgrade no other server until then.
5. **Resume** it, and go on with the next server.

### Which server runs the jobs

From this version on, the server that runs the background jobs hands them to the
first upgraded server once that one has been ready for a minute and has caught up
with the shared settings, so the jobs move once, to the new version. Upgrade the
server that runs the jobs last; the checklist puts it at the end. A server that is in
the middle of a retention run or an archive restore finishes it first. When only one
server may run the jobs, they pause for about 40 seconds while it is upgraded.

### New features while versions are mixed

A feature that needs every server to read a newer format is greyed out, with
**Available when every server runs** and the version, until every server seen in the
last 24 hours runs the new version. Then the cluster's level rises by itself and the
feature turns on; the Servers page names the servers it still waits for. After the
raise, a server of an older version refuses to start. From this version on, its
message names the version to install; an older release says only which level the
shared settings are at, and that a newer version wrote them. A server you took away for good still counts for 24 hours:
remove it on the Servers page so it stops counting at once.

### Going back to the previous version

Before the level rose, install the previous version again, one server at a time as
above. After it rose, the previous version cannot read the shared settings, so they
go back into each server's own files:

1. Stop every server, so no change is made after the export.
2. On each server but one, run `sudo signalith cluster export -c /etc/signalith/signalith.yaml --to-files <new folder>`
   (see [export --to-files](cluster-cli.md#export-to-files)). The files are for that
   server: their passwords and keys are sealed with its master key. A server cannot
   export once the shared settings are put aside, and `-retire` refuses on a server
   that has not exported.
3. On the remaining server, run
   `sudo signalith cluster export -c /etc/signalith/signalith.yaml -retire --to-files <new folder>`,
   then `sudo signalith cluster export -c /etc/signalith/signalith.yaml -retire` on
   each of the others. This puts the shared settings and the cluster keys aside.
4. Copy the files on each server as the `README.txt` of its export says: it gives the
   commands for the platform the export ran on.
5. Install the previous version and start the servers. The server that runs the jobs
   makes a new cluster, with a new cluster key, from its files.
6. Give the other servers that key: `signalith cluster export-key` on that server and
   `signalith cluster import-key` on each of the others (see
   [export-key and import-key](cluster-cli.md#export-key-and-import-key)). Until then
   they keep using their own files and never take the jobs over. Servers with
   `SIGNALITH_CLUSTER_KEY_FILE` set to the same key file use it again instead.

On Windows, run the commands in an administrator PowerShell with
`& "$env:ProgramFiles\Signalith\signalith.exe"` in place of `sudo signalith`. In
Docker, stop the server with `docker compose -f deploy/docker/docker-compose.yml stop signalith`
and run each command as
`docker compose -f deploy/docker/docker-compose.yml run --rm signalith cluster export -c /etc/signalith/signalith.yaml ...`
(for a server added with **Add a server**, use the `docker-compose.server.yml` command
of step 3 above and `-c /var/lib/signalith/signalith.yaml`). The export folder must
then be a new folder directly in `/var/lib/signalith`, such as
`/var/lib/signalith/export`, as that is the only folder Docker keeps.

### Versions before the servers took turns

Versions before the servers took turns run the background jobs on every server with
**Run detections on schedule** on, so two of them run detections, threat intel
downloads and retention twice, and they do not appear on the Servers page. Upgrade
them all at the same time, or turn off **Run detections on schedule**
(`detections.scheduler: false`) on every server but one, upgrade them one by one, and
turn it back on once all of them run this version. Until then, a server of such a
version puts its older index template back when it starts; the next start of a newer
server puts the newer one back.

**The cluster key.** The first server of this version to run the jobs founds the
cluster and makes the cluster key (see
[Shared settings and the cluster key](#shared-settings-and-the-cluster-key)). Every
other server needs it, with `signalith cluster import-key` or
`SIGNALITH_CLUSTER_KEY_FILE` set to one key file on every server before the upgrade:
until it has the key, a server keeps using its own files and never takes the jobs
over. That first server runs each detection that is on once straight away, over its
lookback (see [Schedules and missed runs](detections.md#schedules-and-missed-runs)).

**Users and settings.** The servers start sharing their users, and then their Settings
page, once every server that ran in the last 24 hours runs a version that shares them
(see [When the users become shared](users.md#when-the-users-become-shared) and
[When the settings become shared](settings.md#when-the-settings-become-shared)). When
the users become shared, each server restarts in place and everyone signs in once
more; `signalith passwd` then changes the built-in admin's password for every server,
and `signalith passwd -local` is one server's break-glass password while OpenSearch
cannot be used.

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
| `draining` | An admin drained it for maintenance (see [Draining and removing a server](#draining-and-removing-a-server)); **Resume** on the Servers page undoes it |
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
    server siem-a 10.0.0.11:9000 check
    server siem-b 10.0.0.12:9000 check
```

Agents send to the [agent port](sending-data.md#the-agent-port) (7779 by default), so
balance it the same way, with a backend of its own whose `server` lines use port 7779.
The agent port answers `/readyz` and `/livez` too.

**Seeing who really connected.** A load balancer that passes connections through
(TCP mode, the usual choice, so HTTPS and syslog over TLS end at Signalith) hides the
client's address: every browser, agent and device seems to be the balancer. Have it
add a PROXY protocol v2 header (`send-proxy-v2` in HAProxy, plus `check-send-proxy`
for its checks) and turn on **PROXY protocol from load balancers** for the web port
and for syslog, with the balancer under **Trusted reverse proxies**. Sign-in limits,
the audit log, agent limits, `syslog.allow` and each syslog event's host then see the
real client. Samples for HAProxy, nginx and keepalived are in
[deploy/loadbalancer](https://github.com/jrsamsanchez/Signalith/tree/main/deploy/loadbalancer),
and [Load balancers](load-balancers.md) walks through them.

Both addresses answer over HTTPS and also over plain `http://` on the same port
(everything else on plain HTTP is sent to HTTPS), so the plain `check` above works
while Signalith serves HTTPS, which it does by default. To check over HTTPS instead,
add `check-ssl` and the certificate authority to check it with (`ca-file`, the
server's `tls/ca.pem`; see [docs/https.md](https.md)) to each `server` line. A
Kubernetes container:

```yaml
readinessProbe:
  httpGet: { path: /readyz, port: 9000, scheme: HTTPS }
livenessProbe:
  httpGet: { path: /livez, port: 9000, scheme: HTTPS }
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

**Where agents send.** With several servers, Add data asks **Where do agents send?**:
the shared address (the public address, which should be the load balancer's or a DNS
name over every server) or one server's own address, each on its agent port (each server reports its own; see
[The agent port](sending-data.md#the-agent-port)). It looks the shared address up
and says which servers it reaches, and warns when it is just one server's address:
agents sent there wait while that server is down. Agents keep their events while they
wait, and send them once a server answers. Configurations made while several servers
share the work also have each agent open a new connection every 100 batches
(`net.keepalive_max_recycle`), so a server that comes back gets its share again.
A DNS name over several servers (round robin) works without a load balancer, but an
agent keeps trying the address it picked while that server is down, and some
resolvers keep a down server's address for minutes; a load balancer with health
checks moves agents at once. With neither, agents sent to one server's address are the
fallback, and the Health page and the Servers page say when a running server gets no
agent traffic while another does.

**Syslog behind a load balancer.** Syslog over TCP and TLS goes through the balancer
like the web port, with a PROXY protocol header. UDP has no such header: send it to a
virtual IP (keepalived, see the sample) or straight to one server. Never send one
device to two servers at once: each message would be stored twice. When a server
stops, devices on TCP reconnect through the balancer to another; a few messages sent
just before may be stored twice or lost, as with any syslog server that restarts.
