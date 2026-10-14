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
| Version | The Signalith version it runs |

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

**Which servers may run them.** Every server, unless **Run detections on schedule**
(`detections.scheduler`) is turned off on its Settings page. Leave it on: the
servers take turns by themselves. Turn it off only on a server that should never
run the jobs, for example one that only receives data.

**Changing retention and feeds.** Until settings are shared between servers, the
Data retention, Threat intel feed, Notifications and Playbooks settings can be changed only on
the server that runs the jobs.

## When a server will not take over

Retention policies, threat intel feeds, notifications, playbooks and custom detections are still kept in
files on each server. A server whose files differ from those of the server that
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
`admin-password-hash` when the admin password was changed with `signalith passwd`,
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
4. Copy the retention, feed and detection files listed above, so it can take the
   jobs over. Copy only those files: never `node.id` or the `cluster` folder. In
   Docker they are in the data volume; copy them into the new server's volume
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
| `stopping` | It is shutting down and handing its jobs over. This takes up to a minute while jobs finish: the systemd unit allows 100 seconds, the compose file 90, and the Windows service waits 90 |

Do not use `/readyz` to restart a server: a server that waits for OpenSearch is
fine, and restarting it does not help. Use `/livez` for that.

HAProxy, for example, with each person kept on one server (see below):

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

**Keep each person on one server.** A sign-in to the web pages is kept by the
server it was made on, so set the load balancer to send each person to the same
server (sticky sessions, or source address affinity). If that server stops, people
sign in again on the other one. Agents and syslog need no such setting: any server
takes any agent's data.
