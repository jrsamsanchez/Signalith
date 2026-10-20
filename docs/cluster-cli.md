# signalith cluster

The servers that share one OpenSearch keep the settings they share in it, in the
`<prefix>_config` index, signed with the cluster key that each of them keeps in its
state folder (see [Shared settings and the cluster key](servers.md#shared-settings-and-the-cluster-key)).
The server that runs the background jobs makes the cluster by itself, so most setups
only ever need `export-key` and `import-key`, to give another server the key. The
other commands are for when something went wrong.

Run the commands as the user Signalith runs as (on Linux packages, `sudo -u
signalith`), on a server whose `signalith.yaml` names the OpenSearch the servers
share. Every command takes `-c <file>` for another configuration file. Each change is
written to the log as an audit record, with who ran it.

`found` and `reset-key` change the cluster without a running server's help, and
`leave` and `new-identity` need Signalith stopped on the same computer; the others
may run while it runs.

| Command | What it does |
| --- | --- |
| [`status`](#status) | This server's place in the cluster, the servers with the key, and any problem |
| [`export-key`](#export-key-and-import-key) | Writes the cluster key, encrypted with a passphrase, for another server |
| [`import-key`](#export-key-and-import-key) | Gives this server the cluster key that `export-key` wrote |
| [`export`](#export) | Prints the shared settings as YAML; with `-settings`, the settings of all servers as a file `apply` takes |
| [`apply`](#apply) | Changes the settings of all servers to those of a file (configuration as code) |
| [`import -from-cache`](#import-from-cache) | Writes this server's copy of the shared settings back to OpenSearch |
| [`found`](#found) | Makes the cluster from this server's files |
| [`reset-key`](#reset-key) | Makes a new cluster key when every copy of it is lost |
| [`accept-restore`](#accept-restore) | Accepts the shared settings after an OpenSearch snapshot was restored |
| [`tls`](#tls) | The cluster's certificate authority and each server's; `tls choose` keeps one for the whole cluster, `tls import` gives back its key after `reset-key`, `tls rotate-ca` replaces it |
| [`token`](#token) | Makes a join token, which adds a server with `signalith join` |
| [`approve`](#approve) | Approves a server that waits to join, by its fingerprint |
| [`rotate-key`](#rotate-key) | Gives the cluster a new key, so copies of the old one open nothing new |
| [`remove`](#remove-and-leave) | Takes a drained or stopped server out of the cluster |
| [`leave`](#remove-and-leave) | Takes this stopped server out of the cluster |
| [`new-identity`](#new-identity) | Makes this stopped server a new one, for a cloned computer or a copied state folder |

`signalith join` and `signalith opensearch-check`, which are not `cluster` commands,
add a server with a join token and check an OpenSearch for several servers; see
[join](#join) and [opensearch-check](#opensearch-check).

`signalith passwd`, which is not a `cluster` command, changes the built-in admin's
password for every server of a cluster that shares its users; see
[The built-in admin's password](#the-built-in-admins-password).

## status

```
signalith cluster status [-c file] [-json]
```

Shows this server's name and identity, its mode, the cluster's name, identity and
level (4 once every server keeps audit records and archives in OpenSearch, 3 once every server can read shared settings, 2 once every server can read shared users, 1 before), the cluster key it uses, the servers in the keyring and any problem, such as a
shared setting that does not check out. `-json` prints the same as JSON, with the
mode and the cluster under `shared`, and `problems` and `warnings` when there are any:

```json
{
  "server": "siem-a",
  "node_id": "…",
  "shared": {"mode": "member", "cluster_id": "…", "cluster_name": "Signalith", "…": "…"},
  "keyring": {"…": {"name": "siem-a", "fingerprint": "…", "added_at": "…", "added_by": "…"}},
  "keys": ["…"]
}
```

The modes:

| Mode | Meaning |
| --- | --- |
| `member` | This server is a member of the cluster and reads the shared settings from OpenSearch |
| `importing` | It founded the cluster and is moving its files into OpenSearch |
| `legacy_b` | It is not part of the cluster yet, so it uses its own files and runs no background jobs: give it the cluster key |
| `legacy_c` | No cluster exists yet; it uses its own files until the server that runs the background jobs founds it |
| `legacy_a` | OpenSearch could not be reached and it has no copy of the shared settings, so it uses its own files |
| `degraded` | It cannot use the shared settings in OpenSearch now; it keeps the copy it has, and changes are paused |
| `key_missing` | The shared settings are signed with a cluster key this server does not have |
| `gone` | The shared settings in OpenSearch are gone: their index was deleted or replaced |

## export-key and import-key

```
signalith cluster export-key [-c file] [-o file]
signalith cluster import-key [-c file] <file>
```

`export-key` asks for a passphrase of at least 12 characters and writes the cluster
key, encrypted with it, to `-o` (readable by you only) or to the standard output.
Copy the file to the other server and run `import-key` there with the same
passphrase. `import-key` refuses when OpenSearch is not secured (https with a checked
certificate, and a password or client certificate): a second server is never added
to an OpenSearch anyone on the network can read. The key is kept in that server's state folder, encrypted with its master
key, and a running server joins the cluster within seconds. Delete the file
afterwards.

When the standard input is not a terminal, both read the passphrase from its first
line, so a script can pipe it in.

Instead of `import-key`, a key you chose before the cluster was made can be given
in a file named in `SIGNALITH_CLUSTER_KEY_FILE`: 32 random bytes as one line of
base64, such as `openssl rand -base64 32 > cluster-key`, readable by Signalith only.
The server that makes the cluster uses that key, so only a cluster made with it can
be joined this way; no command writes an existing cluster's key in plain form (see
[Shared settings and the cluster key](servers.md#shared-settings-and-the-cluster-key)).

## export

```
signalith cluster export [-c file] [-o file]
```

Prints every shared document as YAML: its kind, revision, who changed it last and
its content. Stored passwords and API keys stay encrypted with the cluster key.
Use it to look at the shared settings, or to keep a copy next to your backups.
Documents in `<prefix>_config` that Signalith did not write are named in a comment
and left out.

### export -settings

```
signalith cluster export -settings [-c file] [-o file] [-server name]
```

Once the servers share their settings (see
[Settings on several servers](settings.md#settings-on-several-servers)), writes the
settings of all servers as one file in the shape of `signalith.yaml`, the file
`apply` takes as it is, followed by each server's own settings as comments marked
"this server only" (only one server's with `-server`, a name or node id). Passwords
and keys are left out. It is the same file as **Download settings as YAML** on the
Settings page.

## apply

```
signalith cluster apply [-c file] -f file [-yes]
```

Changes the settings every server shares to those of a file in the shape of
`signalith.yaml`, such as one `export -settings` wrote and you then edited and keep
in version control. It shows what changes, compared with the values in use, asks,
and then writes them, as a change on the Settings page would: what applies at once
does so on every server within a few seconds, and the Settings page lists what waits
for a restart and restarts the servers one at a time. `-yes` skips the question, for
scripts. Applying a file that changes nothing says so and writes nothing.

- Only settings for all servers are taken. A file with a server's own settings, or
  its connection and folder settings, is refused with the list of them: change those
  on that server's Settings page. Settings not in the file are left as they are.
- `retention.*`, `intel.feeds` and `auth.ldap` in the file change the shared retention
  policies, feeds and directory sign-in, as a change of them in a server's
  `signalith.yaml` would.
- A changed `auth.admin_user` renames the built-in admin for every server: it signs in
  under the new name with the same password, and its sessions end. A user that already
  has the new name stops it. If the command is stopped part way, run it again to finish.
  This is the only way to rename it: a changed `auth.admin_user` in one server's
  `signalith.yaml` is only listed on the Servers page.
- It refuses while the servers do not share their settings yet, or while this server
  cannot use the shared settings (it is not a member, or OpenSearch refuses writes).

Every change is audited with who ran the command.

## import -from-cache

```
signalith cluster import [-c file] -from-cache
```

Each server keeps its last copy of the shared settings in `cluster/cache.enc` in its
state folder, encrypted with its master key. When the `<prefix>_config` index was
deleted, every server says the shared settings are `gone` (and `/readyz` answers
`gone`). Run this on the server whose copy is the newest: it writes the copy back,
with the same cluster identity, and the other servers resume by themselves.
Documents still in OpenSearch are left as they are. If OpenSearch holds another
cluster by then, nothing is written.

A copy older than 30 days is not used.

## found

```
signalith cluster found [-c file] [-force] [-name name]
```

Makes the servers sharing this OpenSearch a cluster, from this server's files: its
feeds and retention policies become the shared ones, and it makes the cluster key.
The server that runs the background jobs does this by itself, so `found` refuses
while a server that may run them is up (it watches the servers' heartbeats for 12
seconds to tell); `-force` founds anyway. `-name` names the cluster (`Signalith` by
default).

If this server was a member of a cluster whose shared settings are gone, use
`import -from-cache` instead, which keeps the cluster. When no server keeps a copy,
`found -force` makes the cluster again from this server's files.

Give the other servers the new key afterwards (`export-key`, then `import-key`).

## reset-key

```
signalith cluster reset-key [-c file] [-yes]
```

When every copy of the cluster key is lost, nobody can check the shared settings any
more. Stop every server first: `reset-key` refuses while one is up. It also refuses
while this server still has a key the shared settings check out with (in its state
folder or in `SIGNALITH_CLUSTER_KEY_FILE`): the key is not lost then, so give it to
the other servers with `export-key` and `import-key` instead. It shows each shared
document, with its revision, who changed it last, whether its signature checks out
with a key this server has and how it compares to this server's copy, asks you to
confirm (`-yes` skips the question), makes a new key and signs the documents with
it. A document whose signature fails under a key this server has was changed outside
Signalith: it is not signed again, so every server keeps ignoring it. Passwords and
API keys stored with the old key cannot be read and are emptied; the command lists
them, so you can enter them again on the Threat intel page. The cluster's HTTPS
certificate authority key is among them: servers keep their certificates until they
expire, and can't renew them until `tls import` gives the key back (see
[tls](#tls)). Then give the other
servers the new key. Settings in a server's signalith.yaml that it already applied
are not applied again because of the new key: each server records them afresh at
its next start.

## accept-restore

```
signalith cluster accept-restore [-c file] [-yes]
```

Each server remembers how far the shared settings had got, and refuses older ones as
changed outside Signalith. After you restore an OpenSearch snapshot on purpose, run
this on a member of the cluster: every server accepts the shared settings now in
OpenSearch within seconds.

## rotate-key

```
signalith cluster rotate-key [-c file] [-yes]
```

Asks the server that runs the background jobs to rotate the cluster key, as
**Rotate cluster key** on the Servers page does, and prints each step until it is
done (Ctrl-C stops waiting, not the rotation). See
[Draining and removing a server](servers.md#draining-and-removing-a-server) for the
steps, and what happens to servers that are offline. A rotation that stopped part
way goes on from where it stopped when you run it again. It needs every server on a
version that supports it.

## remove and leave

```
signalith cluster remove [-c file] [-yes] [-no-rotate] <server name or node id>
signalith cluster leave  [-c file] [-yes] [-no-rotate]
```

`remove` takes another server out of the cluster: out of the keyring and off the list
of servers. The server must be drained (on the Servers page), stopped, or offline for
10 minutes. `leave` does it for this server: stop Signalith first. It also deletes this
server's copy of the cluster key and of the shared settings, and keeps its HTTPS
certificate. That certificate can't be renewed once the server is out: `leave` prints
the date it expires. To use the server on its own after that, delete its `tls` folder
before it starts, and give its agents a new configuration. Uninstall the server
afterwards, or run `new-identity` on it before you add it again.

Both print that the removed server may still hold the cluster's HTTPS certificate
authority key, in a backup of its state folder or its copy of the shared settings. It
could make certificates agents trust until the cluster's certificate authority is
replaced with `tls rotate-ca` (see [When a server leaves](servers.md#when-a-server-leaves)).

Both then rotate the cluster key, so the removed server's copy opens nothing new;
`-no-rotate` skips that, and `rotate-key` does it later. A removed server that starts
again with its old copy runs no background jobs and says it was removed; `import-key`
brings it back on purpose.

## new-identity

```
signalith cluster new-identity [-c file] [-yes]
```

For a computer cloned from another server, or a state folder copied from one: two
servers with one identity refuse to run side by side. Stop Signalith, then run this on
the copy. It moves `node.id` aside (to `node.id.replaced-<time>`), deletes the node key
and the copy of the cluster key, and the server makes a new identity when it starts.
Give it the cluster key again with `export-key` and `import-key`. It needs no
OpenSearch. In Docker:

```
docker compose -f deploy/docker/docker-compose.yml stop signalith
docker compose -f deploy/docker/docker-compose.yml run --rm signalith signalith cluster new-identity
docker compose -f deploy/docker/docker-compose.yml up -d
```

## The built-in admin's password

```
signalith passwd [-c file] [-local]
```

On a server of a cluster whose servers share their users (see
[Users on several servers](users.md#users-on-several-servers)), `signalith passwd`
asks for the new password twice and changes the built-in admin's password for every
server of the cluster, in OpenSearch. It applies within a few seconds, with no restart,
and is written to the log as an audit record. It needs the cluster key and OpenSearch,
like the commands above. When OpenSearch cannot be reached, or the servers do not
share their users yet, it changes the password in this server's files, as on a server
that is not in a cluster, and says what that does: a password kept in
`admin-password-hash` in the state folder is used only while this server keeps its
users in its own files, and one written to signalith.yaml becomes the password of every
server the next time this server starts with OpenSearch available. Run it again once
OpenSearch answers to change the cluster's password at once.

`-local` keeps the new password on this server only, in `admin-password-local` in its
state folder. On a server of a cluster that shares its users it works only while the
shared settings cannot be used (OpenSearch down, or refusing writes because its disk is
full), so an admin can always sign in to that server to fix it; it applies within a few
seconds, with no restart. It is the only break-glass password: an
`admin-password-hash` from an earlier `signalith passwd` is not one. Use it before you
need it; it never changes the password of the other servers. On a server that was never
in a cluster, `-local` writes `admin-password-hash` and needs a restart, as
`signalith passwd` does there.

## When to use which

| What happened | What to do |
| --- | --- |
| A new server says it is not part of the cluster | `export-key` on a member, `import-key` on it |
| Someone deleted the `<prefix>_config` index | `import -from-cache` on the server with the newest copy |
| OpenSearch was restored from a snapshot | `accept-restore` |
| Every copy of the cluster key is lost | Stop every server, `reset-key`, then `export-key` and `import-key`, then `tls import` the certificate authority's key from your offline copy |
| No server can run the background jobs, and you need the cluster now | `found` |
| The built-in admin's password is lost or must change on every server | `signalith passwd` on any server |
| You want a password for one server that works while OpenSearch is down | `signalith passwd -local` on that server |
| Servers set up separately each have their own certificate authority | `tls`, then `tls choose` the one to keep |
| A server is retired for good | Drain it and remove it on the Servers page, or `remove`; on the server itself, stop it and `leave` |
| A copy of the cluster key may have leaked | `rotate-key`, then `tls rotate-ca` |
| A removed server, or a backup, may hold the cluster's certificate authority key | `tls rotate-ca prepare`, `switch`, then `retire` |
| A server was cloned from another, or its state folder copied | Stop the copy, `new-identity`, then `import-key` |

## tls

```
signalith cluster tls        [-c file] [-json]
signalith cluster tls choose [-c file] [-yes] <server or fingerprint>
signalith cluster tls import [-c file] [-cert ca.pem] [-yes] <ca.key>
signalith cluster tls rotate-ca [-c file] [-yes] prepare|switch|retire|abort
```

Once every server runs a version that shares one, the servers of a cluster share one certificate
authority: each issues its own HTTPS certificate from it, so an agent set up against one
server trusts them all. A cluster that grew from one server keeps that server's, so
nothing changes for its agents. When servers that were set up separately meet, each
keeps its own until you choose one.

`tls` shows the cluster's certificate authority (its fingerprint, the names every
server's certificate covers and the ones retired), each server's certificate and, while
none is chosen, the certificate authorities to choose from: the servers using each, how
many agents trust it and how many would need a new configuration, and the servers whose
names it may not sign. The one marked `*` is the one Signalith suggests: most agents,
then the founder's. `-json` prints the same as JSON.

`tls choose` keeps the certificate authority of a server (its name or node id) or with
that fingerprint for the whole cluster. It asks first unless you add `-yes`, then asks
the server holding it to publish it and waits for it. A server that is offline can't
publish it: start it first. When the agents can't all be read from OpenSearch, the
counts may be short, so it refuses unless you add `-yes`. The other servers take it within
seconds: each keeps its old one in `tls/retired` in its state folder, and the agents set
up with an old one are marked as needing a new configuration. The choice is made once:
to change the cluster's certificate authority afterwards, replace it with `tls rotate-ca`.

`tls import` gives the cluster its certificate authority's key again, after `reset-key`
emptied it. `tls` then says the key was lost with the cluster key, and no server can
renew its certificate. Give it the `tls/ca.key` of an `export --to-files` folder, or a
founder's old `tls/ca.key` from a backup. It reads only a plain file (not a link) of at
most 64 KB, and never prints the key. When `ca.pem` is next to the key, or you name a
certificate with `-cert`, its fingerprint must be the cluster's. The key must belong to
the cluster's certificate authority: any other key is refused, and nothing changes. The
key is sealed with the cluster key, bound to the fingerprint, as when the certificate
authority was first shared. Every server renews from it within seconds. It asks first
unless you add `-yes`, and is written to the audit log. Keep the key file offline
afterwards, or delete it (see
[Backing up the cluster's CA](servers.md#backing-up-the-clusters-ca)).

`tls rotate-ca` replaces the cluster's certificate authority, one step at a time, as the
Servers page does (see [Replacing the cluster's CA](servers.md#replacing-the-clusters-ca)):

- `prepare` makes a new one, with the same limits as the one in use, and every server
  hands out both;
- `switch` makes every server issue its certificate from the new one, once every running
  server hands it out. The old one is still handed out;
- `retire` stops handing out the old one and deletes its key, once every running
  server's certificate comes from the new one;
- `abort` drops the prepared one and its key, before the switch. Every server then hands
  out only the one in use again. After a switch there is nothing to abort: retire the
  old one, then replace the new one if needed.

`reset-key` empties the prepared one's key too, and `tls import` can't give it back. `tls`
then says its key is lost, and `switch` and `prepare` are refused: run `abort`, then
`prepare` again.

Each asks first unless you add `-yes`, then asks the server that runs the background
jobs to take the step, and waits for it. A step that isn't ready is refused with the
servers it waits for. `tls` shows which step the cluster is at, and its date, and how
many managed agents have the new certificate authority (agents of older versions don't
say). `switch` warns when some don't have it yet, but doesn't wait for them: an agent
that is offline can't fetch it. Each step is written to the audit log.

## upgrade-check

```
signalith cluster upgrade-check [-c file] [-json]
```

Run it on any server before each server's upgrade, with the version installed now. It
only reads, so it may run while the servers run. It says whether it is safe to stop one
more server and install the new version on it:

- every server that is up has applied every change of the shared settings;
- no server is starting, stopping, down or restarting to apply new settings;
- no retention step is deleting data (OpenSearch runs no delete, reindex or snapshot
  of the cluster's indices, and the server that runs the jobs is not in delete-only
  mode);
- the servers run at most two versions, and each can read the cluster's level of
  stored data.

It also warns, without blocking, when the server that runs the background jobs is the
only one that can run them (the jobs then pause for about 40 seconds while it is
upgraded), when a server is offline, and when an older server does not say how far it
applied the shared settings. It suggests which server to upgrade next: the ones that
do not run the jobs first, then the one that does, so the jobs move once, to the new
version.
The Servers page shows the same check as a checklist, **Upgrade the servers**, with
Drain, Upgrade, Ready and Resume for each server (see
[Upgrading servers you set up by hand](servers.md#upgrading-servers-you-set-up-by-hand)).

| Exit code | Meaning |
| --- | --- |
| 0 | Safe to upgrade the next server |
| 3 | Not safe yet: the output says what to wait for |
| 1 | The check could not run (OpenSearch not reachable, no identity) |

```
Server  Version  State  Jobs       Caught up
siem-a  0.2.0    ready  runs them  yes
siem-b  0.2.0    ready             yes

Every server runs 0.2.0. Safe to start an upgrade.

To upgrade, start with siem-b: it does not run the jobs. Upgrade siem-a, which runs them, last.
```

Once a server runs the new version it says `Upgrade siem-a next` instead. It promises
that the server running the jobs hands them to the first upgraded server only when that
will happen: the server is not a scanner, and both versions are releases the old one can
tell apart. Builds named by a commit, such as a lab's, keep the jobs where they are
until that server is drained or upgraded.

With `-json` it prints `safe`, `servers` (each with `name`, `version`, `state`, `live`,
`jobs`, `caught_up` as `yes`, `no` or `unknown`, and `level_max`), `versions`,
`cluster_level`, `blockers` and `warnings` (each with a `code`, the `server` and the
`text`), `next`, and `current` when every server runs one version or `newest` while
they run two. A server that is the only one using its OpenSearch prints that
it can simply be stopped, upgraded and started, and exits 0.

## token

```
signalith cluster token [-c file] [-platform linux|windows|docker] [-role scanner] [-ttl 60m] [-note text] [-node-url url] [-url url] [-json]
signalith cluster token [-c file] -revoke <id>
```

Makes a join token, as **Servers → Add a server** does, and prints it with the line
to run on the new server for Linux, Windows and Docker: the same one-line installs as
the dialog, which install Signalith when the new computer has none and then join (see
[Adding servers](multi-server.md)). The token works once and
for `-ttl` (60 minutes by default, at most 24 hours). It names this server's https
address (`-url`, else `server.node_url`, else `server.public_url`; one only this
computer reaches is refused) and the fingerprint of its HTTPS certificate authority,
which the new server checks before it trusts the answer. Its secret is printed this
once and kept in OpenSearch only encrypted with the cluster key, so a lost token
cannot be shown again: make a new one. `-platform`, `-note` and `-node-url` (the
address the other servers will reach the new server at) are shown with the token on
the Servers page. `-role scanner` adds a scanner, which only scans the networks picked for
it and never runs the background jobs (see [Cluster servers and scanners](multi-server.md#cluster-servers-and-scanners));
without it the token adds a cluster server. `-revoke <id>` cancels a token that was not used yet (its id, such
as `jt_…`, is printed with it), for one pasted in the wrong place.

It needs a member of the cluster, OpenSearch with security turned on, and an HTTPS
certificate from Signalith's own certificate authority or a private one whose root
is in the certificate file. Without one, approve the new server instead.

## approve

```
signalith cluster approve [-c file] [-fingerprint fp] [-yes] [<server|fingerprint>]
```

A server started with the cluster's OpenSearch settings but without the cluster key
waits to join and shows a fingerprint, such as `4F2A-91C0-…`, on its sign-in page
and in its log. Without an argument, `approve` lists the servers that wait, with
their fingerprints. With a fingerprint (dashes and case do not matter), it approves
that server. What is approved is always a fingerprint you read on the new server,
never the name the waiting server gives itself, which anyone who can write to
OpenSearch could copy: with a name or node id, give the fingerprint with
`-fingerprint`, or compare the one shown and answer yes at a terminal (`-yes` does not
do that comparison for you, so with a name it needs `-fingerprint`). The server then
gets the cluster key, encrypted so only it can read it, and joins within a minute. A
fingerprint that does not match is refused, as is any approval while OpenSearch is not
secured or while the cluster key is being rotated, and a server that would take the
place of a member (its node id listed with another key, or a member's name). A server
whose approval was lost (it stayed away a day, or the approval could not be written) is
listed again and can be approved again.

## join

`signalith join '<token>'` adds the computer it runs on to a cluster, with a join
token made on **Servers → Add a server** of a server of the cluster. Run it as root
(`sudo`) or as an Administrator, after installing Signalith from a package, the
`.msi` or the Docker image:

```
sudo signalith join 'SJ1.eyJ1Ijoi...' --name siem-c --node-url https://siem-c.example.com:9000
```

The token may also come from the standard input (`signalith join -`), or be left out
to be asked for without being shown. Other users of the computer can see the command
line of a running program, so on a shared computer give it one of these ways rather
than in the command. It asks before it changes anything, unless `--yes`.

It checks the server the token names by the certificate the token pins, asks it for
what a new server needs (sealed so only this computer can read it), and checks from
here that it can use the cluster's OpenSearch: OpenSearch answers, its certificate is
trusted, it takes the sign-in, its security plugin is on, the cluster's settings in it
check out with the key received, the listen address is free and the clocks agree
within 2 seconds. Only then does it write the cluster key, the OpenSearch settings
(as Settings page entries, so environment variables still win), OpenSearch's
certificate files under `<state>/opensearch/`, and the HTTPS certificate from the
cluster's certificate authority. If anything fails to be written, what was written is
undone, with the owners and access the files had. On Linux the files join made go to
the `signalith` account (never a folder it only wrote in, and never through a link),
an archive folder outside `/var/lib/signalith` is added to the unit's
`ReadWritePaths=`, and the service is enabled and restarted. Its last line names the
cluster and how many servers it has: `siem-c joined Signalith (3 servers). Add it to
your load balancer: …`.

When the name given with `--name` differs from `cluster.node_name` in `signalith.yaml`
(or `SIGNALITH_NODE_NAME` in the service's settings), join refuses: the service would
start under that other name. The answering server refuses a name another server of
the cluster has, and a server that has a member's identity with another key (a state
folder copied from that server).

A joined server has no built-in admin password of its own: the cluster's users sign
in, and join never writes one. For a password that works on this server while
OpenSearch is down, run `signalith passwd -local` on it.

Without root, join runs only with `--no-start`: it then writes only files this user
can write and changes no owner. The Docker image joins this way on its first start, as
its own user, with `-c /var/lib/signalith/signalith.yaml`: join makes that file and
keeps its state next to it, taking the listen address, name and node URL from
`SIGNALITH_LISTEN`, `SIGNALITH_NODE_NAME` and `SIGNALITH_NODE_URL`.

| Flag | What it does |
| --- | --- |
| `-c <file>` | Another configuration file; one is made, as `signalith init` makes it, when there is none |
| `--name` | This server's name (default: `SIGNALITH_NODE_NAME`, the name it has, or the computer's name) |
| `--listen` | The address the web page and API listen on (default: `SIGNALITH_LISTEN`, else the answering server's) |
| `--node-url` | The address the other servers reach this one at (`server.node_url`; default: `SIGNALITH_NODE_URL`) |
| `--copy-syslog` | Receive syslog on the same addresses as the answering server |
| `--no-start` | Write everything but do not start the service; needed to run join without root |
| `--merge` | For a server that kept its own files: adds its users, feeds, retention policies and settings that the cluster lacks (see below) |
| `--yes` | Do not ask before joining |
| `--allow-version-skew` | Join a cluster whose servers run another version (the cluster level must still allow it) |

| Exit code | Meaning |
| --- | --- |
| 0 | Joined |
| 1 | It cannot run here (not root, already in a cluster, a bad name), the server did not answer, or it used the token but could not finish (the message says to make a new one) |
| 2 | The token was refused: wrong, used or expired; or the token checked out but this server cannot join yet (another version, OpenSearch not secured, a name or identity another server has, a cluster key rotation in progress), and the message says the token was not used |
| 3 | The server is not the one the token names: someone may be intercepting the connection |
| 4 | This computer cannot use the cluster's OpenSearch; nothing was written, and the token is used |
| 5 | Writing failed and was undone; or, with `--merge`, the server joined but the merge failed partway (the message says so) |
| 6 | Everything was written, but the service did not start |

A token works once. After exit 4 or 5, after exit 2 for a wrong, used or expired
token, and after exit 1 when the message says the token was used, make a new one.

Without `--merge`, the new server uses the cluster's users, feeds, retention policies and
settings, and its own files are left as they are, unused. With `--merge`, for a server
that served alone (or waited to join) with files of its own, join adds to the cluster
what the cluster lacks: its users (with their passwords), threat intel feeds, retention
policies and shared settings. It never changes what the cluster has. What differs (a
user with another role or password, a feed of the same name at another address, a
policy that keeps data for another time, a setting with another value) is printed and
kept in the server's migration report in the shared settings, for an admin to decide;
passwords, keys and password hashes are never in it. When a retention policy differs,
retention waits until an admin confirms the policies on the **Data retention** page,
so nothing but the disk guard deletes by a policy the servers disagree on. When the
server's own HTTPS certificate authority is replaced by the cluster's, the report says
its agents need a new configuration. The merge runs last, once everything that makes
the server a member is written: what it adds to the cluster cannot be taken back by
undoing this computer's files. If it fails partway, the join is kept, the service
starts, what it added stays in the cluster, and join exits 5 saying so; add what is
missing on the cluster's pages. Each merge is audited as `cluster.merged`. Detections
and dashboards are not shared between servers yet, so they stay in the server's own
files.

## opensearch-check

`signalith opensearch-check <url> [--ca file] [--cert file --key file] [--user name]`
runs the OpenSearch checks of `join` on their own, from the computer it runs on, and
says what to fix for each that fails. The password of `--user` is read from
`SIGNALITH_OPENSEARCH_PASSWORD`, or asked for. It exits 1 when a check fails.
## opensearch-ca

```
signalith cluster opensearch-ca        [-c file] [-json]
signalith cluster opensearch-ca import [-c file] [-cert root-ca.pem] <root-ca-key.pem>
signalith cluster opensearch-ca revoke [-c file] [-yes] <server>
signalith cluster opensearch-ca crl    [-c file] [-o file]
```

`opensearch-ca` shows OpenSearch's certificate authority, if the cluster keeps one, and
who each server signs in to OpenSearch as: its own certificate, the shared one or a user
name, when that expires, and why it could not get or renew its own. `-json` prints the
same as JSON, without the CA's key.

`opensearch-ca import` hands OpenSearch's certificate authority to the cluster, so each
server gets its own OpenSearch certificate (see
[Each server's own OpenSearch certificate](servers.md#each-servers-own-opensearch-certificate)).
Give it the CA's key; its certificate is `root-ca.pem` next to it unless `-cert` names
another file. It refuses a CA that is not the one in `opensearch.ca_file`, and one other
than the cluster keeps already. In Docker, use `bootstrap-docker -export-ca-key` instead.

`opensearch-ca revoke` ends a server's OpenSearch access at once: every certificate the
cluster issued it that has not expired goes on the revocation list, and it gets no new
one unless it joins the cluster again. Name the server by its name or node id; it asks
first unless `-yes` is given, and refuses this server itself. Removing a server does the
same. OpenSearch hears of it through the revocation list (see
[Ending a server's OpenSearch access at once](servers.md#ending-a-servers-opensearch-access-at-once)).

`opensearch-ca crl` prints that revocation list, or writes it to the file `-o` names, to
copy to OpenSearch nodes that no Signalith server keeps it for.

## export --to-files

```
signalith cluster export --to-files <dir> [-c file] [-server s]
signalith cluster export -retire [--to-files <dir>] [-c file] [-yes] [-force]
```

`export --to-files` writes the shared settings as the files a server on its own keeps,
for going back to a version from before the cluster's level rose (see
[Going back to the previous version](servers.md#going-back-to-the-previous-version)).
`<dir>` must be a new or empty folder outside this server's folders, or a new folder
directly in the state folder (in Docker, `/var/lib/signalith/export`: the state folder
is the only one Docker keeps). It holds:

- the feeds (`intel_feeds.yaml`, the feeds of signalith.yaml included) and their status
  (`intel_feeds.json`), the retention policies (`retention.yaml`) and history
  (`retention_history.json`), the users (`users.json`, with their password hashes),
  the directory sign-in settings (`directory.json`), the settings of the Settings page
  (`settings.yaml`: the shared ones and this server's own, or those of the server
  `-server` names), the detections and their state, the dashboards, the asset and
  identity lists, and the cluster's certificate authority (`ca.pem` and `ca.key` in the
  state folder's `tls` folder);
- each laid out as on this server (`config/`, `state/`, `detections/`, `dashboards/`),
  with `MANIFEST.json`, which lists every file and where it goes, and `README.txt`,
  with the steps and the commands that copy them on the platform the export ran on
  (Linux, Windows or Docker).

Passwords and keys are sealed again with this server's master key, as its own files
keep them, so an export is for the server it ran on: run it on each server. One that
cannot be opened with this server's cluster keys is left out, and the log says which.
Not written, and listed as skipped in `MANIFEST.json`: the archive manifests (they are
files in the archive folder already), API tokens, join tokens, the reports of servers
that joined with `-merge`, the keyring, sign-in sessions and OpenSearch's certificate
authority. The built-in admin stays as signalith.yaml and `signalith passwd` set it.
While the shared retention policies wait to be confirmed (after servers with different
policies joined), the export is refused: confirm them on the Retention page first,
since a server on its own has no such hold. Each export leaves
`exported-<cluster id>.json` in the state folder, which `-retire` checks for.

`-retire` runs with every server stopped: it watches the heartbeats first and refuses
while any server runs, and this server must be stopped too. On the first server it
needs `--to-files`: it writes the files, blocks writes to the `<prefix>_config`
index, copies it into `<prefix>_config_retired_<UTC time>`, checks that the copy and
the original hold as many documents as were read, and deletes `<prefix>_config` (on a
failure it lifts the block and deletes the partial copy). On every server it moves this server's copy of the
shared settings (`cache.enc`) and its cluster keys into `retired-<UTC time>` in the
state folder; `node.id` and `node.key` stay. On the other servers, run it without
`--to-files`, after `export --to-files` there: it refuses on a server that never
exported, since that server cannot export any more, unless `-force` is given. It asks first unless `-yes` is given. The retired copy is kept, so going
forward again is possible. Both are audited.
