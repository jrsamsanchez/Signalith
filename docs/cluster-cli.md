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

`found` and `reset-key` change the cluster without a running server's help; the
others may run while Signalith runs on the same computer.

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
| [`tls`](#tls) | The cluster's certificate authority and each server's; `tls choose` keeps one for the whole cluster |

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
passphrase. The key is kept in that server's state folder, encrypted with its master
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
them, so you can enter them again on the Threat intel page. Then give the other
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
| Every copy of the cluster key is lost | Stop every server, `reset-key`, then `export-key` and `import-key` |
| No server can run the background jobs, and you need the cluster now | `found` |
| The built-in admin's password is lost or must change on every server | `signalith passwd` on any server |
| You want a password for one server that works while OpenSearch is down | `signalith passwd -local` on that server |
| Servers set up separately each have their own certificate authority | `tls`, then `tls choose` the one to keep |

## tls

```
signalith cluster tls        [-c file] [-json]
signalith cluster tls choose [-c file] [-yes] <server or fingerprint>
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
changing the cluster's certificate authority comes in a later version.

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

| Exit code | Meaning |
| --- | --- |
| 0 | Safe to upgrade the next server |
| 3 | Not safe yet: the output says what to wait for |
| 1 | The check could not run (OpenSearch not reachable, no identity) |

```
Server  Version  State  Jobs       Caught up
siem-a  0.2.0    ready  runs them  yes
siem-b  0.2.0    ready             yes

Safe to upgrade the next server.

Upgrade siem-b next: it does not run the jobs. Upgrade siem-a, which runs them, last.
```

With `-json` it prints `safe`, `servers` (each with `name`, `version`, `state`, `live`,
`jobs`, `caught_up` as `yes`, `no` or `unknown`, and `level_max`), `versions`,
`cluster_level`, `blockers` and `warnings` (each with a `code`, the `server` and the
`text`) and `next`. A server that is the only one using its OpenSearch prints that
it can simply be stopped, upgraded and started, and exits 0.

## opensearch-ca

```
signalith cluster opensearch-ca        [-c file] [-json]
signalith cluster opensearch-ca import [-c file] [-cert root-ca.pem] <root-ca-key.pem>
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
