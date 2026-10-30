# Backup and restore

A Signalith server keeps its data in two places, and a backup needs both:

- **OpenSearch** holds the events, findings, cases and risk events, and the settings
  the server keeps there: users and sign-in, threat intel feeds, retention policies,
  agent tokens and the shared settings of the cluster.
- **Signalith's own files** hold `signalith.yaml`, the settings saved on the
  **Settings** page, custom detections, dashboards, asset and identity lists,
  notifications, response actions and playbooks, and the **state folder**: the master
  key, the cluster key, Signalith's HTTPS certificate and its certificate authority, and
  the server's identity.

Back up both at about the same time and restore them together. A server restored with
only one half finds settings signed with a key it does not have, or keys for settings
it no longer has.

| | Docker quick start | Linux (package or by hand) | Windows |
| --- | --- | --- | --- |
| Config file | `deploy/docker/signalith.yaml` in your checkout | `/etc/signalith/signalith.yaml` | `C:\ProgramData\Signalith\signalith.yaml` |
| State folder and lists | the `signalith-data` volume (`/var/lib/signalith`) | `/var/lib/signalith` | `C:\ProgramData\Signalith` |
| OpenSearch certificates, first admin password, shared agent token | the `opensearch-certs` and `signalith-secrets` volumes | your OpenSearch's files | your OpenSearch's files |
| OpenSearch data | the `opensearch-data` volume | your OpenSearch | your OpenSearch |

!!! warning "A backup holds your keys"
    A backup of Signalith's files holds the passwords and API keys Signalith keeps,
    encrypted with the master key, and the private keys of Signalith's HTTPS certificate,
    its certificate authority and its OpenSearch account. The master key is written to a
    file of its own next to the zip; store that file somewhere other than the backups (see
    [The master key](#the-master-key)). Keep backups private, on encrypted storage, and
    only restore backups you made and kept private: a backup brings back settings and
    response scripts the server runs.

Signalith can have OpenSearch take the snapshots by itself, on a schedule, and shows on
the **Health** page when the last one was taken: see
[Scheduled snapshots](#scheduled-snapshots). Several servers that share one OpenSearch
need one set of snapshots and a backup of each server's files; see
[Restore drill](#restore-drill) for how to bring back one server or all of them.

## Docker quick start

There are two ways. Copying the volumes is the simplest and brings everything back
exactly as it was, but stops Signalith for a minute or two. Snapshots work while it
runs.

### Copy the volumes

Run these from the folder you cloned Signalith into. They stop Signalith and
OpenSearch, copy each volume into a `.tar.gz` file in a `signalith-backup` folder, and
start them again. Pick a quiet time: Signalith receives nothing while it is stopped.

In a shell (Linux, macOS, WSL):

```sh
docker compose -f deploy/docker/docker-compose.yml stop
mkdir -p signalith-backup
for v in opensearch-data opensearch-certs opensearch-snapshots signalith-data signalith-secrets; do
  docker run --rm -v "docker_$v:/volume:ro" -v "$PWD/signalith-backup:/backup" busybox tar czf "/backup/$v.tar.gz" -C /volume .
done
docker compose -f deploy/docker/docker-compose.yml up -d
```

In PowerShell (Windows with Docker Desktop):

```powershell
docker compose -f deploy/docker/docker-compose.yml stop
New-Item -ItemType Directory -Force signalith-backup | Out-Null
foreach ($v in "opensearch-data","opensearch-certs","opensearch-snapshots","signalith-data","signalith-secrets") {
  docker run --rm -v "docker_${v}:/volume:ro" -v "${PWD}/signalith-backup:/backup" busybox tar czf "/backup/$v.tar.gz" -C /volume .
}
docker compose -f deploy/docker/docker-compose.yml up -d
```

The volumes' names start with `docker_`, the name of the folder the compose file is in.
If `docker volume ls` shows another start, use that instead.

**To restore**, on the same computer or a new one with Signalith checked out at the same
version: create the containers without starting them, unpack each file into its
volume, then start.

```sh
docker compose -f deploy/docker/docker-compose.yml down -v      # only on a computer whose Signalith you are replacing: deletes its volumes
docker compose -f deploy/docker/docker-compose.yml up --no-start
for v in opensearch-data opensearch-certs opensearch-snapshots signalith-data signalith-secrets; do
  docker run --rm -v "docker_$v:/volume" -v "$PWD/signalith-backup:/backup:ro" busybox tar xzf "/backup/$v.tar.gz" -C /volume
done
docker compose -f deploy/docker/docker-compose.yml up -d
```

In PowerShell, the loop is the one above with `tar xzf` in place of `tar czf`, and
`/volume` without `:ro`. Everything comes back as it was: the same admin password, the
same certificate for browsers and agents, and the same agent tokens.

### While Signalith runs

Two commands, with nothing stopped:

1. An OpenSearch **snapshot** of the events, findings, cases and settings:

    ```sh
    docker compose -f deploy/docker/docker-compose.yml exec opensearch sh snapshot.sh create
    ```

    OpenSearch writes it to the `opensearch-snapshots` volume. Later snapshots only copy
    what changed since the one before, so they are quick. `sh snapshot.sh list` lists
    them and `sh snapshot.sh delete <name>` deletes one.

2. A copy of **Signalith's files** with `signalith backup`:

    ```sh
    docker compose -f deploy/docker/docker-compose.yml exec signalith signalith backup -o /var/lib/signalith/signalith-backup.zip
    docker compose -f deploy/docker/docker-compose.yml cp signalith:/var/lib/signalith/signalith-backup.zip .
    docker compose -f deploy/docker/docker-compose.yml cp signalith:/var/lib/signalith/signalith-backup.master-key.zip .
    docker compose -f deploy/docker/docker-compose.yml exec signalith rm /var/lib/signalith/signalith-backup.zip /var/lib/signalith/signalith-backup.master-key.zip
    ```

    Store `signalith-backup.master-key.zip` somewhere other than the backup, such as a
    password manager (see [The master key](#the-master-key)).

Then copy the snapshots out of Docker, next to the zip:

```sh
docker compose -f deploy/docker/docker-compose.yml cp opensearch:/usr/share/opensearch/snapshots ./opensearch-snapshots
```

Keep `signalith-backup.zip` and the `opensearch-snapshots` folder together, somewhere
other than this computer, and the master key file apart from them.

**To restore**, on a Signalith started with `docker compose up -d` at the same version,
from the folder that holds the zip, the master key file and the snapshots folder (all
of these work in PowerShell too):

```sh
docker compose -f deploy/docker/docker-compose.yml stop signalith
docker compose -f deploy/docker/docker-compose.yml cp ./opensearch-snapshots/. opensearch:/usr/share/opensearch/snapshots/
docker compose -f deploy/docker/docker-compose.yml exec -u 0 opensearch chown -R 1000:1000 /usr/share/opensearch/snapshots
docker compose -f deploy/docker/docker-compose.yml exec opensearch sh snapshot.sh list
docker compose -f deploy/docker/docker-compose.yml exec opensearch sh snapshot.sh restore <name>
docker compose -f deploy/docker/docker-compose.yml run --rm --no-deps --user 0 --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER -v "${PWD}:/backup" signalith restore -yes -master-key /backup/signalith-backup.master-key.zip /backup/signalith-backup.zip
docker compose -f deploy/docker/docker-compose.yml up -d
docker compose -f deploy/docker/docker-compose.yml exec signalith signalith cluster accept-restore -yes
```

Run the `-f` paths from your Signalith folder, or give the full path to
`docker-compose.yml`. What to expect:

- `snapshot.sh restore` replaces the days and indices the snapshot holds and keeps
  newer ones, so events that arrived after the snapshot stay.
- `signalith restore` puts back the master key, the cluster key, the HTTPS certificate
  and its authority, and the lists, detections and dashboards. It leaves
  `signalith.yaml` and the OpenSearch certificates of the new install as they are (they
  are read-only in the container); copy your old `deploy/docker/signalith.yaml` back by
  hand if you changed it.
- `accept-restore` tells the server that the older shared settings in OpenSearch are
  wanted, not changed behind its back. See
  [signalith cluster](cluster-cli.md#accept-restore).
- On a new install, the built-in admin's password is the new install's
  (`signalith initial-password` shows it) unless you changed it with
  `signalith passwd`. Users added on the **Users** page come back with their passwords.
- Agents set up with their own token (from **Add data**) keep working. Agents that use
  the older shared token need it again: reinstall them from **Add data**, or copy the
  volumes instead, which keeps it.

## Linux and Windows installs

Here OpenSearch is yours, so you back it up with its own snapshots, and Signalith's
files with `signalith backup`.

### Signalith's files

`signalith backup` copies `signalith.yaml`, the state folder and every file and folder
the server uses into one zip file. It finds them the way the service does, including
folders set in the systemd unit or the Windows service, and can run while the server
runs.

On Linux:

```sh
sudo signalith backup -o /root/signalith-backup.zip
```

On Windows, in PowerShell as Administrator:

```powershell
signalith backup -o C:\Backups\signalith-backup.zip
```

Without `-o`, it writes `signalith-backup-<server>-<date>-<time>.zip` in the current
folder, so a scheduled backup never overwrites the last one. It never overwrites a file.
It prints each folder it copied, and writes the master key next to the zip as
`<zip name>.master-key.zip` (see [The master key](#the-master-key)). Both files are
readable only by the account that made them, on Windows too. Options:

| Option | What it does |
| --- | --- |
| `-o file.zip` | Where to write the backup |
| `-archive` | Also copies the [archived days](retention.md#archives), which can be large. Without it, back up the archive folder on its own |
| `-include-master-key` | Puts the master key in the zip instead, for one file to keep |
| `-no-master-key` | Writes no copy of the master key at all |

### OpenSearch snapshots

OpenSearch writes snapshots to a folder named in `path.repo`. Once, on every
OpenSearch node: make the folder, give it to OpenSearch's account, add it to
`opensearch.yml` and restart OpenSearch.

```sh
sudo install -d -o opensearch -g opensearch -m 0750 /var/backups/opensearch
echo 'path.repo: ["/var/backups/opensearch"]' | sudo tee -a /etc/opensearch/opensearch.yml
sudo systemctl restart opensearch
```

With several OpenSearch nodes, the folder must be one shared folder that every node
mounts at the same path, such as an NFS share. OpenSearch can also write to S3, Azure
or Google Cloud Storage with its repository plugins; see OpenSearch's
[snapshot documentation](https://opensearch.org/docs/latest/tuning-your-cluster/availability-and-recovery/snapshots/snapshot-restore/).

Then register the folder, once, and take snapshots. These use OpenSearch's admin
account and the certificate of the CA that signed OpenSearch's own (put its path in
`--cacert`); `signalith` in `signalith*` is `opensearch.index_prefix` from
signalith.yaml.

```sh
OS="https://localhost:9200"
CURL="curl -sS -u admin --cacert /etc/opensearch/root-ca.pem -H Content-Type:application/json"

# Once: register the folder as the repository "signalith"
$CURL -X PUT "$OS/_snapshot/signalith" -d '{"type":"fs","settings":{"location":"/var/backups/opensearch"}}'

# Each backup: a snapshot of Signalith's indices, named by date
$CURL -X PUT "$OS/_snapshot/signalith/signalith-$(date +%Y%m%d-%H%M%S)?wait_for_completion=true" \
  -d '{"indices":"signalith*","include_global_state":false}'

# List them
$CURL "$OS/_cat/snapshots/signalith?v"
```

`include_global_state: false` leaves OpenSearch's own settings and its security
configuration out: those stay with your OpenSearch. Copy the snapshot folder somewhere
else too; a snapshot on the same disk does not survive the disk. Windows has `curl.exe`
too; run these from any computer that can reach OpenSearch.

### Restoring

1. Install Signalith, the same version as the backup (or newer), and stop it:
   `sudo systemctl stop signalith`, or `Stop-Service Signalith` on Windows.
2. Put its files back. `signalith restore` shows what it will write and asks first:

    ```sh
    sudo signalith restore -master-key /root/signalith-backup.master-key.zip /root/signalith-backup.zip
    ```

    ```powershell
    signalith restore -master-key C:\Backups\signalith-backup.master-key.zip C:\Backups\signalith-backup.zip
    ```

    Without `-master-key` the install keeps its own master key (see
    [The master key](#the-master-key)).

    It refuses while the server runs. It writes each file where this install keeps the
    same thing, which may be another folder than on the old server, and gives it to the
    service's account. Files of this install that the backup does not have (such as a
    master key made when it was installed) are moved to a `before-restore-<time>` folder
    in the state folder, so nothing is lost. Archived days are never moved.
3. Restore the snapshot. Signalith's indices must be closed to be restored over; this
   closes them, restores the snapshot's, and opens the rest again:

    ```sh
    $CURL -X POST "$OS/signalith*/_close?expand_wildcards=open"
    $CURL -X POST "$OS/_snapshot/signalith/<name>/_restore?wait_for_completion=true" \
      -d '{"indices":"signalith*","include_global_state":false}'
    $CURL -X POST "$OS/signalith*/_open?expand_wildcards=closed"
    ```

    On a new OpenSearch, register the repository first (above).
4. Start Signalith, then tell it the restored settings are wanted:

    ```sh
    sudo systemctl start signalith
    sudo signalith cluster accept-restore -yes
    ```

Browsers and agents keep trusting the server: its certificate authority comes back with
it. If the new server has another name or address, set the public address on the
**Settings** page and reinstall the agents from **Add data**.

**Moving to a new Windows computer.** Windows keeps the master key encrypted for that
Windows installation (`keys\master.key.dpapi`), and a copy cannot be read anywhere
else, so the passwords and API keys it protects and the cluster key do not move with
it. Before you need it, keep the cluster key with `signalith cluster export-key` (see
[signalith cluster](cluster-cli.md)) and your passwords in a vault, or keep the master
key in a file you can move (see
[Keeping the key elsewhere](encryption.md#keeping-the-key-elsewhere)). On the new
computer, restore the backup without `-master-key`, then
`signalith cluster import-key`, and enter the passwords again on the **Settings**,
**Threat intel** and **Notifications** pages.

## Scheduled snapshots

Signalith can keep the OpenSearch half of the backup by itself: turn on **Scheduled
snapshots** in **Settings > Server > Backups** and name a snapshot repository. The
server that runs the background jobs then keeps an OpenSearch
[snapshot management](https://opensearch.org/docs/latest/tuning-your-cluster/availability-and-recovery/snapshots/snapshot-management/)
policy named `signalith-daily` (`<opensearch.index_prefix>-daily`), and OpenSearch
takes the snapshots and deletes the oldest by itself, also while Signalith is stopped.
It works on OpenSearch 2.17 and 3.x.

| Setting | Default | What it does |
| --- | --- | --- |
| Scheduled snapshots (`backup.snapshots`) | off | Turns them on. Turned off, the policy is deleted and the snapshots taken so far stay |
| Snapshot repository (`backup.snapshot_repository`) | `signalith` | A repository registered in OpenSearch: a shared folder, an S3 bucket or other storage |
| Take a snapshot (`backup.snapshot_every`) | every day | Every day, 12 hours, 6 hours or hour |
| Snapshot time (`backup.snapshot_at`) | `02:30` | The time of day of the first snapshot of each day, at a quiet hour |
| Snapshot time zone (`backup.snapshot_timezone`) | UTC | An IANA name such as `Europe/Berlin` |
| Snapshots to keep (`backup.snapshot_keep`) | 14 | OpenSearch deletes the oldest beyond this after each new snapshot |

Every server shares these settings. Each snapshot holds Signalith's indices
(`signalith-*`, `signalith_*` and the tenants' `signalith.t.*`), not OpenSearch's own
settings or security configuration (`include_global_state: false`), and only copies
what changed since the one before. The policy is Signalith's: a change made to it in
OpenSearch is put back within a minute, so change the settings instead.

Days in [cold storage](cold-storage.md) are left out. They are mounted from their own
snapshots in the cold storage repository (`signalith-cold`, and each tenant's own), so
a scheduled snapshot would copy nothing of them, and restoring one would mount them
again from a cold snapshot that retention may have deleted since, which leaves the
cluster red. Signalith adds a `-<index>` exclusion to the policy's indices for each
mounted day, or a whole month or year at a time when they are many, and updates it as
days go cold. To back up cold days, keep those repositories (or copies of them); after
a restore, retention mounts the cold days it finds missing there by itself.

The **Backups** card of the **Health** page shows the last snapshot and the last
successful one, when the next is due and how many are kept, with the last
`signalith backup` of that server's own files. It turns red when the last successful
snapshot is older than two scheduled periods (two days, with one a day), when
OpenSearch has no repository by that name, or when it does not let Signalith manage
snapshots, and says what to do. While scheduled snapshots are off and the server's
files had no `signalith backup` in 30 days, the Health page shows an amber
*Nothing is being backed up* item instead.

### What OpenSearch needs

**A repository**, registered once with OpenSearch's admin account:

- In the Docker quick start, the `opensearch-snapshots` volume is ready; register it as
  the repository `signalith`:

    ```sh
    docker compose -f deploy/docker/docker-compose.yml exec opensearch sh snapshot.sh register
    ```

- On your own OpenSearch, register a folder named in `path.repo` (see
  [OpenSearch snapshots](#opensearch-snapshots)) or a bucket, by the name you give in
  the settings:

    ```sh
    $CURL -X PUT "$OS/_snapshot/signalith" -d '{"type":"fs","settings":{"location":"/var/backups/opensearch"}}'
    ```

**Permissions** for Signalith's own OpenSearch user. OpenSearch runs the policy as the
user that wrote it, so Signalith needs these cluster permissions itself:

- `cluster:admin/opensearch/snapshot_management/policy/write`, `.../policy/get`,
  `.../policy/delete` and `.../policy/explain` to keep the policy and read how it runs;
- `cluster:admin/snapshot/create`, `cluster:admin/snapshot/get` and
  `cluster:admin/snapshot/delete` to take, list and delete the snapshots;
- `cluster:admin/repository/get` to check the repository.

The role names each action, so Signalith cannot restore or clone a snapshot with it.

The Docker quick start, the Helm chart and the OpenSearch the Windows installer sets up (`signalith opensearch install`)
give them with the role `signalith_snapshots` (in
`deploy/docker/opensearch/security/roles.yml`), mapped to Signalith's certificates in
`roles_mapping.yml`; an update loads it with the next
`docker compose -f deploy/docker/docker-compose.yml up -d`. On an OpenSearch with your
own security configuration, add the same role:

```yaml
signalith_snapshots:
  cluster_permissions:
    - "cluster:admin/opensearch/snapshot_management/policy/write"
    - "cluster:admin/opensearch/snapshot_management/policy/get"
    - "cluster:admin/opensearch/snapshot_management/policy/delete"
    - "cluster:admin/opensearch/snapshot_management/policy/explain"
    - "cluster:admin/snapshot/create"
    - "cluster:admin/snapshot/get"
    - "cluster:admin/snapshot/delete"
    - "cluster:admin/repository/get"
```

and map it to Signalith's user or certificate (in `roles_mapping.yml`, or with
`PUT _plugins/_security/api/rolesmapping/signalith_snapshots`).

**What these snapshots do not protect against.** Read these before you rely on them:

- **Snapshot rights in OpenSearch cover every repository.** They cannot be limited to
  one, so with this role Signalith can list, take and delete snapshots in any
  repository of that OpenSearch, not only its own. On an OpenSearch you share with
  other applications, you may prefer to leave the role out and take snapshots yourself.
- **Snapshots that Signalith's credentials can delete do not protect against a
  compromised Signalith.** Someone who takes over a Signalith server, or its OpenSearch
  certificate or password, can delete every snapshot, and so the evidence in them.
  Copy the repository off-site, or use storage that refuses deletes for a time, such as
  an S3 bucket with Object Lock or other WORM storage (see
  [Copies elsewhere](#copies-elsewhere)).
- **Turning scheduled snapshots off for good takes two steps.** OpenSearch keeps
  running the policy with the roles that were stored with it when Signalith wrote it,
  even after you take the role away from Signalith. Turn **Scheduled snapshots** off in
  the settings (the server running the background jobs then deletes the policy), check
  that it is gone, and delete it with OpenSearch's admin account if it is not:

    ```sh
    $CURL "$OS/_plugins/_sm/policies/signalith-daily"
    $CURL -X DELETE "$OS/_plugins/_sm/policies/signalith-daily"
    ```

    (`<opensearch.index_prefix>-daily`). Then remove the `signalith_snapshots` mapping.

Saving any of the backup settings asks for your password again, as other settings that
change where data goes do.

OpenSearch's snapshot management is part of its index-management plugin, which every
OpenSearch download has; a minimal build without it gets a red item that says so.

### Copies elsewhere

A snapshot in a folder on the same disk as OpenSearch does not survive the disk, and a
snapshot Signalith can delete does not survive someone who has taken over Signalith.
So keep a copy where Signalith's credentials cannot reach it:

- **Off-site:** copy the repository regularly to another computer or bucket that
  Signalith and OpenSearch cannot write to, such as the quick start's volume with
  `docker compose -f deploy/docker/docker-compose.yml cp opensearch:/usr/share/opensearch/snapshots ./opensearch-snapshots`.
- **WORM storage:** an S3 bucket with Object Lock (compliance mode), or other
  write-once storage, refuses deletes until its retention period ends, whoever asks.
  Keep that period shorter than the time **Snapshots to keep** spans (under 14 days for
  14 daily snapshots), or OpenSearch cannot delete the oldest ones and the policy's
  deletions fail.

A repository on another computer (an NFS share, an S3 bucket) survives a lost disk,
but not a compromised Signalith.

## Schedule backups of each server's files

Scheduled snapshots keep OpenSearch's half. Each server's own files still need
`signalith backup`, and keep changing less often: after an update, a new certificate
or a change of settings is enough, plus a schedule as a safety net. A nightly backup
with cron on Linux, keeping two weeks of zips (`sudo crontab -e`; use
`/usr/local/bin/signalith` for an install by hand):

```sh
15 2 * * * cd /var/backups/signalith && /usr/bin/signalith backup >/dev/null && find . -name 'signalith-backup-*.zip' -mtime +14 -delete
```

On Windows, a scheduled task as SYSTEM, from PowerShell as Administrator:

```powershell
schtasks /Create /TN "Signalith backup" /RU SYSTEM /SC DAILY /ST 02:15 /TR "cmd /c cd /d C:\Backups && signalith backup"
```

For the Docker quick start, schedule the `signalith backup` commands under
[While Signalith runs](#while-signalith-runs) the same way. Each backup is noted in the
state folder (`last-backup.json`), and the **Backups** card shows the last one.

Without scheduled snapshots, add the snapshot command of
[OpenSearch snapshots](#opensearch-snapshots) to the same script, and delete old
snapshots with `$CURL -X DELETE "$OS/_snapshot/signalith/<name>"`.

## Restore drill

Practise a restore before you need one, once a quarter or after a big change, on spare
computers so the real ones keep running: a backup that was never restored is a hope.
The same steps restore for real. You need the same version of Signalith as the backup
(or newer), the snapshots, each server's `signalith backup` zip and its master key file.

**Practise on a copy.** Give a spare OpenSearch the same repository, read-only, so the
drill cannot change or delete a snapshot (for a folder, mount the share there too and
name it in `path.repo`):

```sh
$CURL -X PUT "$OS/_snapshot/signalith" -d '{"type":"fs","settings":{"location":"/var/backups/opensearch","readonly":true}}'
$CURL "$OS/_cat/snapshots/signalith?v&s=start_epoch"
```

The last line lists the snapshots, oldest first; pick the newest `SUCCESS` one.
Scheduled snapshots are named `signalith-daily-<date>-<letters>`.

### One server

1. Install Signalith on the spare computer and stop it (or, in the Docker quick start,
   `up -d` and stop `signalith`).
2. Put its files back with `signalith restore -master-key <key file> <zip>`, as in
   [Restoring](#restoring) (or [While Signalith runs](#while-signalith-runs) in Docker).
3. Restore the snapshot over Signalith's indices: close them, restore, open the rest.
   In Docker, `sh snapshot.sh restore <name>` does the three; otherwise:

    ```sh
    $CURL -X POST "$OS/signalith*/_close?expand_wildcards=open"
    $CURL -X POST "$OS/_snapshot/signalith/<name>/_restore?wait_for_completion=true" \
      -d '{"indices":"signalith*","include_global_state":false}'
    $CURL -X POST "$OS/signalith*/_open?expand_wildcards=closed"
    ```

4. Start Signalith and accept the restored shared settings:

    ```sh
    sudo systemctl start signalith
    sudo signalith cluster accept-restore -yes
    ```

5. Check, and write down how long it took:
    - you can sign in with an account from the backup;
    - a search over the day before the snapshot finds events, and **Findings** and
      **Cases** show the old ones;
    - the **Health** page has no red items, and **Backups** shows the snapshots;
    - an agent sends to the restored server (point one at it for the drill).

A drill on a copy ends here: turn the spare computer off, or wipe it. For real, the
restored server is the server; with scheduled snapshots on in the restored settings,
it writes the policy again within a minute and the snapshots go on.

### Several servers sharing one OpenSearch

The servers share one OpenSearch, so there is one set of snapshots, and each server has
its own files and its own backup zip: its name, identity, keys and certificates. Never
restore one server's zip onto another; two servers with one identity get in each
other's way (see [new-identity](cluster-cli.md#new-identity) if it happened).

1. **Stop every Signalith server**: `sudo systemctl stop signalith`, or
   `Stop-Service Signalith`, on each. Nothing may write to Signalith's indices while
   they are restored.
2. **Pause the snapshots**, so none starts while the indices are closed:

    ```sh
    $CURL -X POST "$OS/_plugins/_sm/policies/signalith-daily/_stop"
    ```

    Signalith starts the policy again once a server runs the background jobs.
3. **Restore the snapshot** once, from any computer that reaches OpenSearch, with the
   three commands of [One server](#one-server), step 3.
4. **Put back the files of each server that lost them**, on that server, with its own
   zip and master key file: `signalith restore -master-key <its key file> <its zip>`.
   A server whose files are intact needs nothing. A server you rebuild from scratch
   instead joins again with a join token, as when it was added (see
   [Servers](servers.md)).
5. **Start the servers**, then on any one of them:

    ```sh
    sudo signalith cluster accept-restore -yes
    ```

    Each server remembers how far the shared settings had got, and refuses older ones
    as changed behind its back until this says the restore was on purpose; every
    server accepts them within seconds (see
    [accept-restore](cluster-cli.md#accept-restore)).
6. **Check**, as for one server, and on the **Servers** page that every server is
   there, one of them runs the background jobs, and no server reports shared settings
   it refuses. **Backups** on the **Health** page shows the policy running again.

For a drill on copies, use spare computers for the servers too, each restored from its
own zip, and pause nothing on the real cluster: the read-only repository keeps the real
snapshots safe.

## The master key

The master key decrypts every password and API key Signalith keeps: scan logins, which
are often domain accounts, Microsoft 365 and Okta tokens, the directory's bind password,
AI keys and the mail and webhook secrets. So `signalith backup` leaves it out of the zip
and writes it to a file of its own next to it, `<zip name>.master-key.zip`: whoever gets a
backup alone cannot read the passwords and keys in it. Store the key file somewhere other
than the backups, such as a password manager or a vault (see
[Backing up the key](encryption.md#backing-up-the-key)), and give it to `signalith
restore -master-key` to put the key back. You only need a new copy after the key is
changed.

Restored without `-master-key`, the install keeps its own master key; put the old one
back in its place before you start the server, or enter the passwords and keys again.

`-include-master-key` puts the key in the zip instead, if you would rather keep one file
and store it as carefully as the key. `-no-master-key` writes no copy at all, for when
the key is already kept elsewhere.

Disk encryption protects backups too; see [Disk encryption](encryption.md#disk-encryption).

## Archived days

[Archives](retention.md#archives) are another copy of events: each day is written to a
`.ndjson.gz` file before retention deletes it, and `signalith archive restore` brings
it back, even into a new OpenSearch. They hold only events, not findings, cases or
settings, so they add to a backup rather than replace it. Keep the archive folder on
another disk and back it up with your usual file backups.
