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
    A backup of Signalith's files holds the master key together with the passwords and
    API keys it decrypts, and the private key of Signalith's certificate authority. Keep
    backups as private as the key itself, on encrypted storage. To keep the master key
    apart, see [Keeping the master key out](#keeping-the-master-key-out).

This page covers one server. Backing up several servers that share one OpenSearch is
coming in a later version; until then, back up OpenSearch once and the files of each
server.

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
    docker compose -f deploy/docker/docker-compose.yml exec signalith rm /var/lib/signalith/signalith-backup.zip
    ```

Then copy the snapshots out of Docker, next to the zip:

```sh
docker compose -f deploy/docker/docker-compose.yml cp opensearch:/usr/share/opensearch/snapshots ./opensearch-snapshots
```

Keep `signalith-backup.zip` and the `opensearch-snapshots` folder together, somewhere
other than this computer.

**To restore**, on a Signalith started with `docker compose up -d` at the same version,
from the folder that holds the zip and the snapshots folder (all of these work in
PowerShell too):

```sh
docker compose -f deploy/docker/docker-compose.yml stop signalith
docker compose -f deploy/docker/docker-compose.yml cp ./opensearch-snapshots/. opensearch:/usr/share/opensearch/snapshots/
docker compose -f deploy/docker/docker-compose.yml exec -u 0 opensearch chown -R 1000:1000 /usr/share/opensearch/snapshots
docker compose -f deploy/docker/docker-compose.yml exec opensearch sh snapshot.sh list
docker compose -f deploy/docker/docker-compose.yml exec opensearch sh snapshot.sh restore <name>
docker compose -f deploy/docker/docker-compose.yml run --rm --no-deps --user 0 --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER -v "${PWD}:/backup" signalith restore -yes /backup/signalith-backup.zip
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
It prints each folder it copied. Options:

| Option | What it does |
| --- | --- |
| `-o file.zip` | Where to write the backup |
| `-archive` | Also copies the [archived days](retention.md#archives), which can be large. Without it, back up the archive folder on its own |
| `-no-master-key` | Leaves the master key out (see [Keeping the master key out](#keeping-the-master-key-out)) |

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
    sudo signalith restore /root/signalith-backup.zip
    ```

    ```powershell
    signalith restore C:\Backups\signalith-backup.zip
    ```

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
computer, restore a backup made with `-no-master-key`, then
`signalith cluster import-key`, and enter the passwords again on the **Settings**,
**Threat intel** and **Notifications** pages.

## Schedule backups

A nightly backup with cron on Linux, keeping two weeks of zips (`sudo crontab -e`; use
`/usr/local/bin/signalith` for an install by hand):

```sh
15 2 * * * cd /var/backups/signalith && /usr/bin/signalith backup >/dev/null && find . -name 'signalith-backup-*.zip' -mtime +14 -delete
```

Add the snapshot command above to the same script, and delete old snapshots with
`$CURL -X DELETE "$OS/_snapshot/signalith/<name>"`. OpenSearch's
[snapshot management](https://opensearch.org/docs/latest/tuning-your-cluster/availability-and-recovery/snapshots/snapshot-management/)
can also take and delete snapshots on a schedule by itself.

On Windows, a scheduled task as SYSTEM, from PowerShell as Administrator:

```powershell
schtasks /Create /TN "Signalith backup" /RU SYSTEM /SC DAILY /ST 02:15 /TR "cmd /c cd /d C:\Backups && signalith backup"
```

For the Docker quick start, schedule the two commands under
[While Signalith runs](#while-signalith-runs) the same way.

## Keeping the master key out

`signalith backup -no-master-key` leaves the master key out of the zip, so whoever gets
the backup cannot read the passwords and API keys in it. Keep the key apart, in a
password manager or a vault (see [Backing up the key](encryption.md#backing-up-the-key)).
When you restore such a backup, the install keeps its own master key; put the old one
back in its place before you start the server, or enter the passwords and keys again.

Disk encryption protects backups too; see [Disk encryption](encryption.md#disk-encryption).

## Archived days

[Archives](retention.md#archives) are another copy of events: each day is written to a
`.ndjson.gz` file before retention deletes it, and `signalith archive restore` brings
it back, even into a new OpenSearch. They hold only events, not findings, cases or
settings, so they add to a backup rather than replace it. Keep the archive folder on
another disk and back it up with your usual file backups.
