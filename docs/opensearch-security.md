# Securing OpenSearch

Signalith keeps every event, finding and investigation in OpenSearch, so anyone who
can reach OpenSearch can read or change them. This page sets OpenSearch up so that:

- it answers only over HTTPS, with a certificate from a small certificate authority
  (CA) of your own;
- nobody signs in with a password: Signalith signs in with a client certificate, and
  there are no built-in users and no anonymous access;
- Signalith's certificate may touch only Signalith's own indices (`signalith*`) and read
  the cluster's health.

The Docker quick start does all of this by itself. For OpenSearch installed on Linux or
Windows, `signalith opensearch-certs` makes the files and the steps below put them in
place.

Do not keep OpenSearch's demo security configuration. Its certificates, keys and
passwords (such as `admin`, and the `kirk` admin certificate) are published with
OpenSearch, so anyone can use them.

## Docker quick start

Nothing to set up by hand. Each `docker compose ... up` runs two short steps around
OpenSearch. First the setup step, `signalith bootstrap-docker`, which:

- makes the CA and three certificates the first time (RSA 3072, valid 10 years): one for
  OpenSearch, one for Signalith (`CN=signalith,O=Signalith`) and an admin certificate
  (`CN=signalith-admin,O=Signalith`) that can change OpenSearch's security settings;
- keeps them in the `opensearch-certs` and `signalith-secrets` volumes, readable only by
  the container that uses them, and the CA's key in a volume of its own (below). It leaves
  them alone on later runs. If a certificate is missing, damaged or due to expire within
  30 days, it makes that one again under the same CA; restart both then with
  `docker compose -f deploy/docker/docker-compose.yml restart opensearch signalith`;
- makes the first admin password and the shared agent token (the quick start's `ingest-token`) the same way.

Then, once OpenSearch has started, the step that loads OpenSearch's security settings
(the `opensearch-security` service, `deploy/docker/opensearch/load-security.sh`).
OpenSearch loads them by itself only as it starts with none stored yet, and tries just
once, which can fail on a slow computer. So this step checks that OpenSearch has them,
and loads them with `securityadmin.sh` and the admin certificate when it has none, or
when the files changed since the step last loaded them (after an update of Signalith, or
your own edit). When OpenSearch is too slow to take a file, it tries that file again, for
about 10 minutes in all. Signalith starts only after this step succeeds. When there is
nothing to do, it takes a second or two.

OpenSearch runs with its security plugin on and the demo setup skipped. Its settings are
in `deploy/docker/opensearch/opensearch.yml`, and the users and roles in
`deploy/docker/opensearch/security/`: `config.yml` (certificate sign-in only),
`internal_users.yml` (empty), `roles.yml` (the `signalith_server` role, and
`signalith_snapshots` for [scheduled snapshots](backup.md#scheduled-snapshots)) and
`roles_mapping.yml` (Signalith's certificate gets `signalith_server`, and
`signalith_snapshots` only once you register a snapshot repository with `snapshot.sh register`). OpenSearch publishes no
port; only Signalith reaches it, on the Docker network.

To look at OpenSearch yourself, use the admin certificate from inside its container. From
the folder you cloned Signalith into (one line, in PowerShell too):

```sh
docker compose -f deploy/docker/docker-compose.yml exec opensearch curl -s --cacert config/certs/root-ca.pem --cert config/certs/admin.pem --key config/certs/admin-key.pem "https://localhost:9200/_cat/indices?v"
```

If you change the files in `security/`, for example to give `roles.yml` another
`index_prefix`, run `docker compose -f deploy/docker/docker-compose.yml up -d` again: the
step sees the change and loads them.

### Where the CA's key is kept

The CA's certificate and key are in the `opensearch-ca` volume, which only the setup step
mounts: OpenSearch and Signalith never see the key. Guard it like a password: whoever has
it can make certificates OpenSearch trusts. A backup of the Docker volumes holds it, so
keep such backups as private as the data itself.

Versions before this one did not keep the key. Such an install keeps working as it is, and
the setup step's log says once per `up` that the key was not kept. Its certificates last
10 years, but to renew one, or to add servers, give it a CA with a key first (see
[Replacing the CA](#replacing-the-ca)).

To run the setup step by hand with one of the options below, from the folder you cloned
Signalith into (one line, in PowerShell too):

```sh
docker compose -f deploy/docker/docker-compose.yml run --rm setup bootstrap-docker <option>
```

### More names or nodes under the same CA

- `-opensearch-name NAME` adds a host name or IP address to OpenSearch's certificate, for
  when something reaches OpenSearch by another name. Repeat it, or separate names with
  commas. The certificate is made again under the same CA and keeps the name from then on;
  restart OpenSearch to use it.
- `-nodes N` keeps certificates for N OpenSearch nodes: `node.pem` for the first
  (`CN=opensearch`), then `node-2.pem` (`CN=opensearch-2`) and so on, all in the
  `opensearch-certs` volume. They are kept and renewed like the first, and never deleted
  when N goes down.

### Handing the CA key to Signalith

To add servers, Signalith gives each one its own OpenSearch certificate
(`CN=signalith-server-<name>,O=Signalith`), which `roles_mapping.yml` maps to the same
`signalith_server` role. For that it needs the CA:

```sh
docker compose -f deploy/docker/docker-compose.yml run --rm setup bootstrap-docker -export-ca-key
```

This puts `opensearch-ca.pem` and `opensearch-ca-key.pem` in the `import` folder of
Signalith's state volume, readable only by Signalith. Within a minute Signalith keeps the
CA in the cluster's shared settings, its key encrypted with the cluster key, deletes the
key file, and switches itself to a certificate of its own (see
[Each server's own OpenSearch certificate](servers.md#each-servers-own-opensearch-certificate)).
Start Signalith at least once before running it. If the files are already waiting there,
it leaves them as they are.

### Loading changed security settings

```sh
docker compose -f deploy/docker/docker-compose.yml run --rm setup bootstrap-docker -apply-security
docker compose -f deploy/docker/docker-compose.yml up -d
```

The first command makes the step that loads OpenSearch's security settings forget what it
loaded last, so the next `up` loads every file again. You seldom need it: an update of
Signalith that changes `roles_mapping.yml` or another file in `security/` is loaded on the
next `up` anyway, since the step compares the files with what it loaded last. On OpenSearch
installed without Docker, run `securityadmin.sh` (or `.bat`) as in
[step 3](#3-load-the-security-settings).

### Replacing the CA

```sh
docker compose -f deploy/docker/docker-compose.yml run --rm setup bootstrap-docker -new-ca
docker compose -f deploy/docker/docker-compose.yml restart opensearch signalith
```

This makes a new CA, keeps its key, and makes every certificate again under it. The setup
step never does this by itself, even when the CA is about to expire (after 10 years): it
stops with a message pointing here instead. Everything the old CA issued stops working:
the certificates Signalith made for other servers, and Signalith's own copy of the CA. Run
`-export-ca-key` again: Signalith then keeps the new CA in place of the old one, and each
server gets a new certificate of its own.

### If OpenSearch's security settings aren't loaded

You see one of these:

- `docker compose -f deploy/docker/docker-compose.yml up -d` ends with
  `service "opensearch-security" didn't complete successfully: exit 1`, and Signalith does
  not start;
- the **Servers** page shows a red alert that OpenSearch's security settings aren't
  loaded, and OpenSearch answers every request with `503` and
  `OpenSearch Security not initialized.`

OpenSearch refuses everyone until its security settings are loaded. From the folder you
cloned Signalith into:

1. Run the usual command again. It runs the step that loads OpenSearch's security
   settings again, which keeps trying for about 10 minutes, and then starts Signalith:
   ```sh
   docker compose -f deploy/docker/docker-compose.yml up -d
   ```
2. If it fails again, the step's log says why:
   ```sh
   docker compose -f deploy/docker/docker-compose.yml logs opensearch-security
   ```
   - `OpenSearch did not answer`: OpenSearch did not start, or keeps stopping.
     `docker compose -f deploy/docker/docker-compose.yml ps -a opensearch` shows whether it
     runs (`Up`; `Exited` or `Restarting` when it stopped), and the end of
     `docker compose -f deploy/docker/docker-compose.yml logs opensearch` says why. Fix
     what it says, then do step 1 again.
   - `... has a mistake, so OpenSearch can't read it`: a file in
     `deploy/docker/opensearch/security/` that you changed. Correct it, or undo your
     changes with `git checkout deploy/docker/opensearch/security`, then do step 1 again.
   - `OpenSearch's disk is nearly full` (`flood-stage watermark`): free some disk space,
     then do step 1 again. OpenSearch lifts its block by itself once there is room.
   - `OpenSearch didn't answer within 30 seconds` (`SocketTimeoutException`) on every
     try: OpenSearch is too slow on this computer right now. Close other programs, or give
     Docker more memory and CPU (below), then do step 1 again.
   - OpenSearch's own log may say more:
     `docker compose -f deploy/docker/docker-compose.yml logs opensearch`
3. To load them by hand instead (step 1 does the same by itself, so try it first), run
   this one line:
   ```sh
   docker compose -f deploy/docker/docker-compose.yml exec opensearch plugins/opensearch-security/tools/securityadmin.sh -cd config/opensearch-security -icl -nhnv -cacert config/certs/root-ca.pem -cert config/certs/admin.pem -key config/certs/admin-key.pem -h localhost
   ```
   It ends with `Done with success`. On a slow computer it can end with
   `ERR: cannot upload configuration, see errors above` instead, after a
   `SocketTimeoutException` for one of the files; on such a computer a whole run seldom gets
   every file in. Run it again: each run prints
   `SUCC: Configuration for '...' created or updated` for each kind it stored (`config`,
   `roles`, `tenants` and so on). Once every kind has printed that in at least one run,
   ask OpenSearch to use what is stored (the same command with `-rl` in place of
   `-cd config/opensearch-security`, one line):
   ```sh
   docker compose -f deploy/docker/docker-compose.yml exec opensearch plugins/opensearch-security/tools/securityadmin.sh -rl -icl -nhnv -cacert config/certs/root-ca.pem -cert config/certs/admin.pem -key config/certs/admin-key.pem -h localhost
   ```
   It ends with `Reload config on all nodes`. To check that OpenSearch now uses them (one
   line; it shows `"status":"UP"` once they are loaded, and `"status":"DOWN"` while they
   aren't):
   ```sh
   docker compose -f deploy/docker/docker-compose.yml exec opensearch curl -s --cacert config/certs/root-ca.pem https://localhost:9200/_plugins/_security/health
   ```
   Then start Signalith without the step:
   ```sh
   docker compose -f deploy/docker/docker-compose.yml up -d --no-deps signalith
   ```
   The next `up -d` (after an update, say) runs the step again, and it loads the files
   once more, since it did not load them itself.

To give Docker more memory and CPU: OpenSearch here needs about 2 GB of memory, so give
Docker at least 4 GB and 2 processors, more if the computer has them to spare.

- **Docker Desktop on Windows** (with WSL 2, the default): Windows sets the limits. Open
  (or create) the file `.wslconfig` in your user folder (`C:\Users\<you>\.wslconfig`) and
  put in it, with the numbers you want:
  ```ini
  [wsl2]
  memory=6GB
  processors=4
  ```
  Then quit Docker Desktop, run `wsl --shutdown` in PowerShell, and start Docker Desktop
  again.
- **Docker Desktop on Mac or Linux**: Settings > Resources.

## OpenSearch on Linux or Windows

Below, `<config>` is OpenSearch's config folder: `/etc/opensearch` for the Linux
packages, or the `config` folder where you unpacked OpenSearch on Windows (such as
`C:\opensearch\config`).

### 1. Make the certificates

On the Signalith server:

```sh
signalith opensearch-certs -out opensearch-pki
```

This is enough when OpenSearch runs on the same machine as Signalith. When it runs on
another machine, give its name with `-node` and every other name or address Signalith
uses to reach it with `-san`:

```sh
signalith opensearch-certs -out opensearch-pki -node search1 -san search1.example.com -san 10.0.0.5
```

The folder it writes holds:

| Path | For |
| --- | --- |
| `opensearch/certs/` | OpenSearch: the CA, its own certificate and key, and the admin certificate and key |
| `opensearch/opensearch-security/` | OpenSearch: `config.yml`, `internal_users.yml`, `roles.yml`, `roles_mapping.yml` |
| `opensearch/add-to-opensearch.yml` | Lines to add to `opensearch.yml` |
| `signalith/` | Signalith: the CA, its client certificate and key, and `add-to-signalith.yaml` |
| `ca/` | The CA's certificate and key: never copy it to OpenSearch |

The `*-key.pem` files are private keys. Copy them only where the steps say. Keep the `ca`
folder with the admin, somewhere safe, like a password: it makes certificates for more
nodes and servers under the same CA (below). Delete the rest of the `opensearch-pki`
folder when you are done.

Signalith uses indices named `signalith*`. If you set another `opensearch.index_prefix`,
change `index_patterns` in `opensearch-security/roles.yml` to match before step 4.

### 2. Put the files in place on the OpenSearch machine

1. Copy `opensearch/certs` to `<config>/certs`. On Linux, let only OpenSearch read it:
   ```sh
   sudo cp -r opensearch-pki/opensearch/certs /etc/opensearch/certs
   sudo chown -R opensearch:opensearch /etc/opensearch/certs
   sudo chmod 700 /etc/opensearch/certs && sudo chmod 600 /etc/opensearch/certs/*
   ```
2. Delete the demo certificates OpenSearch put directly in `<config>` (`esnode.pem`,
   `kirk.pem`, `root-ca.pem` and their keys), but not your new `certs` folder. OpenSearch
   refuses to start while they are there (`Demo certificates found`), and the Linux
   packages put them there even when the demo setup is skipped. On Linux:
   ```sh
   sudo rm -f /etc/opensearch/*.pem
   ```
   On Windows, delete the `.pem` files in `C:\opensearch\config` (not in its `certs` folder).
3. Copy the four files in `opensearch/opensearch-security/` into
   `<config>/opensearch-security/`, replacing the ones there (keep a copy of the old ones).
4. Edit `<config>/opensearch.yml`: delete the block from
   `######## Start OpenSearch Security Demo Configuration ########` to
   `######## End OpenSearch Security Demo Configuration ########` if there is one, and any
   other line starting with `plugins.security.`. Then paste in the contents of
   `opensearch/add-to-opensearch.yml`. Leave `network.host` as it is when Signalith runs on
   the same machine (OpenSearch then listens on this machine only).
5. Restart OpenSearch: `sudo systemctl restart opensearch`, or on Windows restart its
   service (or `opensearch.bat`).

### 3. Load the security settings

If OpenSearch ran with its security plugin before, which the demo configuration does, it
keeps its users and roles in an index and does not read the files again. Load them once
with the admin certificate. On Linux:

```sh
sudo env OPENSEARCH_JAVA_HOME=/usr/share/opensearch/jdk \
  bash /usr/share/opensearch/plugins/opensearch-security/tools/securityadmin.sh \
  -cd /etc/opensearch/opensearch-security/ -cacert /etc/opensearch/certs/root-ca.pem \
  -cert /etc/opensearch/certs/admin.pem -key /etc/opensearch/certs/admin-key.pem -h localhost
```

On Windows, in PowerShell (change `C:\opensearch` to where OpenSearch is):

```powershell
$env:OPENSEARCH_JAVA_HOME = "C:\opensearch\jdk"
C:\opensearch\plugins\opensearch-security\tools\securityadmin.bat `
  -cd C:\opensearch\config\opensearch-security\ -cacert C:\opensearch\config\certs\root-ca.pem `
  -cert C:\opensearch\config\certs\admin.pem -key C:\opensearch\config\certs\admin-key.pem -h localhost
```

It ends with `Done with success`. The demo users, `admin` included, are gone from then
on. A new OpenSearch that never ran with its security plugin loads the files by itself on
first start; running this anyway does no harm.

The admin certificate can change every security setting. It is only needed for this
command, so keep `admin-key.pem` somewhere safe rather than on the server.

Check that OpenSearch now refuses everyone without a certificate. Both should print
`401` (on Windows, type `curl.exe` and use the Windows paths):

```sh
curl -s -o /dev/null -w '%{http_code}\n' --cacert /etc/opensearch/certs/root-ca.pem https://localhost:9200/
curl -s -o /dev/null -w '%{http_code}\n' --cacert /etc/opensearch/certs/root-ca.pem -u admin:admin https://localhost:9200/
```

### 4. Point Signalith at it

1. Copy the three `.pem` files in `signalith/` next to `signalith.yaml` and let only
   Signalith read them. On Linux:
   ```sh
   sudo cp opensearch-pki/signalith/opensearch-*.pem /etc/signalith/
   sudo chown signalith /etc/signalith/opensearch-*.pem
   sudo chmod 400 /etc/signalith/opensearch-*.pem
   ```
   On Windows, copy them to `C:\ProgramData\Signalith\`, which `install.ps1` lets only
   Administrators and SYSTEM (the service) read.
2. In `signalith.yaml`, set `opensearch:` as in `signalith/add-to-signalith.yaml`: the
   `https://` URL, `ca_file`, `cert_file` and `key_file`. Remove `username` and `password`
   if they are there. The URL's host must be a name or address the certificate covers;
   `add-to-signalith.yaml` lists them.
3. Run `signalith validate`, then restart Signalith. The **Health** page shows OpenSearch's
   status.

### More nodes under the same CA

For another node of the same OpenSearch cluster, give `-ca-dir` the `ca` folder of the first
run (or that run's `-out` folder), the new node's name, and with `-peer` the names of the
other nodes:

```sh
signalith opensearch-certs -ca-dir opensearch-pki/ca -node search2 -san 10.0.0.6 -peer search1 -out opensearch-pki-search2
```

It writes that node's certificate and the CA's certificate in `opensearch/certs/`, and a
new Signalith client certificate in `signalith/`, all under the same CA; no new admin
certificate (use the first one). `add-to-opensearch.yml` lists every node in
`plugins.security.nodes_dn`; add the new node's name to the other nodes' `nodes_dn` too.
Node names may not be `signalith` or start with `signalith-`: those are for Signalith's own
certificates.

## Snapshot permissions

The `signalith_snapshots` role lets Signalith keep its
[scheduled snapshots](backup.md#scheduled-snapshots) policy, and lets OpenSearch take
and delete the snapshots as Signalith. It names each action it needs (the policy's
`write`, `get`, `delete` and `explain`, and `cluster:admin/snapshot/create`, `get` and
`delete`, with `cluster:admin/repository/get`), so it cannot restore or clone
snapshots. It is not given to Signalith until you want scheduled snapshots (see
[What OpenSearch needs](backup.md#what-opensearch-needs)). Know what it allows:

- **Snapshot rights cover every repository.** OpenSearch cannot limit them to one, so
  Signalith can list, take and delete snapshots in any repository, not only its own.
- **Snapshots that Signalith's credentials can delete do not protect against a
  compromised Signalith.** Copy the repository off-site, or keep it on WORM storage such
  as an S3 bucket with Object Lock (see [Copies elsewhere](backup.md#copies-elsewhere)).
- **Removing the mapping does not stop the snapshots.** OpenSearch runs the policy with
  the roles stored with it when Signalith wrote it. To turn them off, turn **Scheduled
  snapshots** off in the settings, or delete the policy with the admin account
  (`DELETE _plugins/_sm/policies/<opensearch.index_prefix>-daily`), and then remove the
  `signalith_snapshots` mapping.

## OpenSearch's own audit log

Signalith keeps its own audit log of what people do (see [audit.md](audit.md)). OpenSearch
keeps one too, of who tried to reach it: failed sign-ins, requests refused for missing
permissions, TLS and certificate errors, and every change to its security settings.
Successful requests are left out, since they are Signalith's own searches and writes.
These records go to OpenSearch's log rather than an index, so Signalith's certificate,
which can write to the indices, cannot change them.

The Docker quick start, the Helm chart and the files `signalith opensearch-certs` makes
turn it on. To read it:

- Docker: `docker compose -f deploy/docker/docker-compose.yml logs opensearch | grep -i audit`
- Linux: `grep -i audit /var/log/opensearch/*.log`
- Windows: the `logs` folder of the OpenSearch install.

On OpenSearch set up before this, do these two steps in this order.

1. Load Signalith's `audit.yml`. Once the security settings are loaded, OpenSearch takes
   what it logs from `audit.yml` in its `opensearch-security` folder rather than from
   `opensearch.yml`, and the one that comes with OpenSearch logs request bodies. Signalith's
   makes the same choices as the lines below. The Docker quick start and the Helm chart load
   it for you. Without Docker, copy `opensearch/opensearch-security/audit.yml` from the files
   `signalith opensearch-certs` makes into the `opensearch-security` folder and load it with
   `securityadmin.sh -f audit.yml -t audit` (the certificates and host as when you loaded the
   other files). This changes nothing yet while the audit type is still `noop`.
2. Add these lines to `opensearch.yml` in place of `plugins.security.audit.type: noop`, and
   restart OpenSearch:

    ```yaml
    plugins.security.audit.type: log4j
    plugins.security.audit.config.disabled_rest_categories: ["AUTHENTICATED", "GRANTED_PRIVILEGES"]
    plugins.security.audit.config.disabled_transport_categories: ["AUTHENTICATED", "GRANTED_PRIVILEGES"]
    plugins.security.audit.config.log_request_body: false
    plugins.security.audit.config.exclude_sensitive_headers: true
    ```

Loading `audit.yml` first means OpenSearch never logs request bodies, even for a moment.

## Renewing

The CA and the certificates last 10 years. In the Docker quick start, the setup step makes
a certificate again under the same CA when it is within 30 days of expiry; only the CA
itself needs [replacing](#replacing-the-ca) by hand.

Without Docker, make new certificates under the same CA with
`signalith opensearch-certs -ca-dir opensearch-pki/ca -node <name> -out <new folder>` and
repeat steps 2 and 4, then restart OpenSearch and Signalith. Without the `ca` folder, run
`signalith opensearch-certs` into a new folder instead and repeat steps 2 and 4 (step 3
too if you changed the security files): the CA is then new as well.

## Moving to OpenSearch 3.x

The Docker quick start uses OpenSearch 3.9 from Signalith 0.3.0 on; earlier versions used
2.17. Signalith works with both, and the security settings on this page are the same for
each. An OpenSearch 2.17 data volume starts directly on 3.9 and keeps its events, findings
and security settings, so a quick start updated with `git pull` moves on its next `up`.

OpenSearch can't go back to 2.17 on the same data once 3.9 has started on it, so copy the
OpenSearch volume first, from the Signalith folder (PowerShell or a terminal):

```sh
docker compose -f deploy/docker/docker-compose.yml stop
docker run --rm -v docker_opensearch-data:/data -v "${PWD}:/backup" alpine tar czf /backup/opensearch-data-2.17.tgz -C /data .
```

Then update and start as in
[Upgrading the Docker quick start](docker.md#upgrading-the-docker-quick-start).
The step that loads the security settings loads them once more after the move (3.x has no
`whitelist.yml`), which is expected. To stay on 2.17 for now, put the 2.17 image on the
`opensearch` and `opensearch-security` services in an override file and add
`-f deploy/docker/docker-compose.override.yml` to each command:

```yaml
# deploy/docker/docker-compose.override.yml
services:
  opensearch:
    image: opensearchproject/opensearch:2.17.1
  opensearch-security:
    image: opensearchproject/opensearch:2.17.1
```

On OpenSearch installed without Docker, follow OpenSearch's own upgrade steps and keep the
`opensearch.yml` lines from [step 2](#2-put-the-files-in-place-on-the-opensearch-machine).

## Other setups

- **A cluster of several nodes**: make each node's certificate under the same CA (see
  [More nodes under the same CA](#more-nodes-under-the-same-ca)), or use your own CA, list
  every node's certificate subject in `plugins.security.nodes_dn`, and give Signalith a
  client certificate whose common name is `signalith` (or map yours to `signalith_server`
  in `roles_mapping.yml`).
- **Passwords instead of certificates**: Signalith can also sign in with
  `opensearch.username` and `opensearch.password` (or `SIGNALITH_OPENSEARCH_PASSWORD`, or
  `SIGNALITH_OPENSEARCH_PASSWORD_FILE`). It sends them over `https://` only, unless the
  OpenSearch is on the same machine. Give that user the `signalith_server` role from
  `roles.yml` rather than an admin role, and `signalith_snapshots` too for
  [scheduled snapshots](backup.md#scheduled-snapshots).
