# Server settings

Admins change how the server runs on the **Settings** page: the public address,
the web address and certificate, the OpenSearch connection, search limits, syslog,
the detection scheduler, the AI assistant and more, without editing
`signalith.yaml` on the server. Each setting says where its value comes from, and
whether it applies at once or after a restart, which the page does for you.

Users, directory sign-in, agent tokens, threat intel feeds and data retention keep
their own pages; the Settings page links to them.

Only admins see the page (under **Configure**, or type "settings" in the
**Jump to** box with Ctrl+K). Viewers and analysts do not see it, and its API
answers them `403`.

## Using the page

The page has one card per section (General, Web server, HTTPS, OpenSearch,
Search, Syslog, Detections, AI assistant, Threat intel) and **About this server**. On a
wide screen a list of the sections stays on the left; on a phone the sections
are a row of buttons under the top bar that scrolls sideways.

Each setting has its name and what it does. A setting with no note comes from
`signalith.yaml` or the built-in default (an empty box shows what empty means,
such as "When empty: 12h"); the page says so once, at the top. A note shows only
when it tells you something:

- **Changed here by ann, 2h ago**, with **Reset** to take it off the page.
- A lock and **Set by SIGNALITH_…** when an environment variable sets it. The box
  cannot be changed; change the variable where Signalith's environment is set.
- **Set aside**, when a restart could not use a change (see below), with why,
  **Try it again** and **Remove**.

Changes wait until you save them. A bar at the bottom says how many are not
saved yet, with **Discard** and **Save changes**; leaving the page or closing the
tab with unsaved changes asks first. When something cannot be saved, nothing is
saved: each setting with a problem says what is wrong, and the cursor moves to
the first one.

Changes that are hard to undo ask before they are saved, and say what will happen:
a new listen address, OpenSearch address or index prefix, turning HTTPS on or off,
skipping OpenSearch's certificate check, turning the detection scheduler off, and
allowing threat intel feeds from this computer. The server checks the changes
first, so you are only asked about changes that can be saved. When the listen
port or HTTPS changes and the public address still names the old one, the same
question offers to change the public address too, since agents send there. A
listen address on `127.0.0.1` chosen from another computer says plainly that you
could not open the page again from there.

The public address may be left empty: it is then worked out from the listen
address, and the page shows what it works out to. When it is set and does not
match how Signalith answers (`http://` while it serves HTTPS, or another port),
the page warns and offers the matching address with one click. That is right
only behind a proxy or a port forward.

**Proxies and gateways**, in the **Web server** card, lists addresses that stand for
many people, such as a NAT gateway or Docker Desktop's port forwarding. Such an
address is not held to one computer's share of connections, and wrong passwords
from it count against each account instead of pausing sign-ins from the whole
address. For a reverse proxy that sets `X-Forwarded-For` itself, list it under
**Trusted reverse proxies** in the **HTTPS** card instead and choose **Client address
header**, so each person is counted by their own address. See
[failed sign-in limits](users.md#signing-in). Applies after a restart.

Turning syslog on is two settings in the **Syslog** card (UDP and TCP address,
such as `0.0.0.0:514`), then a restart. The **Add data** page's syslog steps send
you there.

**Replicas**, in the **OpenSearch** card, is how many extra copies of each day's
events OpenSearch keeps on its other nodes, so losing one node loses no events. It
is `auto` unless you change it: one copy on another node once OpenSearch has more
than one node, and none while it has just one (where a copy would have nowhere to
go). Enter a number instead to choose yourself, such as `0` for no copies. A change
applies to the next day's events after a restart; days already stored keep the
copies they have. Findings, investigations and threat intel follow the setting too,
from when they are first stored; if they were stored by an older version with no
copy, they get the setting when a server starts running the background jobs.
Copies someone set on them by hand in OpenSearch are kept.

## HTTPS

The **HTTPS** card has how Signalith keeps the web page, the API, agents and syslog
over TLS private (see [HTTPS](https.md)):

- **HTTPS**: Automatic (Signalith's own certificate, the default), your own certificate
  files, or Off, only behind a reverse proxy that serves HTTPS.
- **Extra certificate names**: other names or addresses people and agents use, for the
  automatic certificate.
- **Certificate authority reaches**: standard (this server and private network names,
  the default) or strict (only this server's own names and addresses), for a
  certificate authority Signalith makes. Saving it changes nothing for browsers or
  agents. It is used when you make a new certificate authority on the Security page,
  which then helps you switch to it (see
  [How far the certificate authority reaches](https.md#how-far-the-certificate-authority-reaches)).
- **Certificate file** and **Key file**: used only with your own certificate files. The
  page checks that they load before saving.
- **Agents on plain HTTP**: whether agents set up for `http://` may still send while you
  update them from **Add data**. Applies at once. On a Docker quick start upgraded from an
  older version, choosing **Refuse them** also ends the old example token
  `change-this-ingest-token` for good.
- **Trusted reverse proxies**: the proxies whose `X-Forwarded-Proto` header is believed.
  Applies at once. With this empty, a `signalith.yaml` from before HTTPS was the default
  believes a proxy on this computer or a private network, and the field says so; listing
  one ends that. A list that leaves out the proxy you opened the page through is
  refused, since with HTTPS on that proxy would stop working at once: add it, or make
  the change from a browser that reaches Signalith without the proxy.
- **Client address header**: the header the trusted proxies set to each person's
  address, `X-Forwarded-For` or `Forwarded`. The sign-in limits and the log then use
  that address instead of the proxy's (see [failed sign-in limits](users.md#signing-in)).
  Choose one only if the proxy sets the header itself; for nginx that takes
  `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` (see
  [Behind a reverse proxy](https.md#behind-a-reverse-proxy)). With **None**, everyone
  reaching Signalith through a trusted proxy counts as one shared address. Applies at once.

The rules are those of `signalith.yaml`: your own files need both files, and the files
are refused with the other modes; an `http://` public address is read as `https://`
while HTTPS is on, and the page offers the `https://` one. Certificate files saved on
the page by a version without the **HTTPS** setting, which was then how HTTPS was turned
on, mean your own certificate files, as they do in a `signalith.yaml` without
`server.tls.mode`. A restart keeps the same
certificate authority, so browsers and agents that trust it go on doing so; a public
address saved on the page joins the certificate at once. **In use now**, under the
settings, shows the mode in use, the names the certificate covers and the CA's
fingerprint, with a link to download the CA.

## Where changes are kept

Changes made on the page are written to `settings.yaml` in the lookups folder
(`/var/lib/signalith/lookups/settings.yaml` on Linux,
`C:\ProgramData\Signalith\lookups\settings.yaml` on Windows, the `lookups` volume in
Docker), never to `signalith.yaml`, which is often read-only. Set
`SIGNALITH_SETTINGS_FILE` to keep it somewhere else.

The file holds only the settings changed on the page, each with who changed it and
when, when a restart last checked it (`checked_at`), and for a change a restart set
aside, why (`refused`). Signalith rewrites it whole on every save, through a
temporary file and a rename, readable only by its own account: mode 0600, even
when the file it replaces allowed more (on Windows, only SYSTEM, Administrators,
the service account and the account that saved it). A link put in its place is
replaced by the new file, and the file it pointed to is left as it was, with
whatever it held; `signalith secrets` and the server's log say so. The
OpenSearch password and the AI model's API key saved on the page are kept in it
encrypted with Signalith's master key (`enc:v1:...`, see
[encryption.md](encryption.md)); one kept as plain text, as earlier versions did,
still works and is encrypted when the server next starts. When `signalith settings
reset` runs as root, the new file keeps the owner the old one had (or takes its
folder's), so the service can still read it.

```yaml
settings:
  opensearch.index_prefix:
    value: siem2
    changed_by: ann
    changed_at: 2026-10-12T18:52:32Z
    checked_at: 2026-10-12T18:53:02Z
  server.listen:
    value: 0.0.0.0:443
    changed_by: ann
    changed_at: 2026-10-12T18:55:10Z
    refused: "Signalith cannot listen on 0.0.0.0:443 (bind: permission denied). Signalith kept running with the previous settings. Choose another address or port."
    refused_at: 2026-10-12T18:55:12Z
  opensearch.password:
    secret: enc:v1:9096cd23:zNhdzHvpeSnrdiqQHGOGMRlih2VUzUrwcOjWVF3w4lW1dAVcs-fPcn_nBiPB6wM
    sent_to: https://opensearch.corp.example:9200
    changed_by: ann
    changed_at: 2026-10-12T18:52:32Z
```

## Which value wins

1. An **environment variable**, such as `SIGNALITH_LISTEN` or
   `SIGNALITH_OPENSEARCH_PASSWORD`. The page shows these settings locked, with the
   variable's name: change them where Signalith's environment is set (for example
   `docker-compose.yml` or the service's settings), then restart it.
2. The **Settings page**.
3. **`signalith.yaml`**.
4. The **built-in default**.

Every setting on the page shows which of these its value comes from, and
**Reset** takes it off the page, so `signalith.yaml` or the default applies again.

## Applying changes

Settings marked **applies at once** take effect when you save: the public address,
the sign-out time, the default time range and events per search, the quiet data
source time, the most findings per run, and the AI assistant. A new public address
waits for the restart when the listen address or the certificate also changes, so
agents set up meanwhile are not sent to an address nothing answers yet.

The others are saved and wait for a restart. A banner at the top of the page
names what is waiting (**What changes** lists the value in use and the saved
one) and has a **Restart now** button. While Signalith restarts, the banner
shows its progress; the page reloads when Signalith is back, or moves to the new
address when the web address or HTTPS changed, and you stay signed in (unless
HTTPS was turned on or off: browsers keep sign-ins over `http://` and `https://`
apart, so you sign in again there). If the new settings cannot work, the banner
says why, with a link to the setting to change, and **Try again** is no longer
the main button until something changes. Signalith restarts
itself inside the same process: it stops its components (web handlers, OpenSearch
client, syslog receiver, detection scheduler, feed downloader and the rest) and
builds them again from the saved settings. This works the same under Docker,
systemd, a Windows service or a terminal. People stay signed in, and requests that
arrive during the few milliseconds of the switch wait for it. The server keeps its
identity, and, when it runs the background jobs, keeps running them: they finish
their current step and start again with the new settings. If the restart turns
**Run detections on schedule** off, or moves to another OpenSearch, it hands them to
another server that shares the OpenSearch, if there is one.

### Protection against locking yourself out

The page makes it hard to lock yourself out, though not impossible: a firewall
or a proxy between you and Signalith can still make a working address
unreachable. Keep shell access to the server for the steps below.

Before anything stops, a restart checks that the new settings can work:

- data retention is not deleting, archiving or restoring days right now;
- the files and folders Signalith reads can be read (users, directory sign-in,
  detections, dashboards);
- the certificate and key files load;
- OpenSearch answers with the new connection settings (within 10 seconds);
- the new web address and syslog addresses can be listened on.

If one of these fails, nothing changes: Signalith keeps running with the settings
in use, and the page says what failed. A change that caused it is **set aside**:
it stays in the settings file, marked with why, but is not used, not even when
Signalith next starts, until you **Try it again**, change it or **Remove** it.
Changes that cannot be used without it are set aside with it, such as the
certificate files saved with **HTTPS** set to your own files, so the rest still
work at the next start. The
other changes can then be applied with **Restart now**. If the new
components then fail to start anyway, Signalith goes back to the previous
settings, sets the changes aside, and says so. If even the previous settings
cannot start, the web page stays up to say so, and Signalith tries again every
30 seconds.

When the web address or HTTPS changes, the page moves to the new address, and
Signalith waits up to 2 minutes for an admin to open a page there. Behind a
trusted reverse proxy, turning HTTPS on or off leaves the proxy's address as it
is, so the page stays there, and its next request confirms the change. If nobody
does (the new address cannot be reached from your computer, or a firewall blocks
it), Signalith goes back to the previous address by itself and sets the change
aside. For a move to another port, the old address keeps answering until then.
A listen address on `127.0.0.1` saved from another computer asks once more
before the restart, and is then kept, since only the server can reach it.

Settings saved on the page never keep Signalith from starting. If the settings
file cannot be read, or Signalith cannot start with the settings in it (for
example, the saved web address is taken) but can with `signalith.yaml` alone, it
starts with `signalith.yaml` alone, logs why, and shows it at the top of the
Settings page, on the setting to blame, and in `signalith validate`. An
OpenSearch connection saved on the page but not checked by a restart yet is
checked when Signalith starts: if OpenSearch answers with the settings in
`signalith.yaml` but not with the page's, those are set aside.

### If you are locked out anyway

On the server, with the file the service uses. On Linux, the service's unit
points the lookups folder at `/var/lib/signalith`. `signalith settings` and
`signalith validate` read the folders the service is given from its unit
(`systemctl show signalith`, as `signalith secrets` does) when it runs with the
same config file, and say so, so they find its file by themselves:

```
sudo signalith settings list  -c /etc/signalith/signalith.yaml
sudo signalith settings reset -c /etc/signalith/signalith.yaml server.listen
sudo signalith settings reset -c /etc/signalith/signalith.yaml   # every change
sudo systemctl restart signalith
```

Where the unit cannot be read (no systemd, or another config file), give the
file with `-file`, which always wins:

```
sudo signalith settings reset -c /etc/signalith/signalith.yaml -file /var/lib/signalith/lookups/settings.yaml server.listen
```

`list` shows what was changed on the page, by whom and when, and what was set
aside. Passwords and keys are never printed. When there is no settings file
where the command looks, it says so and names the service's file if it finds
one; it never claims to have reset anything. A file that cannot be read is kept
as `settings.yaml.broken` when `reset` starts a new one. `signalith validate`
takes `-file` too.

On Windows (PowerShell as administrator):

```
signalith settings reset server.listen
Restart-Service Signalith
```

In Docker, see below.

## Docker

In the quick start (`deploy/docker/docker-compose.yml`), `signalith.yaml` is
mounted read-only, and the page keeps its changes in the `signalith-data` volume.

- The page's file is `/var/lib/signalith/lookups/settings.yaml`, in the
  `signalith-data` volume with Signalith's own certificate authority (`tls`) and
  master key (`keys`), so changes survive updates and `docker compose down`.
- Only settings set in the compose file's `environment:` are locked on the page.
  In the quick start that is the public address, once you uncomment
  `SIGNALITH_PUBLIC_URL`, and the OpenSearch password or the AI model's API key if
  you add a `SIGNALITH_..._FILE` variable for one (the admin password and ingest
  token it reads from files are not page settings). Change them in
  `docker-compose.yml`, then `docker compose -f deploy/docker/docker-compose.yml up -d`.
- The listen address, the OpenSearch connection and the other settings come from
  the read-only `deploy/docker/signalith.yaml`, so they can be changed on the page,
  and the page's value wins. Change the OpenSearch settings only if you run
  OpenSearch somewhere else: the quick start's own OpenSearch is set up for the
  client certificate in `signalith.yaml`.
- A port Signalith listens on inside the container only reaches it when the
  compose file publishes it under `ports:`. The quick start publishes 8080 (web),
  514 to the container's 5514 (syslog over UDP and TCP) and 6514 (syslog over
  TLS). If you change the listen port or a syslog address on the page, add the
  port to `ports:` too (and for syslog set **Port devices send to** to the port on
  the host). The page reminds you on those settings when it runs in a container.
- To undo a change from the command line:

```
docker compose -f deploy/docker/docker-compose.yml exec signalith signalith settings list
docker compose -f deploy/docker/docker-compose.yml exec signalith signalith settings reset server.listen
docker compose -f deploy/docker/docker-compose.yml restart signalith
```

## Passwords and API keys

The OpenSearch password and the AI assistant's API key are never shown or sent back
to the browser; the page only says whether one is set.

- One saved on the page shows as **Saved encrypted, hidden**, and one from
  `signalith.yaml` as **Saved, hidden**. **Replace** opens a box to type a new one
  (**Keep saved** closes it again), and **Remove** removes it when you save.
- One saved on the page that cannot be decrypted (the master key it was saved with
  is not there) is not used: its field says so, with what to do. Enter it again,
  or restore that master key. When OpenSearch refuses Signalith without it, a
  restart says why and sets none of the page's settings aside.
- A password is only ever sent to the address it was entered for (its scheme, host
  and port). To point Signalith at another OpenSearch or AI provider, enter the
  password or key again, or clear it; the page refuses to save otherwise. A password
  from `signalith.yaml` or the environment is likewise only sent to the address set
  there.
- An address with a user name and password in it (`http://user:pass@host`) or a
  key in its query is refused on the page: put them in their own fields. One that
  comes from `signalith.yaml` is shown, logged and exported without it.

**Test connection** checks OpenSearch with the values on the form, saved or not,
and says plainly what is wrong: nothing answers, wrong password, a certificate that
is not trusted, HTTP on an HTTPS port, or not an OpenSearch at all. It also says when
the problem is OpenSearch itself, so that no setting here would fix it: its security
settings aren't loaded, it is too busy, or it took the request but didn't answer in time.
[When this server can't use OpenSearch](servers.md#when-this-server-cant-use-opensearch)
says what to do about each. **Test** for the
AI assistant asks the model one fixed question ("failed logins in the last 24
hours") and shows the query it wrote. A result is marked out of date as soon as
one of the settings it used changes.

## Exporting settings

**Download settings as YAML**, in **About this server**, downloads the page's
settings in the format of `signalith.yaml`, for a second server or a backup.
Passwords and keys are left out, and settings that belong to this server only (its
addresses and certificate files) are marked. A public address worked out from the
listen address is left empty, so the other server works out its own.

**About this server** also shows the version, platform and how long Signalith has
been running, where its files and folders are, and **Reset all**, which takes every
change off the page.

## Not on this page

| Setting | Where instead |
| --- | --- |
| `retention.days` | The data retention page. |
| `auth.admin_user`, `auth.admin_password_hash` | `signalith.yaml` and `signalith passwd` only: the built-in admin is the break-glass account, so no page can lock everyone out. |
| `auth.ldap` | The Users page sets up directory sign-in. |
| `auth.users_file`, `intel.feeds_file`, `notify.file`, `playbooks.file`, `detections.dir`, `dashboards.dir`, `lookups.dir` | `signalith.yaml`: pages save into these files and folders, and the lookups folder holds the Settings page's own file. The page shows where they are. |
| `ingest.tokens` | Shared agent tokens from older setups and the Docker quick start: `signalith.yaml` (`ingest.tokens`) or `SIGNALITH_INGEST_TOKEN` (`SIGNALITH_INGEST_TOKEN_FILE` in Docker). New agents get their own token on **Add data**, under **Agent tokens**, where shared tokens can also be retired; see [agent-tokens.md](agent-tokens.md). The page shows how many tokens are active and how many shared tokens are still accepted. |
| `intel.feeds` | The Threat intel page. |

## Audit log

Every save, test and restart is logged with `audit=true`, who did it and from which
address. Values of settings are logged; passwords and keys never are (they show as
`(changed)` or `(none)`).

| Message | Fields |
| --- | --- |
| `settings saved` | `by`, `client`, `changes` (`key=value` pairs), `reset`, `cleared`, `retried`, `reset_all`, `applied_now`, `after_restart`, `file`, `backup` |
| `settings tested` | `by`, `client`, `what` (`opensearch` or `assistant`), the address, `ok` |
| `restart requested` | `by`, `client`, `pending`, `local_only` |
| `restarted with the saved settings` | `by`, `client`, `settings`, `took_ms` |
| `restart failed` | `by`, `client`, `settings`, `rolled_back`, `set_aside`, `reason` |
| `new web address confirmed` | `by`, `client`, `host` |
| `went back to the previous web address` | `settings`, `reason` |

Addresses are logged without any password in them.

```
level=INFO msg="settings saved" audit=true by=ann client=10.0.0.12 changes="opensearch.index_prefix=siem2 opensearch.password=(changed) search.max_events=5000" applied_now=search.max_events after_restart=opensearch.password,opensearch.index_prefix
level=ERROR msg="restart failed" audit=true by=ann client=10.0.0.12 settings=server.listen rolled_back=false reason="Signalith cannot listen on 0.0.0.0:443 (bind: permission denied). Signalith kept running with the previous settings. Choose another address or port."
```

## API

Every route is for admins. Requests from a browser that change something must come
from the Signalith page itself.

| Route | What it does |
| --- | --- |
| `GET /api/settings` | Every setting by section, with its value, source, whether it is locked, applies at once or after a restart, and is waiting for one; what is waiting; the last restart; paths and version |
| `PUT /api/settings` | Saves changes: `{"values": {key: value}, "clear": [keys], "reset": [keys], "retry": [keys], "reset_all": false}`. With `"check_only": true` it saves nothing and answers `{"ok": true, "changed": [...], "confirm": [...]}`: what to ask before saving |
| `POST /api/settings/test/opensearch` | Tests OpenSearch with `{"values": {...}}` over the saved settings; one test at a time (`429` `busy` otherwise) |
| `POST /api/settings/test/assistant` | Tests the AI assistant the same way |
| `POST /api/settings/restart` | Restarts with the saved settings; answers 202 at once. `409` with `code` `restarting`, `awaiting` (a move waits for confirmation), `settings_invalid`, or `local_only` (send `{"local_only": true}` to go ahead) |
| `POST /api/settings/restart/confirm` | From the new address after a move: confirms it (`GET /api/me` by an admin does too) |
| `GET /api/settings/export` | `{"yaml": "...", "filename": "signalith-settings.yaml"}`; `?download=1` downloads the file |

One setting in `GET /api/settings`:

```json
{"key": "opensearch.password", "label": "Password", "type": "secret",
 "help": "Only sent to the address it was entered for.",
 "value": null, "set": true, "sent_to": "https://opensearch.corp.example:9200",
 "source": {"kind": "page", "by": "ann", "at": "2026-10-12T18:57:24Z"},
 "env": "SIGNALITH_OPENSEARCH_PASSWORD", "locked": false,
 "apply": "restart", "dangerous": false, "pending": true,
 "reset_to": {"value": null, "set": false, "source": "default"}}
```

A save with problems saves nothing and answers 400 with each problem by setting:

```json
{"error": "Nothing was saved. Fix the settings marked below.",
 "fields": {"server.listen": "Must be host:port, for example 0.0.0.0:8080",
            "server.tls_cert": "Enter the full path of your certificate file."},
 "problems": []}
```

A restart answers at once, then `GET /api/settings` shows how it went under
`restart.last`:

```json
{"restarting": true, "pending": ["server.listen"], "listen_changed": true,
 "new_listen": "0.0.0.0:9443", "go_to": "https://siem.corp.example:9443/"}
```

```json
{"available": true, "in_progress": false, "needed": true,
 "last": {"at": "2026-10-12T18:54:45Z", "by": "ann", "ok": false, "keys": ["opensearch.url"],
          "error": "OpenSearch did not answer with the new settings: Nothing answered at 10.0.0.9:9200. Check that OpenSearch is running, and the address and port. Signalith kept running with the previous settings.",
          "took_ms": 1}}
```

While the components are being switched, a request that waits more than 30 seconds
is answered `503` with `{"code": "restarting"}` and `Retry-After: 5`.
