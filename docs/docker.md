---
description: Run Signalith and OpenSearch with Docker Compose, run a release or your own build, and upgrade an older quick start.
---

# Docker quick start

The Docker quick start runs OpenSearch and Signalith on one computer with Docker Compose.
It is the quickest way to try Signalith, and it suits labs and small sites. To run
Signalith as a service on a server instead, see [Install from packages](install-packages.md)
or [Kubernetes](kubernetes.md).

## Start it

It needs Docker Compose 2.20 or newer (Docker Desktop has it). Check with
`docker compose version`; on Linux, update the `docker-compose-plugin` package if it is
older. Get the code with
`git clone https://github.com/jrsamsanchez/Signalith.git` and, from the `Signalith`
folder it makes, run:

```sh
docker compose -f deploy/docker/docker-compose.yml up -d
docker compose -f deploy/docker/docker-compose.yml exec signalith signalith initial-password
```

The first command downloads Signalith's ready-made image from GitHub
(`ghcr.io/jrsamsanchez/signalith`) and starts OpenSearch and Signalith. On first start a setup step makes the
admin password, a shared agent token and the certificates OpenSearch and Signalith use
with each other, and keeps them in Docker volumes; no password is written in the compose
files. Once OpenSearch is up, a second step loads OpenSearch's security settings (who may
sign in, and what each may do), and Signalith starts after it. If the first command ends
with `service "opensearch-security" didn't complete successfully`, see
[If OpenSearch's security settings aren't loaded](opensearch-security.md#if-opensearchs-security-settings-arent-loaded).
The second command shows the admin password. Open https://localhost:9000 and sign
in as `signalithadmin` with it; since Signalith made that password, you then choose your own
before anything else. Signalith serves HTTPS with a certificate it makes for itself, so
the browser warns until you trust it; the sign-in page has a **Download the server
certificate** link, and [HTTPS](https.md) says how to trust it.

Agents get their configuration from the **Add data** page: they send over HTTPS, and each
group of agents gets its own token when you copy or download its configuration. A new
install refuses events sent over plain `http://`, and refuses `change-this-ingest-token`,
the example token older versions gave every agent.

The token the setup step made (`ingest-token` in the `signalith-secrets` volume, passed in
as `SIGNALITH_INGEST_TOKEN_FILE`) is a **legacy shared token**: every agent set up with it
uses the same secret. It is kept so agents set up before per-agent tokens keep working.
To switch, give those agents a new configuration from **Add data**, then, under **Agent
tokens**, choose **Stop accepting** on the shared token. That's all: you don't need to
edit `docker-compose.yml`, and the Security page counts the token as retired. On a new
install no agent has it, so you can choose **Stop accepting** straight away. See
[Replace a shared token](agent-tokens.md#replace-a-shared-token).
Coming from an older version? See
[Upgrading the Docker quick start](#upgrading-the-docker-quick-start).

Ports 9000 (the web page) and 7779 (agents) are open on every network this computer is
on, and so is 6514 for syslog over TLS. Plain syslog on port 514 is unencrypted and can be
forged, so nothing answers there until you turn it on (**Add data** > **Syslog**, **Turn on
plain syslog**). To take agents and browsers from one network only, put this computer's address on that
network in front of each in `docker-compose.yml`, for example `- "192.168.1.20:9000:9000"`
and `- "192.168.1.20:7779:7779"`, then run the first command again.

OpenSearch runs with its security plugin on: it answers only over HTTPS, publishes no
port, and lets in only Signalith's certificate, which may use only Signalith's own
indices. See [Securing OpenSearch](opensearch-security.md).

To change the admin password (the first one then stops working):

```sh
docker compose -f deploy/docker/docker-compose.yml exec signalith signalith passwd
docker compose -f deploy/docker/docker-compose.yml restart signalith
```

Settings changed on the **Settings** page are kept in the `signalith-data` volume
(`/var/lib/signalith/lookups/settings.yaml` in the container), with Signalith's own
certificate authority, so they survive updates; settings given in `docker-compose.yml`'s
`environment:` show there locked.

To update, run `git pull` and then the first command again. It downloads the Signalith
image built from the newest code each time. If `git pull` says your local changes to
`deploy/docker/signalith.yaml` would be overwritten, run `git stash` and `git pull` again.
If the change you had made there was `plaintext_ingest: deny`, add that line back under
`mode: auto`, indented the same, before you run the first command; otherwise agents on
plain `http://` and the old example token may be accepted again. After a reboot
everything starts again by itself once Docker is running; in Docker Desktop turn on
Settings > General > "Start Docker Desktop when you sign in". If the computer restarted
while the first command was still waiting for the step that loads OpenSearch's security
settings, Signalith had not started yet and does not start by itself: https://localhost:9000
doesn't answer. Run `docker compose -f deploy/docker/docker-compose.yml up -d` again then.

## If an update gets stuck

Signalith stops within a few seconds when an update replaces it, and Docker stops it by
force after 90 seconds at most. If the first command stays at `Container
docker-signalith-1 Stopping` for longer than that, and `docker kill docker-signalith-1`
doesn't help either, Docker itself is stuck, not Signalith. On Windows, quit Docker Desktop
(right-click its icon by the clock, **Quit Docker Desktop**), run `wsl --shutdown` in
PowerShell, start Docker Desktop again and run the first command again. Your data is kept.
If `wsl --shutdown` hangs too, restart the computer, or end WSL in PowerShell run as
administrator with `taskkill /F /IM wslservice.exe`, then start Docker Desktop again.

This happens most when the computer is short of memory: OpenSearch alone uses about 1.5 GB.
To keep Docker from taking all of it, give WSL a fixed share in `%UserProfile%\.wslconfig`
(make the file if there is none), for example on a computer with 16 GB:

```ini
[wsl2]
memory=6GB
```

then run `wsl --shutdown` and start Docker Desktop again. Signalith with OpenSearch needs
at least 4 GB there.

## Running a release, or building the image yourself

The quick start runs the image GitHub builds from `main`, which matches the code `git pull`
gives you. To run a release instead, check out its tag and set `SIGNALITH_VERSION` to the
same version before the first command, for example in PowerShell:

```powershell
git checkout v0.3.0
$env:SIGNALITH_VERSION = "0.3.0"
docker compose -f deploy/docker/docker-compose.yml up -d
```

(in a Linux or macOS terminal: `export SIGNALITH_VERSION=0.3.0`). To build the image
from the code you checked out, for example to try a change of your own, add
`-f deploy/docker/docker-compose.build.yml` after the first `-f` in every command:

```sh
docker compose -f deploy/docker/docker-compose.yml -f deploy/docker/docker-compose.build.yml up -d
```

## Upgrading the Docker quick start

From 0.3.0 on, the quick start runs OpenSearch 3.9 instead of 2.17. Your data moves over
by itself on the next start, but OpenSearch can't go back to 2.17 afterwards, so copy the
OpenSearch volume first as in
[Moving to OpenSearch 3.x](opensearch-security.md#moving-to-opensearch-3x).

Earlier versions of the quick start served plain HTTP, ran OpenSearch without security,
and took the admin password and ingest token from `docker-compose.yml`
(`change-me-please` and `change-this-ingest-token` unless you changed them). To upgrade,
in the folder you cloned Signalith into (PowerShell or a terminal, the commands are the
same):

1. Put your own edits aside and update:
   ```sh
   git stash
   git pull
   ```
   `git stash` keeps what you changed (such as the admin password in
   `docker-compose.yml`, which is no longer needed); `git stash show -p` shows it later.
2. Start it as usual:
   ```sh
   docker compose -f deploy/docker/docker-compose.yml up -d
   ```
   This downloads the new Signalith image, runs the setup step once, restarts OpenSearch with its
   security plugin on, and then runs the step that loads OpenSearch's security settings;
   Signalith starts after that. The first start takes a minute or two longer, and up to
   about 10 minutes on a slow computer, where that step keeps trying while OpenSearch is
   slow. Events, findings, investigations, users, detections and dashboards are kept: they
   are in the `opensearch-data` and `signalith-data` volumes, which stay. If the command
   ends with `service "opensearch-security" didn't complete successfully`, or the
   **Servers** page later says OpenSearch's security settings aren't loaded, follow
   [If OpenSearch's security settings aren't loaded](opensearch-security.md#if-opensearchs-security-settings-arent-loaded).
3. Show the new admin password:
   ```sh
   docker compose -f deploy/docker/docker-compose.yml exec signalith signalith initial-password
   ```
   The old one no longer works. People you added on the **Users** page keep theirs.
4. Open **https**://localhost:9000 (old `http://` bookmarks are redirected) and sign in as
   before: `admin` on an install made before 0.3.1, `signalithadmin` on a newer one. You are asked to choose your own password before anything else (an install
   that still uses the first password Signalith made is asked once, after any upgrade,
   however often it was used before). Trust the certificate as described in [HTTPS](https.md).
5. Update the agents. Agents you set up before keep sending for now: on its first start
   Signalith sees that OpenSearch already holds events from before the upgrade, so it
   still accepts agents over plain `http://`, with the old example token. (A new install
   refuses both. Signalith decides this once and keeps the answer, so events stored later,
   such as sample data, never change it.) The **Health** page lists each agent still
   sending over plain `http://` (behind Docker Desktop they share one address, so it names
   them by the computer names in their events). On each of them, install the configuration
   from the **Add data** page again; it gives the agent a token of its own and moves it to
   HTTPS. Syslog devices need no change. If you had set a token of your own in
   `SIGNALITH_INGEST_TOKEN`, add that line back under `environment:` of the `signalith`
   service in `docker-compose.yml` and run step 2 again; new agents still get their own
   token.
6. If you had changed other things, such as ports or `SIGNALITH_PUBLIC_URL`, make the same
   changes in the new files (`SIGNALITH_PUBLIC_URL` now starts with `https://`).
7. Once the **Health** page lists no agent still sending over plain `http://`, set
   **Agents on plain HTTP** to **Refuse them** on the **Settings** page (the **HTTPS**
   card; it applies at once). That also ends the old token for good: it stays refused even
   if you accept agents on plain HTTP again later. An agent you missed is turned away until
   it gets a new configuration; it keeps its events and sends them then, and Health names
   it. Until then the **Security** page shows the old token as a risk.

## Upgrading to 0.3.1: syslog over TLS only

A new install takes syslog over TLS (port 6514) only: plain syslog over UDP and TCP 514 is
unencrypted and can be forged, so it is off until you turn it on. An upgrade keeps plain
syslog as it was, so devices that send to port 514 need no change: package, Windows and
hand-made installs keep their `signalith.yaml`; a Docker quick start that was set up before
keeps it on although the new `signalith.yaml` has it off (decided once, at its first start
with this version, and noted in `plain-syslog.json` in the `signalith-data` volume); and a
Helm upgrade keeps it when the release's syslog Service takes port 514. Once every device
sends over TLS, turn plain syslog off on the **Settings** page (Syslog), or with
`server.syslog.plain=false` on Helm.

## Upgrading to 0.3: the agent port

From 0.3 agents send to a port of their own, 7779, and the web page of a new install is on
port 9000.
In the Docker quick start, `git pull` and the first command bring files that publish
9000 and 7779 and set `server.agent_listen`: open https://localhost:9000 after the
update, and set up each agent again from **Add data**: agents set up before send to port
8080, which the quick start no longer publishes.

A server set up by hand, from packages or with the installers keeps its web port (such as
8080), since it is in its `signalith.yaml`. It also listens on port 7779, and keeps taking
agents on the web port, with a warning in the log for each one, so nothing stops. Then:

1. Allow port 7779 through the firewall, and through any load balancer in front of the
   servers.
2. Set up each agent again from **Add data**: its new configuration sends to port 7779.
3. Set `server.agent_listen` (for example `0.0.0.0:7779`) so the web port stops taking
   agents. The next release stops taking agents on the web port anyway.

See [The agent port](sending-data.md#the-agent-port).

This version encrypts the passwords and keys it keeps in the `signalith-data` volume
(`directory.json`, `intel_feeds.yaml` and `settings.yaml`), which older versions cannot
read. Before going back to one, run `secrets decrypt` in a container of its own (see
[Going back to an older version](encryption.md#going-back-to-an-older-version), which has the
Docker commands).
