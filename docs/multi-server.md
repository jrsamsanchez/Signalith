# Adding servers

Several Signalith servers can share one OpenSearch: they share their settings, users,
detections and dashboards, take turns running the background jobs, and keep working when
one of them stops. [Servers](servers.md) explains how they work together. This page is about
adding one.

The short version: on the Servers page, click **Add a server**, pick what you are adding
and where it runs, and run the line it gives you on the new computer. The dialog checks first that
OpenSearch is ready for a second server, and says what to change if it isn't.

## What a new server needs

- **The same OpenSearch, over the network.** Every server keeps its events in one
  OpenSearch, so the new computer must reach it: not at `127.0.0.1`, and not at a name only
  Docker's own network knows. It must use **TLS and a sign-in** (a password or a client
  certificate), because a second server is never added to an OpenSearch anyone on the
  network could read. [Prepare OpenSearch](#prepare-opensearch) below makes it so.
- **Ports.** The new server reaches OpenSearch (TCP 9200 by default). The other servers
  reach the new one on its web port (TCP 9000 by default), to check it is ready and to hand
  it work. Agents send to it on its agent port (TCP 7779 by default, see
  [The agent port](sending-data.md#the-agent-port)), and devices on its syslog ports (6514 for syslog over TLS,
  and 514 when plain syslog is turned on).
- **The same version.** Every server runs the same version of Signalith. The line installs
  that version, or checks the one already installed.
- **Linux** with systemd (Debian, Ubuntu, RHEL, Rocky, Alma, Fedora, SUSE), **Windows**
  Server 2019 or later or Windows 10 or 11, or **Docker**.
- **Clocks in sync** (NTP, or Windows Time). The Servers page shows each server's offset.

## Add a server

1. On the **Servers** page (Settings > Servers), click **Add a server**, and pick what you
   are adding (see [Cluster servers and scanners](#cluster-servers-and-scanners)):
   - **Cluster server**: shares the work of the other servers.
   - **Vulnerability scanner**: a server inside a network zone that only scans it.
   - **Network sensor**: Zeek and Suricata on a mirror port. It isn't a Signalith server, so
     the dialog takes you to its setup on Add data ([Network sensor](network-sensor.md)).
2. The dialog checks what a new server needs from this one. If OpenSearch isn't ready, do
   the steps under **Prepare OpenSearch** first and save the **Address for new servers**.
3. Pick where the new server runs, **Linux**, **Windows** or **Docker**, and click **Make
   the line**.
4. Run the line on the new computer (below). The dialog follows it live: the token used,
   the server started, and this server reaching it. When it says the server **joined and is
   ready**, it is in the list of servers.

### Cluster servers and scanners

Both join the same way, with the same line, and both share this OpenSearch, the settings and
the users. What they are for differs, and the Servers page shows a **Scanner** badge on each
scanner:

- A **cluster server** takes events from agents and devices, answers searches, and may run
  the background jobs (detections, threat intel downloads, notifications, playbooks and
  retention), taking them over when another server stops. Put it behind your load balancer.
- A **scanner** scans the networks picked for it on the Vulnerabilities page, from inside
  their zone (see [Vulnerabilities](vulnerabilities.md#scanning-each-network-zone-from-inside-it)),
  and never runs the background jobs. Agents and devices don't send to it, so only its web
  port must be open, for the other servers to check it.

The join token carries the choice, and the new server keeps it as its **Server role**
(`cluster.role: scanner` in its settings). Change it later on that server's settings, under
Detections; it applies after a restart. If only scanners are left running, no server runs
the background jobs.

The line holds a **join token** that works **once, for 60 minutes**. Anyone who has it can
add a server to your cluster, so don't post it anywhere. Your shell may keep the line in its
history: the one use and the 60 minutes limit what that copy is worth. Close the dialog, and
the line is gone from the page; a new one takes a click.

### Linux

In a terminal on the new computer. It asks for your sudo password:

```sh
f=$(mktemp) && curl -fsSk --proto '=https' https://siem-a:9000/api/cluster/join/install.sh -o "$f" \
  && echo "<script's SHA-256>  $f" | sha256sum -c --quiet \
  && echo 'SJ1....' | sudo sh "$f" --from https://siem-a:9000 --version 1.5.0 --sha256 <program's SHA-256> --join -
```

The line downloads the install script from your server and checks its SHA-256 before running
it. The token goes to the script on its standard input, so it never shows in the list of
running programs other users of the computer can see. The script ([deploy/linux/install.sh](https://github.com/jrsamsanchez/Signalith/blob/main/deploy/linux/install.sh)):

1. Checks the computer: root, systemd, the processor (amd64 or arm64).
2. Finds the program. When the `signalith` .deb or .rpm package is installed, it uses the
   package as it is, and stops if its version is not the cluster's (upgrade the package
   first; the token isn't used until the join succeeds). Otherwise it downloads the
   program from your server, when that server is a Linux computer with the same processor,
   checks its SHA-256, and installs it as `/usr/local/bin/signalith`, with the `signalith`
   account, `/etc/signalith`, `/var/lib/signalith` and the systemd unit.
3. Runs `signalith join`, which checks the token with your server, checks from the new
   computer that it can reach and sign in to OpenSearch, and only then writes anything. It
   starts the service.

When your server runs Windows (or another processor), it can't hand out the Linux program:
install the [package](install-packages.md) of the same version on the new computer first,
then run the line.

### Windows

In PowerShell opened with **Run as administrator** on the new computer. The line works in
Windows PowerShell 5.1 and PowerShell 7. It downloads
[install.ps1](https://github.com/jrsamsanchez/Signalith/blob/main/deploy/windows/install.ps1)
from your server, checks its SHA-256, and runs it with `-Join`: it installs the program
(downloaded from a Windows server of the cluster, or the one the .msi installed), sets up
the service and its folder permissions, runs `signalith join`, opens the firewall for the
web, agent and syslog ports, and starts the service.

When your server runs Linux, install the [.msi](install-packages.md) of the same version on
the new computer first, then run the line, or run it from the .msi's folder yourself:

```powershell
cd "C:\Program Files\Signalith"
.\install.ps1 -Join 'SJ1....'
```

### Docker

On the new computer, with Docker and a copy of the Signalith folder
(`git clone https://github.com/jrsamsanchez/Signalith`):

1. Save the lines the dialog gives as `deploy/docker/join.env`. Set `SIGNALITH_NODE_URL` to
   this computer's address, such as `https://192.168.1.21:9000` (its web port), so the other servers can
   reach it (a container can't know it), and `SIGNALITH_NODE_NAME` to a name of your choice.
2. Start it:

   ```sh
   docker compose -f deploy/docker/docker-compose.server.yml --env-file deploy/docker/join.env up -d
   ```

[docker-compose.server.yml](https://github.com/jrsamsanchez/Signalith/blob/main/deploy/docker/docker-compose.server.yml)
runs Signalith alone, with the same hardening as the quick start. On its first start it
joins with the token in `SIGNALITH_JOIN` and saves everything in its data volume. Later
starts ignore the token: delete that line from `join.env` once the server is on the Servers
page. If the join fails, the container stops with the reason in its log
(`docker compose -f deploy/docker/docker-compose.server.yml logs signalith`).

## Prepare OpenSearch

The dialog shows these steps, filled in with your addresses, when OpenSearch isn't ready.
Do them once, on the computer OpenSearch runs on. Nothing is reindexed, and the first server
keeps running.

### Docker quick start

The quick start's OpenSearch already uses TLS and client certificates, but it listens only
inside Docker. In the Signalith folder, with your computer's address in place of
`192.168.1.20`:

1. Add the address to OpenSearch's certificate, so new servers can check it is your
   OpenSearch they reach:

   ```sh
   docker compose -f deploy/docker/docker-compose.yml run --rm setup bootstrap-docker -opensearch-name 192.168.1.20
   ```

2. Open OpenSearch's port to other computers: add the line `COMPOSE_PROFILES=cluster` to
   `deploy/docker/.env` (make the file if there is none). It turns on the `opensearch-port`
   service, which passes connections to OpenSearch on as they are (TLS and the client
   certificate still run between each server and OpenSearch), and keeps it on for every
   later `up`.
3. Start it, and restart OpenSearch to use its new certificate:

   ```sh
   docker compose -f deploy/docker/docker-compose.yml up -d
   docker compose -f deploy/docker/docker-compose.yml restart opensearch
   ```

4. In the computer's firewall, allow TCP 9200 from the new servers only.
5. In the dialog, save the **Address for new servers**: `https://192.168.1.20:9200`.

To publish it on one network only, put `SIGNALITH_OPENSEARCH_PORT=192.168.1.20:9200` in the
same `.env` file.

### Linux and Windows

1. **Security.** If OpenSearch runs with its security plugin off, or with the package's demo
   certificates, turn it on first, as [Securing OpenSearch](opensearch-security.md)
   explains. If it runs with certificates `signalith opensearch-certs` made, make it a
   certificate that covers the new address, under the same CA, and put the new node files in
   place of the old:

   ```sh
   signalith opensearch-certs -ca-dir <first output folder> -san 192.168.1.20 -out <new folder>
   ```

2. **Listen on the network.** In `opensearch.yml` set
   `network.host: ["_local_", "192.168.1.20"]`. On Linux, OpenSearch then checks the memory
   map limit, so raise it and keep it after a reboot:

   ```sh
   sudo sysctl -w vm.max_map_count=262144
   echo vm.max_map_count=262144 | sudo tee /etc/sysctl.d/90-opensearch.conf
   sudo systemctl restart opensearch
   ```

   On Windows, restart the OpenSearch service.
3. **Firewall.** Allow TCP 9200 from the Signalith servers only, one rule per server:

   ```sh
   sudo ufw allow from 192.168.1.21 to any port 9200 proto tcp
   # or, with firewalld:
   sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=192.168.1.21 port port=9200 protocol=tcp accept'
   sudo firewall-cmd --reload
   ```

   ```powershell
   New-NetFirewallRule -DisplayName "OpenSearch from Signalith" -Direction Inbound -LocalPort 9200 -Protocol TCP -RemoteAddress 192.168.1.21 -Action Allow
   ```

4. **Address for new servers.** Save `https://192.168.1.20:9200` in the dialog (it is the
   **Address for new servers** setting, `cluster.opensearch_url`, on the Settings page).

## Approving a server

A server started with the cluster's OpenSearch settings but without a token (or a cluster
key) waits to join. It shows a fingerprint on its sign-in page and in its log, and the
Servers page lists it under **waits to join**. Compare the fingerprint the page shows with
the one on the new server, then click **Approve**: only then does it get the cluster key.

## Automation

For servers set up by a script or image, without the dialog:

- `signalith cluster token` makes a token and prints the same lines (see
  [signalith cluster](cluster-cli.md)).
- The install scripts take the token and the other values as options:
  `sudo sh install.sh --join - [--name siem-c] [--node-url https://10.0.0.7:9000] < token.txt`
  (`--join -` reads the token from the standard input) and
  `.\install.ps1 -Join 'SJ1....' [-Name siem-c] [-NodeUrl https://10.0.0.7:9000]`.
  Each release also carries `install.sh` and a Windows zip with `signalith.exe` and
  `install.ps1`, covered by its checksums.
- A cluster key file still works too: see [Adding a server by hand](servers.md#adding-a-server-by-hand).

## What the join writes, and where

| | Linux | Windows | Docker |
|---|---|---|---|
| Program | `/usr/bin/signalith` (package) or `/usr/local/bin/signalith` | `C:\Program Files\Signalith\signalith.exe` | the image |
| Config | `/etc/signalith/signalith.yaml` | `C:\ProgramData\Signalith\signalith.yaml` | `signalith.yaml` in the data volume |
| Settings from the cluster (OpenSearch's address, sign-in, CA, the listen and node addresses) | `/var/lib/signalith/lookups/settings.yaml` | `C:\ProgramData\Signalith\lookups\settings.yaml` | the data volume |
| Cluster key, master key, HTTPS certificate, identity (`node.id`) | `/var/lib/signalith` | `C:\ProgramData\Signalith` | the data volume |

Settings the join saves are page settings: they show on the new server's Settings page, and
an environment variable still overrides them. Every file belongs to the service's account
(`signalith` on Linux, `NT SERVICE\Signalith` on Windows), and keys are readable by it alone.

## When something goes wrong

`signalith join` (which the lines run) stops with one plain message and an exit code:

| Exit code | What happened | What to do |
|---|---|---|
| 2 | The token was refused: wrong, used or expired. | Make a new line in the dialog. |
| 3 | The server at the token's address doesn't have the certificate the token names. Someone may be intercepting the connection, or the token belongs to another cluster. | Check the address the new computer reaches, and that nothing in between changes HTTPS. |
| 4 | The new computer is not ready: it can't reach OpenSearch, OpenSearch's certificate doesn't cover its address, the sign-in is refused, the web port is taken, or its clock is off. Nothing was written. | Fix what the message says. The token is used up, so make a new line. |
| 5 | The join could not save its files, and undid what it wrote. | The message names the file; check the disk and its permissions. |
| 6 | It joined, but the service did not start. | `sudo journalctl -u signalith -n 50`, or the Windows event log. |

In the dialog, after the join:

- **is running, but this server can't reach it**: open the new server's web port (TCP 9000
  by default) to the other servers, in its firewall and any in between.
- **joined, but the other servers can't check it**: give it its address for the other
  servers (**Address for other servers** on its Settings page, `server.node_url`).
