---
hide:
  - navigation
description: Install Signalith with Docker, on Linux or on Windows, sign in, and send it your first events.
---

# Getting started

Signalith needs two things: **OpenSearch 2.x**, where events are stored, and the
**`signalith` server**, a single program with the web UI built in. The Docker quick start
runs both for you; on Linux and Windows you install OpenSearch first and then Signalith
next to it.

| Way to run it | Good for | Takes |
| --- | --- | --- |
| [Docker quick start](#docker-quick-start) | Trying Signalith, labs, small sites | Two commands |
| [Linux](#linux) | A systemd service on a server | OpenSearch, then a few commands |
| [Windows](#windows) | A Windows service | OpenSearch, then one script |

## Docker quick start

Clone the repository and start it (later, run the commands from that folder):

```sh
git clone https://github.com/jrsamsanchez/Signalith.git signalith
cd signalith
docker compose -f deploy/docker/docker-compose.yml up -d
docker compose -f deploy/docker/docker-compose.yml exec signalith signalith initial-password
```

The `up` command starts OpenSearch and Signalith. On the first start a setup step makes
the admin password, the agents' ingest token and the certificates OpenSearch and
Signalith use with each other, and keeps them in Docker volumes; no password is written
in the compose files. The last command shows the admin password.

Open **https://localhost:8080** and sign in as `admin` with that password.

!!! tip "The browser warns about the certificate"
    Signalith serves HTTPS with a certificate it makes for itself, so the browser warns
    until you trust it. The sign-in page has a **Download the server certificate** link;
    [HTTPS](https.md#trust-the-certificate) shows how to trust it on Windows, macOS and
    Linux.

OpenSearch runs with its security plugin on: it answers only over HTTPS, publishes no
port, and lets in only Signalith's certificate, which may use only Signalith's own
indices. See [Securing OpenSearch](opensearch-security.md).

To change the admin password (the first one then stops working):

```sh
docker compose -f deploy/docker/docker-compose.yml exec signalith signalith passwd
docker compose -f deploy/docker/docker-compose.yml restart signalith
```

Settings changed on the **Settings** page are kept in the `signalith-data` volume, so
they survive updates. To update, run `git pull` and then the `up` command again; it
rebuilds Signalith from the new code. After a reboot everything starts again by itself
once Docker is running (in Docker Desktop, turn on *Start Docker Desktop when you sign
in*).

!!! note "Coming from an older quick start?"
    Earlier versions served plain HTTP and took the admin password from
    `docker-compose.yml`. The README has
    [step-by-step upgrade instructions](https://github.com/jrsamsanchez/Signalith/blob/main/README.md#upgrading-the-docker-quick-start)
    that keep your events, findings, users and detections.

## Try it with sample data

No logs to hand? On the **Add data** page (under Configure, admins only), **Load sample
data** fills Signalith with a week of made-up activity for a fictional company, with a
handful of attacks hidden in it, so detections fire, the triage queue fills, risk builds
up, threat intel matches and the dashboards light up. Everything is fictional and kept
apart from your own data, and one click removes all of it. From the shell:

```sh
docker compose -f deploy/docker/docker-compose.yml exec signalith signalith sample-data load
```

[Sample data](sample-data.md) has a guided tour of the attacks it contains.

## Linux

1. Install OpenSearch 2.x
   ([instructions](https://opensearch.org/docs/latest/install-and-configure/install-opensearch/index/)).
2. Install Signalith:

    ```sh
    sudo install -m 0755 signalith-linux-amd64 /usr/local/bin/signalith
    sudo useradd --system --no-create-home signalith
    sudo signalith init -c /etc/signalith/signalith.yaml -opensearch http://127.0.0.1:9200
    sudo chown -R signalith /etc/signalith /var/lib/signalith
    sudo cp deploy/systemd/signalith.service /etc/systemd/system/
    sudo systemctl enable --now signalith
    ```

    `init` prints the admin password once, and where it put the master key that
    encrypts the passwords and keys Signalith stores
    (`/var/lib/signalith/keys/master.key`). Back that file up, apart from the config;
    see [Encryption](encryption.md#the-master-key).

3. Open `https://<server>:8080` and sign in as `admin`.
4. Replace OpenSearch's demo security setup, whose passwords and certificates are
   public, and have Signalith sign in with a certificate of its own:
   [Securing OpenSearch](opensearch-security.md).

To upgrade, stop the service, replace the program and the unit, encrypt passwords an
older version kept as plain text, and start it again:

```sh
sudo systemctl stop signalith
sudo install -m 0755 signalith-linux-amd64 /usr/local/bin/signalith
sudo cp deploy/systemd/signalith.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo signalith secrets encrypt
sudo systemctl start signalith
sudo signalith secrets status
```

Older versions cannot read encrypted values: before going back to one, run
`sudo signalith secrets decrypt` (see
[Going back to an older version](encryption.md#going-back-to-an-older-version)).

## Windows

1. Install OpenSearch 2.x for Windows
   ([instructions](https://opensearch.org/docs/latest/install-and-configure/install-opensearch/windows/)).
2. In an elevated PowerShell, from the folder holding `signalith.exe` and
   `deploy\windows\install.ps1`:

    ```powershell
    .\install.ps1 -OpenSearchUrl http://127.0.0.1:9200
    ```

    This writes `C:\ProgramData\Signalith\signalith.yaml`, installs the **Signalith**
    service and starts it. The service runs as its own account,
    `NT SERVICE\Signalith`, and only SYSTEM, Administrators and that account can read
    `C:\ProgramData\Signalith`.

3. Open https://localhost:8080 and sign in as `admin`
   ([trust the certificate](https.md#trust-the-certificate) to stop the warning).
4. Secure OpenSearch and have Signalith sign in with a certificate:
   [Securing OpenSearch](opensearch-security.md).

To upgrade, put the new `signalith.exe` next to the script and run it again: it stops
the service, replaces the program, encrypts passwords an older version kept as plain
text, and starts it again. Before going back to an older version, run
`signalith secrets decrypt`.

## Install from packages

Each [release](https://github.com/jrsamsanchez/Signalith/releases) has signed `.deb`,
`.rpm` and `.msi` packages that install Signalith as a service in one step, and a
container image. See [Install from packages](install-packages.md).

## Send data

Open **Add data** in the UI, pick **Linux** or **Windows**, and follow the steps: install
Fluent Bit, save Signalith's CA certificate and the generated configuration, and restart
it. The configuration already contains the server address and ingest token, and sends
over HTTPS, checking the server's certificate with that CA.

- Firewalls, switches and other network devices: pick **Syslog**
  ([Agents and syslog](sending-data.md#syslog)).
- Hosts with an OpenTelemetry Collector, and apps with an OpenTelemetry SDK: pick
  **OpenTelemetry** ([OpenTelemetry](opentelemetry.md)).

!!! warning "Use an address the agents can reach"
    Agents on other machines must send to an address they can reach, such as
    `https://192.168.1.20:8080`, not `localhost`. Enter it under **Agents send to** on
    the Add data page (or set `server.public_url`), and allow the port, 8080 by default,
    through this computer's firewall.

## Next steps

- Learn the [query language](query-language.md), or ask questions in plain English on
  the Search page.
- Review the built-in [detections](detections.md) and import Sigma rules.
- Add [users](users.md), or sign in with Active Directory or LDAP.
- Run the [security check](security.md) to see what to tighten on your server.
- Set how long data is kept on the [Data retention](retention.md) page.
