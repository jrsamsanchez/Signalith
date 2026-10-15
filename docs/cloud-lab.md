---
description: Build a test lab of Signalith on Hetzner Cloud with one command, and delete it with another.
---

# Cloud test lab

[deploy/lab](https://github.com/jrsamsanchez/Signalith/tree/main/deploy/lab) builds a
lab on [Hetzner Cloud](https://www.hetzner.com/cloud) to try Signalith the way it runs
for real: several servers behind a load balancer, a 3-node OpenSearch, a scanner with
OpenVAS, a network sensor, and Linux and Windows endpoints with agents. One command
builds it, another deletes it, so you only pay for the hours you test.

## What it costs

Hetzner bills by the hour, and **charges for a server even while it is turned off**:
delete the lab when you are done, and build it again next time.

| Lab | Machines | Per hour | Per month, if never deleted |
| --- | --- | --- | --- |
| `full` (the default) | 10 machines and a load balancer | about $0.14 | about $99 |
| `minimal` | signalith-1, opensearch-1, linux-1 | about $0.03 | about $23 |

Prices from Hetzner's price list of 15 June 2026, in Nuremberg, Falkenstein or Helsinki
(the cheaper CX machines are only offered there), before tax.

## The machines

| Machine | Size | What it is |
| --- | --- | --- |
| signalith-1 | 2 cores, 4 GB | The first Signalith server. It also runs the setup. |
| signalith-2 | 2 cores, 4 GB | A second server, added with a join token |
| opensearch-1, -2, -3 | 4 cores, 8 GB | OpenSearch 2.17, one cluster, with certificates of its own CA |
| scanner | 4 cores, 8 GB | A scanner-only server with Nmap and OpenVAS |
| sensor | 4 cores, 8 GB | A network sensor with Zeek and Suricata |
| linux-1, linux-2 | 2 cores, 4 GB | Ubuntu endpoints with Fluent Bit |
| windows-1 | 4 cores, 8 GB | A machine you install Windows Server on (see [Windows](#windows)) |
| Load balancer | LB11 | In front of signalith-1 and -2 on the private network, with PROXY protocol |

The machines talk over a private network (`10.0.1.0/24`) and know each other by name
(`signalith-1.lab.internal` and so on). Agents and the sensor send to
`https://siem.lab.internal:8080`, the load balancer, which has no public address.

The firewall lets in only your own internet address, on SSH (22), the web page (8080)
and Windows remote desktop (3389).

Cloud networks have no mirror port, so each Linux endpoint sends a copy of its traffic to
the sensor (over VXLAN), and the sensor captures it on a port with no address, `capture0`,
as it would a mirror port. A timer on the endpoints visits a few web pages every 10
minutes, including `testmynids.org`, which Suricata's rules flag.

## What you need

- A Hetzner Cloud account, a project in it, and an API token with **Read & Write**
  (Console > your project > **Security** > **API tokens**). New accounts are limited in
  how many servers and public IP addresses they can have (the full lab needs 10 of each);
  if `terraform apply` stops with `Primary IP limit exceeded` or a server limit, ask
  Hetzner to raise it (Console > your name > **Limits**), then run `terraform apply` again.
- [Terraform](https://developer.hashicorp.com/terraform/install) 1.5 or later. On Windows:
  `winget install Hashicorp.Terraform`, then open PowerShell again.
- An SSH key. Check with `Test-Path $HOME\.ssh\id_ed25519.pub` (PowerShell) or
  `ls ~/.ssh/id_ed25519.pub`; make one with `ssh-keygen -t ed25519` if there is none.
- This repository on your computer (`git pull` to get the latest).

## Build the lab

In PowerShell, in the folder you cloned Signalith into:

```powershell
cd deploy\lab
$env:HCLOUD_TOKEN = "paste your Hetzner API token here"
terraform init
terraform apply
```

On Linux or macOS, use `export HCLOUD_TOKEN=...` instead of the `$env:` line.

`terraform apply` lists what it will make and asks you to type `yes`. The machines
are ready in a minute or two. signalith-1 then sets up everything else by itself,
which takes about 30 minutes (OpenVAS downloads its feeds for an hour or more after
that). Watch it with the line `terraform apply` prints as `watch_setup`:

```powershell
ssh root@<signalith-1 address> tail -f /var/log/lab-setup.log
```

It ends with `Lab ready.` Press Ctrl+C to stop watching. Then:

1. Open the `signalith` address it printed, such as `https://203.0.113.10:8080`.
2. Sign in as `admin`, with the password from the `admin_password` line:
   `ssh root@<signalith-1 address> cat /etc/signalith/initial-admin-password`.
3. The browser warns about the certificate: trust Signalith's own CA from the sign-in
   page, as on any new install (see [HTTPS](https.md)).

The token stays in this PowerShell window only; it is not saved anywhere. Open a new
window later and you set it again.

The lab builds Signalith from the `main` branch. To try another branch or commit:
`terraform apply -var signalith_ref=my-branch`.

Options, each with `-var name=value` on `terraform apply` and `terraform destroy`:

| Option | Default | What it does |
| --- | --- | --- |
| `size` | `full` | `minimal`: one server, one OpenSearch node and one Linux endpoint |
| `location` | `nbg1` | `fsn1` (Falkenstein) or `hel1` (Helsinki) |
| `home_ip` | your address now | The address the firewall lets in |
| `ssh_public_key_file` | `~/.ssh/id_ed25519.pub` | Your SSH public key |
| `signalith_ref` | `main` | The branch, tag or commit to build |
| `windows` | `true` | Make windows-1 |
| `windows_image` | empty | A snapshot of windows-1 to start it from |
| `openvas` | `true` | Install OpenVAS on the scanner |

## Delete the lab

```powershell
cd deploy\lab
$env:HCLOUD_TOKEN = "paste your Hetzner API token here"
terraform destroy
```

Type `yes`. Every machine, the load balancer, network and firewall are deleted, and
billing stops. Snapshots you made yourself are kept (they cost about $0.014 per GB a
month). Check the Hetzner Console afterwards if you want to be sure nothing is left.

If your internet address changed since you built the lab, `terraform apply` again
updates the firewall.

## After the setup

### Windows

Hetzner has no ready-made Windows images, so windows-1 starts with a blank Ubuntu disk
and you install Windows Server once:

1. Hetzner Console > **windows-1** > **ISO Images**: find **Windows Server 2025** (or
   2022) and click **Mount**. Then **Power** > **Power cycle**.
2. Click **Console** (the `>_` icon) and install Windows: **Custom** install. When it
   finds no disk, mount the **virtio-win** ISO the same way, click **Load driver**,
   and load **Balloon**, **NetKVM** and **vioscsi** (the `amd64` folder of each). Mount
   the Windows ISO again, delete the partitions on the disk, and install.
3. When Windows has started, unmount the ISO, and turn on remote desktop. From then on,
   connect with Remote Desktop to windows-1's address from the `machines` list.
4. Give it the lab's names: in PowerShell as Administrator,
   `Add-Content C:\Windows\System32\drivers\etc\hosts "10.0.1.5 siem.lab.internal"`.
5. In Signalith, **Add data** > **Windows**, and follow the steps. The agent sends to
   `https://siem.lab.internal:8080`.

Windows runs without a license key: it is not activated, which is fine for a lab that is
deleted again. Use your own key if you have one.

So you need not install it each time, save it: Console > **windows-1** > **Snapshots** >
**Take snapshot** (shut Windows down first). Next time, build with
`terraform apply -var windows_image=<snapshot ID>`. The snapshot is kept when the lab is
deleted, and costs about $0.70 a month for 50 GB.

windows-1 can also be an Active Directory domain controller, to test
[directory sign-in](users.md#sign-in-with-active-directory-or-ldap).

### Vulnerability scans

**Vulnerabilities** > add the network `10.0.1.0/24`, pick **scanner** as its scanner, and
turn on **Also scan with OpenVAS**. **Settings** > **Scanners** shows whether the scanner
reaches OpenVAS. OpenVAS answers once its feeds have downloaded, which takes an hour or
more after the setup.

### Single sign-on

Single sign-on needs an identity provider; neither needs any machine in the lab. A free
[Microsoft Entra ID](https://www.microsoft.com/security/business/microsoft-entra-pricing)
tenant comes with any Microsoft Azure account, and [Okta](https://developer.okta.com/signup/)
has a free developer account. Set it up as [Users and sign-in](users.md) describes, with
`https://<signalith-1 address>:8080` as the address people sign in at.

## If something fails

The setup log on signalith-1 (`/var/log/lab-setup.log`) says which step failed and what to
look at. Each step that finished is remembered, so after fixing the cause, run the rest
again on signalith-1:

```sh
sudo lab-setup
```

To start a step over, delete its mark in `/root/lab/done`. To start everything over,
`terraform destroy` and `terraform apply`.

Useful places:

| Where | What |
| --- | --- |
| `journalctl -u signalith -n 50` on a Signalith server | Why Signalith did not start |
| `journalctl -u opensearch -n 50` on an OpenSearch node | Why OpenSearch did not start |
| `/root/lab/pki` on signalith-1 | OpenSearch's CA and admin certificate |
| `cd /opt/greenbone && docker compose -p greenbone-community-edition ps` on scanner | OpenVAS's containers |
| **Settings** > **Network sensors** | The sensor's checks (see [Network sensor](network-sensor.md#status)) |
| `journalctl -u signalith-zeek -u signalith-suricata -n 50` on the sensor | Why Zeek or Suricata stopped |

## What is kept where

- **Your Hetzner token**: only in the PowerShell window (`HCLOUD_TOKEN`).
- **Terraform's state** (`terraform.tfstate` in `deploy/lab`): what it built, so it can
  delete it. It holds the lab's own SSH key and the machines' setup; keep it on your
  computer, and never commit it (`.gitignore` leaves it out).
- **The lab's SSH key** is made for each lab and lets signalith-1 reach the other
  machines. It is gone with the lab.
