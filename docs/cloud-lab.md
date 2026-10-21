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
| `full` (the default) | 9 machines and a load balancer | about $0.10 | about $74 |
| `minimal` | signalith-1, opensearch-1, linux-1 | about $0.03 | about $21 |
| `loadtest` | signalith-1, two 8-core OpenSearch nodes with a 500 GB volume each, the load generator ([Load test](#load-test)) | about $0.12 | about $88 |
| `loadtest` with `loadtest_servers=3` | signalith-1 to -3, two 4-core OpenSearch nodes (`cx33`) with a 500 GB volume each, the load generator ([Detection spread](#detection-spread)) | about the same as `loadtest` | about the same |

Prices from Hetzner's price list of 15 June 2026, in Nuremberg, Falkenstein or Helsinki
(the cheaper CX machines are only offered there), before tax.

## The machines

| Machine | Size | What it is |
| --- | --- | --- |
| signalith-1 | 2 cores, 4 GB | The first Signalith server. It also runs the setup. |
| signalith-2 | 2 cores, 4 GB | A second server, added with a join token |
| opensearch-1, -2, -3 | 2 cores, 4 GB | OpenSearch 2.17, one cluster, with certificates of its own CA |
| scanner | 4 cores, 8 GB | A scanner-only server with Nmap and OpenVAS |
| sensor | 2 cores, 4 GB | A network sensor with Zeek and Suricata |
| linux-1 | 2 cores, 4 GB | An Ubuntu endpoint with Fluent Bit |
| windows-1 | 2 cores, 4 GB | A machine you install Windows Server on (see [Windows](#windows)) |
| Load balancer | LB11 | In front of signalith-1 and -2 on the private network, with PROXY protocol |

The sizes fit a new Hetzner account's first limits. The sensor gets less than the 4 cores
and 8 GB its install script asks for, which is enough for the lab's little traffic (the
script warns about it and carries on).

The machines talk over a private network (`10.0.1.0/24`) and know each other by name
(`signalith-1.lab.internal` and so on). Agents and the sensor send to
`https://siem.lab.internal:7779`, the agent port of the load balancer, which has no public
address. The web page is on port 9000.

The firewall lets in only your own internet address, on SSH (22), the web page (9000)
and Windows remote desktop (3389).

Cloud networks have no mirror port, so each Linux endpoint sends a copy of its traffic to
the sensor (over VXLAN), and the sensor captures it on a port with no address, `capture0`,
as it would a mirror port. A timer on the endpoints visits a few web pages every 10
minutes, one of them with `uid=0(root)` in the clear, which Suricata flags (the rule
`testmynids.org` shows).

## What you need

- A Hetzner Cloud account, a project in it, and an API token with **Read & Write**
  (Console > your project > **Security** > **API tokens**). New accounts are limited in
  how many servers and public IP addresses they can have (the full lab needs 9 servers, 9 addresses and 20 shared cores, which fits the
  usual first limits of 20 cores and 10 addresses);
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
that). To watch it, print the line to run with:

```powershell
terraform output -raw watch_setup
```

It prints `ssh root@<signalith-1 address> tail -f /var/log/lab-setup.log`: copy it and run it
(the first time, ssh asks whether to continue connecting: type `yes`). It ends with `Lab ready.` Press Ctrl+C to stop watching. Then:

1. Open the `signalith` address it printed, such as `https://203.0.113.10:9000`.
2. Sign in as `signalithadmin`, with the password from the `admin_password` line:
   `ssh root@<signalith-1 address> cat /root/lab/admin-password`. Signalith asks the admin
   for a new password before anything else, so the setup replaces the first one with a
   random password and keeps it there.
3. The browser warns about the certificate: trust Signalith's own CA from the sign-in
   page, as on any new install (see [HTTPS](https.md)).

The token stays in this PowerShell window only; it is not saved anywhere. Open a new
window later and you set it again.

The lab builds Signalith from the `main` branch. To try another branch or commit:
`terraform apply -var signalith_ref=my-branch`.

Options, each with `-var name=value` on `terraform apply` and `terraform destroy`:

| Option | Default | What it does |
| --- | --- | --- |
| `size` | `full` | `minimal`: one server, one OpenSearch node and one Linux endpoint; `loadtest`: the [load test](#load-test)'s machines |
| `loadtest_servers` | `1` | The load test's Signalith servers, 1 to 3 (signalith-2 at 10.0.1.12, signalith-3 at 10.0.1.13), for [Detection spread](#detection-spread) |
| `loadtest_opensearch_type` | `cx43` | The load test's OpenSearch machine type: `cx43` (8 cores), or `cx33` (4 cores) with more than one server |
| `vcpu_limit` | `20` | The account's core limit; the load test's machines must fit in it |
| `loadtest_volume_gb` | `500` | The size of each load test OpenSearch node's volume |
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

## Test everything

Once the setup says `Lab ready.`, one command on signalith-1 tests the lab from end to end:

```sh
ssh root@<signalith-1 address>
sudo lab-e2e
```

It makes the lab do what Signalith should notice, then checks through the API that each
thing arrived and was acted on. It takes about 5 minutes:

- **Servers and OpenSearch:** every server ready, the jobs held by one server, OpenSearch
  green, the load balancer, the upgrade check and the Health page.
- **Data coming in:** the agent on linux-1 (logs, logons, the audit log, process launches),
  an OpenTelemetry record through the agent port, a syslog message when the receiver is on,
  and the network sensor (Zeek and Suricata). When the web page and agents have separate
  ports, it checks that each port does only its own job.
- **Attacks and detections:** from the scanner, failed logons as 12 accounts that don't
  exist; on linux-1, a new account, three wrong sudo passwords, password hashes read with
  sudo, the EICAR test file (when ClamAV is installed), traffic to port 4444 and 30 unknown
  DNS names; a threat intel indicator for the address it sent to on port 4444. Each matching detection is
  run as **Run now** does and must find it and raise a finding. linux-1 must then have a
  risk score. The findings go into a case, which is closed as benign (`--keep-findings`
  leaves them open).
- **Search, Ask and dashboards:** a set of searches (stats, timechart, eval, rex, dedup and
  more), an Ask question, every dashboard's panels, the web page's scripts, compliance,
  coverage, the audit log, retention and the shared settings export.
- **Vulnerability scanning:** the scanner online and ready, OpenVAS, and the last scan.

`sudo lab-e2e --all` also changes the lab for a while, and takes about 15 minutes more:
it drains and resumes signalith-2, restarts the server that runs the jobs, stops OpenSearch
on opensearch-3 and starts it again, and runs a vulnerability scan from the scanner.

It ends with how many checks passed and failed, and writes the report to
`/root/lab/e2e/latest/report.md`, failures first. To copy it to your PC (in PowerShell):

```powershell
scp root@<signalith-1 address>:/root/lab/e2e/latest/report.md .
```

The test signs in with the password in `/root/lab/admin-password`. A lab whose admin
still has the first password Signalith made gets a new random one there, as a new lab
does. If you changed the admin password yourself, give it to the test:
`sudo E2E_PASSWORD='<password>' lab-e2e`.

## Load test

The load test puts about a terabyte a day on a small setup: 25,000 events a second of
about 500 bytes for four hours, while five analysts search and the scheduled detections
run, and records where it saturates. It needs its own machines, which fit a new Hetzner
account's 20 cores only without the normal lab, so delete the lab first:

| Machine | Size | What it is |
| --- | --- | --- |
| signalith-1 | 2 cores, 4 GB | The only Signalith server. It also runs the setup and the test. |
| opensearch-1, opensearch-2 | 8 cores, 16 GB, and a 500 GB volume each | OpenSearch, with its data on the volume |
| loadgen | 2 cores, 4 GB | `signalith-loadgen`, which plays 200 agents and the analysts |

```powershell
cd deploy\lab
$env:HCLOUD_TOKEN = "paste your Hetzner API token here"
terraform destroy
terraform apply -var size=loadtest
```

When the setup says "Lab ready" (`watch_setup`), start the test on signalith-1:

```
ssh root@<signalith-1 address> lab-loadtest
```

It runs in the background for about 4.5 hours; `lab-loadtest status` shows how far it
is, and `lab-loadtest stop` stops it early. Every machine records its CPU, memory, disk
and network every 15 seconds, and OpenSearch its stored events, each node's load and
how far the newest event is behind the clock (the lag) every 30 seconds. The detections
are recorded too (see [What it records about detections](#what-it-records-about-detections)).
The results are in `/root/lab/loadtest/latest/` on signalith-1: `report.md` sums them up, with the
load generator's own measurements (`loadgen.txt`, from
[loadtest/tb-day.yaml](https://github.com/jrsamsanchez/Signalith/blob/main/loadtest/tb-day.yaml))
and each sample (`*.csv`, `*.jsonl`, `logs-*.txt`). Copy them before you delete the machines:

```
scp -r root@<signalith-1 address>:/root/lab/loadtest/latest loadtest-results
```

Then build the normal lab again:

```powershell
terraform destroy
terraform apply -var windows=false
```

A run costs about $1: six hours of the test's machines and volumes.

### What it records about detections

Every minute, while either test runs, signalith-1 also keeps:

| File | What |
| --- | --- |
| `detstate.jsonl` | Each detection's run state, from the `detstate` documents in the runtime indices (`signalith_runtime`, and `signalith.t.<tenant>_runtime` for other tenants): `detection_id`, `last_slot`, `last_run`, `last_duration_ms`, `lag_ms`, `late_runs`, `node`, `det_epoch`, `error_kind`, `schedule` and the tenant, one JSON line per rule |
| `detassign.jsonl` | Each tenant's `detassign` document: its `search_budget` and lease epoch |
| `threadpool.jsonl` | OpenSearch's search thread pool per node (`_cat/thread_pool/search`: active, queue, rejected, completed, size) |
| `cluster.jsonl` | The `detections` block of `GET /api/cluster` (buckets each server runs and is moving, per tenant), the servers and who holds the jobs |

Every 10 minutes it keeps `_cat/shards` (`shards.jsonl`) and `_cat/indices/signalith-*`
(`indices.jsonl`), at the start the detections enabled by schedule (`rules.json`), and at
the end each Signalith server's log lines since the start that say "running fewer",
"full rate again", "assigned to servers", "detection ran late" or "rollover size"
(`logs-<server>.txt`). `report.md` adds, per server (and per phase in the spread test):
run time and lag p50/p95, the 1-minute rules' lag p95, late runs, timeouts, the sum of
run times per hour, the search pool's rejected count growth and longest queue, the
buckets each server runs against the even share (64 / servers, within 25%), the primary
shards of each `signalith-*` index, the rollover lines, and the enabled rules by
schedule. With fewer than 1,500 enabled rules it says so; it does not turn more on.

The API calls sign in as the built-in admin (`signalithadmin`, or `admin` on a lab set up
before 0.3.1) with `/root/lab/admin-password`, given to curl on its
input; OpenSearch is read with the admin certificate in `/root/lab/pki`.

### Detection spread

`sudo lab-loadtest spread` measures detections spread over several servers
(`detections.spread`). It needs two or three Signalith servers, so build the load test
with `loadtest_servers`. Hetzner's first limit is 20 cores, and three 2-core servers, two
8-core OpenSearch nodes and the load generator need 24 (two servers need 22): use 4-core
OpenSearch nodes, or ask Hetzner to raise the limit first and give the new limit as
`vcpu_limit`. Terraform refuses a set that does not fit before it makes anything.

```powershell
terraform apply -var size=loadtest -var loadtest_servers=3 -var loadtest_opensearch_type=cx33
```

or, with the limit raised to 24 or more, the plan's 8-core nodes:

```powershell
terraform apply -var size=loadtest -var loadtest_servers=3 -var vcpu_limit=24
```

The setup joins signalith-2 and signalith-3 to signalith-1 with join tokens, each with
`cluster.leader_eligible` on (`SIGNALITH_LEADER_ELIGIBLE=true`), so each may run
detections. Then, on signalith-1:

```
ssh root@<signalith-1 address> lab-loadtest spread
```

It refuses a lab with one server. It sends 10,000 events a second of about 500 bytes for
four hours with the same 200 agents and 5 analysts as the terabyte test
([loadtest/spread-10k.yaml](https://github.com/jrsamsanchez/Signalith/blob/main/loadtest/spread-10k.yaml)),
the agents spread over every server's agent port (7779), and after 10 minutes of
warming up runs these phases, 45 minutes each:

1. **Spread off.** One server runs every rule. If `detections.spread` was on, the test
   turns it off first.
2. **Spread on.** `detections.spread` turned on in the shared settings (`PUT /api/settings`).
3. **Graceful move.** `systemctl restart signalith` on signalith-2.
4. **Crash.** `kill -9` of Signalith on signalith-3 (signalith-2 with two servers), down
   10 minutes, then started again.

The rest of the load is recorded as phase 5, spread on with nothing changed. Each phase's
start and end are in `phases.csv`, and what the test did, with the times the servers were
ready again, in `events.csv`; `report.md` has a table per phase and CPU per machine per
phase. At the end, or when stopped, the test starts any server it left stopped and
puts `detections.spread` back as it found it. It takes about 4.5 hours.

The measurement plan's noisy tenant (phase 5) is not run: a tenant's detections search
only its own events, and the load generator sends none to other tenants. Do it by hand
after the run: add a tenant (**Settings** > **Tenants**), send it events with an agent
token made in it (for example `signalith-loadgen agents` on the load generator), add 5
detections in it that search `*` over `30d` every `1m`, and watch the "running fewer"
lines and the other tenants' lag. The plan's other settings (OpenSearch shards, the extra
tenants of ~300 rules, 1,500 enabled rules) are also set by hand before the run.

### Seven-day soak

`sudo lab-loadtest soak` runs the 7-day soak: real recorded Windows and Sysmon events at
about a terabyte a day, through every server's agent port, with 5 analysts searching
([loadtest/soak-7d.yaml](https://github.com/jrsamsanchez/Signalith/blob/main/loadtest/soak-7d.yaml)).
The events are the 1,677 recordings the detection packs carry as tests, replayed by the load
generator with each agent's name and the time now (see
[Real events](https://github.com/jrsamsanchez/Signalith/blob/main/loadtest/README.md#real-events-replay)).
They average about 1.6 KB, so 7,200 a second is about 1 TB a day. One in a thousand is
sent as recorded, so the detections that match it fire; the rest have their text rotated,
which the detections leave alone. Turn on the detections you want measured before the run.

A week at this rate is far more than two 500 GB volumes hold with a replica, so before the
run set a retention policy on the **Data retention** page that keeps a day or two (the
deletions are part of what a soak tests), or make the volumes bigger with
`loadtest_volume_gb`. Check the free disk in `opensearch-nodes.csv` during the first day.

It works with one Signalith server or several. The same machines as the spread test fit
in Hetzner's first 20 cores; if the account runs other servers, give the cores left as
`vcpu_limit`:

```powershell
terraform apply -var size=loadtest -var loadtest_servers=3 -var loadtest_opensearch_type=cx33 -var vcpu_limit=18
```

Then, on signalith-1:

```
ssh root@<signalith-1 address> lab-loadtest soak
```

It records what the other tests do, but keeps the detections' run state every 10 minutes
rather than every minute, so a week of samples fits on signalith-1's disk. `report.md`
adds, for each day, the events stored, their size (primary and with replicas), the bytes
per event, the event indices and the shards in the cluster, the lag per day, and the
events stored a second per Signalith core. At the end of every test, before the held
updates are released, it keeps OpenSearch's node counters (`node-stats-end.json`). The
week costs about $25 with the spread test's machines.

## A lab made before the port change

Labs set up before Signalith moved to ports 9000 (web page) and 7779 (agents) still use 8080
for both. Change the servers' settings first, while the page is still on 8080; the new ports
are used from each server's restart:

1. In **Settings**, for each server (**Settings of**, at the top of the page), set
   **Listen address** to `0.0.0.0:9000` and **Agent address** to `0.0.0.0:7779`, and change
   the `:8080` in **Address for other servers** to `:9000`. These are each server's own
   settings: in a lab with more than one server they are kept with the shared settings, so
   editing `/etc/signalith/signalith.yaml` does not change them.
2. Change the `:8080` in **Public address** to `:9000`. It is shared by all servers.
3. Run `terraform apply` with this version, which moves the firewall and the load balancer
   to 9000 and 7779. Add `-var windows=false` if you have not made windows-1, or it is
   made too.
4. Restart the servers one at a time, the one that runs background jobs last.
5. Get new agent configurations from **Add data** for linux-1 and the sensor; they now send
   to port 7779.

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
   `https://siem.lab.internal:7779`.

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
`https://<signalith-1 address>:9000` as the address people sign in at.

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
