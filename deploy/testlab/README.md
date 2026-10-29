# Public test lab

Terraform files and a setup script for the public test lab at
`lab.signalith.io`: one long-lived server that outside testers sign into
with accounts of their own, filled with realistic data. Unlike the
[cloud test lab](../lab/README.md), it runs released packages and is not
deleted between sessions.

| File | What |
| --- | --- |
| `main.tf`, `variables.tf`, `outputs.tf`, `versions.tf` | The server (cx43, Hetzner backups on), its data volume and firewall |
| `cloud-init.yaml.tftpl` | First boot: SSH keys only, then starts the setup |
| `testlab-setup.sh` | Signalith from the apt repository, OpenSearch on 127.0.0.1, Caddy for HTTPS, the server's own logs, sample data, a live feed of recorded attack events, nightly snapshots and backups, automatic updates |

## What is reachable

- Port 443 through Caddy, only from `admin_ip` until `public=true`; port 80,
  which only redirects and answers Let's Encrypt, from anyone. Caddy refuses the token routes
  agents and senders use (`/api/ingest`, OTLP, HEC, osquery, sensor, agent,
  join, syslog, SCIM, chat and `/metrics`), so the lab takes no data from outside.
- SSH from `admin_ip` only, with keys only.
- Signalith (9000), its agent port (7779) and OpenSearch (9200) listen on
  127.0.0.1. Signalith trusts Caddy's `X-Forwarded-For` only from
  loopback, and Caddy sets it to the client's own address.
- Outbound: nothing reaches the cloud metadata service; OpenSearch reaches
  nothing; Signalith reaches only HTTPS and mail submission (465, 587) on
  public addresses.

## Build it

From this folder, with `HCLOUD_TOKEN` set to the Hetzner API token:

```sh
terraform init
terraform apply -var admin_ip=203.0.113.7 -var admin_email=you@example.com
```

Add the `dns_record` output where `signalith.io`'s DNS is kept, and follow
the setup with the `watch_setup` output. It ends with "Test lab ready".

## Before anyone else gets in

1. Sign in as the built-in admin (`sudo cat /root/testlab/admin-password`),
   make your own admin account, and give it a passkey.
2. On **Settings**: **Require two-step sign-in** for everyone, the AI
   assistant left off, no response actions, no playbooks that act outside
   Signalith, no ticketing, retention of 30 days with the disk guard on.
3. Alert rules on the audit log (admin sign-ins, failed sign-ins and
   lockouts, accounts, roles, tenants and settings changed, bulk deletes)
   that notify you by email.
4. Snapshots copied off the server, to a bucket with object lock, and one
   restore tested.
5. Turn the built-in admin off.
6. Then open it: `terraform apply -var public=true`.

## Testers

Each tester gets an account (`Settings > Users`): analyst for those who
investigate, viewer for those who only look. Note an end date for each, and
send the one-time password privately. The first sign-in asks for a new
password and two-step sign-in. Turn an account off when its end date passes.

Testers share one set of data, and can see and change each other's cases,
notebooks, dashboards and indicators. The invitation says so, and that this
is a test system: no real customer, production or employer data and no
secrets; data may be reset; report security issues as
[SECURITY.md](../../SECURITY.md) says.
