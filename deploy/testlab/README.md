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
| `testlab-setup.sh` | Signalith from the apt repository, OpenSearch on 127.0.0.1, Caddy for HTTPS, a local audit log, sample data, a live feed of recorded attack events, nightly snapshots and backups, automatic updates |

## What is reachable

- Port 443 through Caddy, only from `admin_ip` until `public=true`; port 80,
  which only redirects and answers Let's Encrypt, from anyone. Caddy refuses the token routes
  agents and senders use (`/api/ingest`, OTLP and `/v1/`, HEC, osquery, sensor, agent,
  join, syslog, SCIM, chat and `/metrics`), so the lab takes no data from outside.
- SSH from `admin_ip` only, with keys only.
- Signalith (9000), its agent port (7779) and OpenSearch (9200) listen on
  127.0.0.1. Signalith trusts Caddy's `X-Forwarded-For` only from
  loopback, and Caddy sets it to the client's own address.
- Outbound: nothing reaches the cloud metadata service; OpenSearch reaches
  nothing; Signalith reaches only HTTPS on public addresses. The lab sends
  no mail.

## Build it

From this folder, with `HCLOUD_TOKEN` set to the Hetzner API token:

```sh
terraform init
terraform apply -var admin_ip=203.0.113.7 -var admin_email=you@example.com
```

Add the `dns_record` output where `signalith.io`'s DNS is kept, and follow
the setup with the `watch_setup` output. It ends with "Test lab ready".

## Before anyone else gets in

1. Sign in as the built-in admin (`sudo cat /etc/signalith/initial-admin-password`),
   and make your own admin account with two-step sign-in.
2. On **Settings**: **Require two-step sign-in** for everyone, the AI
   assistant left off, no response actions, no playbooks that act outside
   Signalith, no ticketing. The setup sets retention to 30 days.
3. Restore one snapshot under a new name to test it, then delete the copy.
4. Turn the built-in admin off (**Settings > Users**, **Actions** on its row).
5. Once the security live check signs off, open it:
   `terraform apply -var public=true`.

Backups: a nightly OpenSearch snapshot (14 kept) and Signalith backup on
the data volume, and a copy of the Signalith backup on the root disk (7
kept, master keys in a separate folder), which Hetzner's server backups
cover. Snapshots stay on the volume: the lab holds only sample and
recorded data, and may be reset.

## Testers

Each tester gets an account (`Settings > Users`): analyst for those who
investigate, viewer for those who only look. Note an end date for each, and
send the one-time password privately. The first sign-in asks for a new
password and two-step sign-in. Turn an account off when its end date passes.

Testers share one set of data, and can see and change each other's cases,
notebooks, dashboards and indicators. The invitation, sent privately, says
so (the account is made once the tester replies that they have read it),
and so does `https://lab.signalith.io/about-this-lab`: that this
is a test system: no real customer, production or employer data and no
secrets; data may be reset; other testers may connect their own AI tools,
so anything written there can reach their AI provider; report security
issues as [SECURITY.md](../../SECURITY.md) says.

Testers who want AI connect their own AI tool with `signalith mcp` (see
[AI tools](../../docs/ai-tools.md)) and a Viewer API token made for them,
sent privately and set to expire in 30 days or less. Revoke it with the
account. The lab's own AI assistant stays off.
