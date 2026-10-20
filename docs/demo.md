# Public demo

Demo mode runs Signalith as a public, read-only demo filled with the made-up
[sample data](sample-data.md), such as a demo site on the internet that anyone
can open without an account. It is off unless you turn it on, and is meant for
a server that holds nothing but the sample: never turn it on for a server with
real events.

## What visitors get

The sign-in page offers **Explore the demo**. One click signs the visitor in as
a built-in, read-only **Analyst**, with no password, so every page an analyst
has shows, Vulnerabilities, Endpoints and the Ask box included. Every page shows a banner:
*Public demo with made-up sample data. Read-only.*, with a link to
[signalith.io](https://signalith.io).

The visitor can search, ask a question in plain English (answered offline),
open the dashboards, findings, cases, risk, the attack storyline,
vulnerabilities, endpoints, detections, threat intel, notebooks and compliance,
and run searches, dashboards and notebooks. The visitor cannot change anything:

- every route for admins is refused, so the admins' pages (Settings, Users,
  Data and the others) stay hidden;
- of the routes for viewers and analysts, only those that read are allowed,
  plus running a search, a dashboard panel or a notebook (a visitor's run is
  not saved) and Ask. Saving a case, a dashboard, a notebook or setup guide
  answers, changing a finding, linking chat accounts and anything else that
  writes answers `403` with the code `demo_read_only`;
- the visitor has no password to change, cannot set up two-step sign-in or
  passkeys, and cannot make API tokens.

Visitors' sessions are kept in the server's memory only, apart from the users'
sessions. One ends after 30 minutes without use and 2 hours after it started,
and when the browser closes. A visitor's address can start 10 sessions a minute,
and the server 3,000 an hour in all; past that the button answers `429` with
`Retry-After`. Someone with many addresses can use up the hourly total and keep
everyone else out for the rest of the hour; if that happens, limit requests per
address in front of the server (at the cloud firewall or a rate-limiting proxy)
and restart Signalith to start the count again. Each visitor's searches count
against a share of the search slots of their own, so one visitor's slow searches
don't hold back the others. A restart ends every visitor's session, and a visitor's session
works only on the server that made it: run a demo on one server, or keep each
visitor on one server (sticky sessions) behind a load balancer.

## What demo mode turns off

Whatever the other settings say, a demo:

| Off | How |
| --- | --- |
| Agents, HEC, OTLP, osquery and network sensors | The agent port is not opened, and these routes answer `403` (`demo_off`) on the web port too. |
| Syslog | No syslog port is opened. |
| Microsoft 365 and Okta | Their logs are not read. |
| The AI assistant | No AI model is ever used: Ask answers offline, and Investigate with AI is off. |
| Notifications, ticketing and chat buttons | Nothing is sent to webhooks, mail servers, Jira, ServiceNow, Slack or Teams. |
| Response actions and playbooks | They do not run, by hand or by themselves. |
| Vulnerability scans | No network is scanned, and scan settings cannot change. The Vulnerabilities page shows the sample's scan results. |
| Threat intel feeds | No feed is downloaded; adding or testing one is refused. |
| Behavior baselines' IP database | It is not downloaded from an address; a file in the `ipdb` folder still works. |
| Single sign-on (OpenID Connect and SAML), SCIM and passkey sign-in | Their routes answer `403`. |
| Directory sign-in tests, the Settings page's connection tests | Refused. |
| Tenants | Only the default tenant runs; adding one is refused. |
| The MCP server | `signalith mcp` signs in with an API token or a password, which work only from the admin networks (below). |

These are refused for admins too. Of the routes that work without signing in,
only signing in and out, the demo's sign-in and the CA certificate are left.

## Signing in as an admin

Signing in with a password, on the sign-in page, with HTTP Basic or with an API
token, works only from the addresses in `demo.admin_networks`. From anywhere
else the sign-in page answers `403` (`demo_password_off`) before it looks at the
password, so nobody can try passwords on a public demo, and a user's session
stops working outside those networks.

With no admin networks (the default) password sign-in is off everywhere, and
the demo is managed from the server's own shell: the `signalith` command, such
as `signalith sample-data status`, works as usual.

## The sample data stays recent

The sample is a week of events that ends when it is loaded. In demo mode the
server that runs the background jobs loads it if none is loaded, and every day
removes it and loads it again, through the same load and removal as **Add
data** and `signalith sample-data`, so only one runs at a time across every
server and the command line. While it reloads, for a few minutes, the demo has
less data or none.

## Turning it on

In `signalith.yaml`:

```yaml
demo:
  enabled: true
  # Where password sign-in still works: your own address or a VPN.
  # Empty (the default) allows it from nowhere.
  admin_networks: [198.51.100.7/32]
```

or with `SIGNALITH_DEMO=true` and `SIGNALITH_DEMO_ADMIN_NETWORKS=198.51.100.7/32`
in the environment. Only the file or the environment set these, never the
Settings page: a page that could turn demo mode off could undo all of it. A
change applies at the next restart. The log says at startup that the server is
a public demo.

Behind a reverse proxy, list it under `server.trusted_proxies` and set
`server.client_header`, so the admin networks and the limits on visitors see
each visitor's own address rather than the proxy's.

## Running a demo with Docker

`deploy/demo/` adds demo mode to the [Docker quick start](getting-started.md),
with [Caddy](https://caddyserver.com) in front. Caddy gets a Let's Encrypt
certificate for the demo's name and is the only thing that answers from the
internet, on port 443; OpenSearch and Signalith publish no port. Signalith
answers Caddy over the private network between them, trusts only Caddy's
address to say who a visitor is, and runs with
`deploy/demo/signalith.yaml`.

You need Docker Compose 2.24.4 or newer, a DNS name for the computer and port
443 open to it. From the folder you cloned Signalith into:

1. Put the demo's name in a file called `.env` next to
   `deploy/docker/docker-compose.yml`:

    ```sh
    SIGNALITH_DEMO_HOST=demo.example.com
    ```

2. Start it:

    ```sh
    docker compose -f deploy/docker/docker-compose.yml -f deploy/demo/docker-compose.demo.yml up -d
    ```

3. Open `https://demo.example.com` and choose **Explore the demo**. The sample
   data loads within a few minutes of the first start.

On a new Ubuntu 24.04 cloud server, `deploy/demo/cloud-init.yaml` does all of
this for you: change `demo.example.com` in it to the demo's name and paste it
into the provider's "Cloud config" or "user data" box when creating the
server. It installs Docker, starts the demo and updates it every Sunday. Give
the server an SSH key, and open port 443 to everyone and port 22 only to your
own address.

To sign in as the admin from your own address, set
`SIGNALITH_DEMO_ADMIN_NETWORKS` in `deploy/demo/docker-compose.demo.yml` and
run step 2 again; the admin's first password is shown by
`docker compose -f deploy/docker/docker-compose.yml exec signalith signalith initial-password`.

## API

`POST /api/demo` signs a visitor in to the demo: no body, and the browser's
`Origin` or `Sec-Fetch-Site` must be this site's. It answers like
`POST /api/login` (the user, with `"demo": true`, and the session cookie), `404`
when the server is not a demo, and `429` past the limits. `GET /api/me` has
`"demo": true` for a visitor and `false` for everyone else.
