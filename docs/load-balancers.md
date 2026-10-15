# Load balancers

Several Signalith servers that share one OpenSearch can sit behind one address: a
load balancer, or a DNS name over all of them. Agents, browsers and syslog devices
then use that one address, and keep working when a server stops. This page shows how
to set one up with the samples in
[deploy/loadbalancer](https://github.com/jrsamsanchez/Signalith/tree/main/deploy/loadbalancer).
For the servers themselves see [Servers](servers.md).

A single server needs none of this: both settings below are off unless you turn them
on, and nothing changes while they are off.

## How it fits together

```
agents, browsers ──► 8443 ┐               ┌─► siem-a  :8080 web, :6514/:5514 syslog
syslog TLS ────────► 6514 ├─ load balancer┤
syslog TCP ────────► 514  ┘ (PROXY v2)    └─► siem-b
syslog UDP ────────► virtual IP (keepalived) or one server
```

The balancer passes each TCP connection through unchanged, so HTTPS and syslog over
TLS end at Signalith and agents keep checking Signalith's certificate. It checks each
server's `/readyz` (see [Load balancers: /readyz and /livez](servers.md#load-balancers-readyz-and-livez))
and sends nothing to a server that is starting, restarting, stopping or cut off from
OpenSearch.

Passing connections through hides who made them: every client would seem to be the
balancer. So the balancer starts each connection with a PROXY protocol header (version
1 or 2) that names the client, and Signalith reads it.

## Settings

On every server (the Settings page, or `signalith.yaml`):

| Setting | Where on the Settings page | What to set |
| --- | --- | --- |
| `server.trusted_proxies` | HTTPS: Trusted reverse proxies | The balancers' own addresses, such as `10.0.0.20` and `10.0.0.21` |
| `server.proxy_protocol` | Web server: PROXY protocol from load balancers | On. Applies after a restart; `SIGNALITH_PROXY_PROTOCOL=true` sets it too |
| `syslog.proxy_protocol` | Syslog: PROXY protocol from load balancers | On, when syslog over TCP or TLS goes through the balancer. Applies after a restart; `SIGNALITH_SYSLOG_PROXY_PROTOCOL=true` sets it too |
| `server.public_url` | Web server: Public address | The balancer's address, such as `https://siem.example.com:8443`, so Add data gives it to agents |

```yaml
server:
  public_url: https://siem.example.com:8443
  trusted_proxies: [10.0.0.20, 10.0.0.21]
  proxy_protocol: true
syslog:
  tcp: 0.0.0.0:514
  tls: 0.0.0.0:6514
  proxy_protocol: true
```

Only the trusted proxies may send a header. They may also connect without one, as a
health check does. A header from any other address closes the connection: otherwise
anyone could pick the address they are counted and logged under. The header must come
within 5 seconds of connecting, and a malformed one closes the connection too.

A trusted proxy counts as many clients: it is never held to one client's share of
connections and requests. The clients behind it each get their own share, by the
address the header names.

`signalith validate` and the Health page warn when PROXY protocol is on but no trusted
proxy is listed (then no header is accepted), and when `server.trusted_proxies`
trusts every address (`0.0.0.0/0` or `::/0`).

## The samples

- **`haproxy.cfg`**: HAProxy in TCP mode for the web port (8443), syslog over TLS
  (6514) and syslog over TCP (514), with `send-proxy-v2`, `/readyz` checks and
  `balance leastconn`. Change the `server` lines to your servers' addresses.
- **`nginx-stream.conf`**: the same with nginx's stream module and `proxy_protocol on`.
  Open source nginx only notices a stopped server when a connection to it fails; it
  cannot read `/readyz`.
- **`keepalived.conf`**: one virtual IP shared by two balancer machines, so the
  balancer is not a single point of failure, and syslog over UDP balanced to the
  servers (UDP has no PROXY protocol).

The [folder's README](https://github.com/jrsamsanchez/Signalith/blob/main/deploy/loadbalancer/README.md)
has notes for Windows Network Load Balancing, AWS and Azure load balancers, F5 and
Citrix, and balancers that end TLS themselves.

## Try it on one machine

`deploy/docker/docker-compose.cluster.yml` runs two servers, one OpenSearch and
HAProxy with the sample configuration, on one computer with Docker:

```
docker compose -f deploy/docker/docker-compose.cluster.yml up -d
docker compose -f deploy/docker/docker-compose.cluster.yml exec signalith-a signalith initial-password
```

Open `https://localhost:8443` and sign in as `admin`. The Servers page lists both
servers, and the Health page's **All servers** card shows what each received. Stop one
(`docker compose -f deploy/docker/docker-compose.cluster.yml stop signalith-b`) and
keep working. Each server still has its own certificate authority there, so the
browser may ask about the certificate again when HAProxy picks the other server.
Remove the lab with `down -v`.

## Agents

On Add data, **Where do agents send?** offers the shared address and each server's own,
and says which servers the shared address reaches (see
[Where agents send](servers.md#several-servers-behind-one-address)). Use the shared
address: agents then carry on with another server when one stops.

## Checking it works

- **Health page, All servers**: agent batches and syslog messages per server, and in
  total. Both servers should get some. A server that runs an older version shows
  "No figures" instead of zero. `GET /api/health?scope=cluster` gives the same.
- **Health and Servers pages, "receives no agent traffic"**: a server running for 15
  minutes got no agent batch in the last 10 while another did. Add it to the load
  balancer or the DNS name.
- **Syslog senders** on the Health page list devices by their own address. If they all
  show the balancer's address, `syslog.proxy_protocol` is off, or the balancer sends no
  header.

## Troubleshooting

**"closed a connection that sent a PROXY header from a peer that is not a trusted
proxy"** in the log (at most once a minute), and syslog connections "with a PROXY
header from an untrusted peer" among those turned away on the Health page: a header came from an
address not under `server.trusted_proxies`. If that address is your balancer, add it.
Check the address Signalith sees: a balancer with several addresses (or a NAT between
it and Signalith) may connect from one you did not list.

**Every client shows the balancer's address**: PROXY protocol is off on that port, or
the balancer does not send the header. Both sides must agree: a balancer that sends a
header to a server that does not read it breaks every connection (the header is taken
for the start of the request), and a server that reads it while the balancer sends none
works, but sees only the balancer.

**Sign-ins fail behind the balancer**: once the servers share their users, any server
takes any request. Until then (servers of an older version), turn on source address
affinity or sticky sessions (see [Load balancers: /readyz and /livez](servers.md#load-balancers-readyz-and-livez)).
