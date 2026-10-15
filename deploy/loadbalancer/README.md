# Load balancer samples

Samples for putting one address in front of several Signalith servers that share
one OpenSearch. The walkthrough, the settings and troubleshooting are in
[docs/load-balancers.md](https://github.com/jrsamsanchez/Signalith/blob/main/docs/load-balancers.md).

| File | What it is |
| --- | --- |
| `haproxy.cfg` | HAProxy passing the web port (8443), syslog over TLS (6514) and syslog over TCP (514) through to the servers, with PROXY protocol v2 and `/readyz` health checks |
| `nginx-stream.conf` | The same with nginx's stream module (passive health checks only) |
| `keepalived.conf` | A virtual IP shared by two balancers, and syslog over UDP |

In Signalith, on every server:

1. List the balancers' own addresses under **Trusted reverse proxies**
   (`server.trusted_proxies`), on the Settings page or in `signalith.yaml`.
2. Turn on **PROXY protocol from load balancers** for the web port
   (`server.proxy_protocol`) and for syslog (`syslog.proxy_protocol`), then
   restart.
3. Set the public address (`server.public_url`) to the balancer's name, such as
   `https://siem.example.com:8443`, so Add data gives agents that address.

Only the trusted proxies may send a PROXY header: a header from any other address
closes the connection, and the Health page counts it.

## Other load balancers

- **Windows Network Load Balancing (NLB)** forwards packets without changing the
  client's address, so no PROXY protocol is needed: leave both settings off. Use
  "Single" affinity for syslog over TCP so a device stays on one server.
- **AWS Network Load Balancer**: use TCP listeners (not TLS) and turn on the target
  group attribute "Proxy protocol v2". List the balancer's subnets under
  `server.trusted_proxies`. Health check: HTTP `/readyz` on the traffic port.
- **Azure Load Balancer** keeps the client's address and has no PROXY protocol:
  leave both settings off and list nothing for it. Health probe: HTTP `/readyz`.
- **F5 BIG-IP, Citrix ADC** and others: a TCP (layer 4) virtual server that adds a
  PROXY protocol v1 or v2 header works like HAProxy above. Without one, use a
  layer 4 mode that keeps the client's address, as with NLB.
- **A balancer that ends TLS itself** (an HTTPS listener): it must connect to
  Signalith over HTTPS again (re-encrypt), be listed under
  `server.trusted_proxies`, and set `X-Forwarded-For` (choose it as the
  **Client address header**). Agents then check the balancer's certificate, not
  Signalith's: when it comes from a public or company authority their computers
  already trust, remove the `tls.ca_file` line from the configuration Add data gives.
  Syslog over TLS still passes through, with PROXY protocol.
