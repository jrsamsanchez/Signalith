# Kubernetes (Helm)

The Helm chart runs Signalith on Kubernetes: one or more Signalith servers, optional
vulnerability scanners, and a secured OpenSearch, or an OpenSearch you already run. It
makes no default passwords, serves HTTPS everywhere, and its pods meet the **restricted**
[Pod Security Standard](https://kubernetes.io/docs/concepts/security/pod-security-standards/).

You need Kubernetes 1.27 or newer, Helm 3.8 or newer, and a default storage class for the
volumes. OpenSearch's pod asks for 2 GB of memory and 30 GB of disk by default.

## Install

```sh
helm install signalith oci://ghcr.io/jrsamsanchez/charts/signalith \
  --version <release> --namespace signalith --create-namespace
```

`<release>` is a Signalith release, such as `0.3.0`; each release publishes the chart with
the same version, signed with Sigstore, and its `.tgz` is on the release page. From a
checkout of the repository, `helm install signalith deploy/helm/signalith -n signalith
--create-namespace` installs the chart as it is on that branch, with the image built from
`main`.

The first start takes a few minutes. Then:

1. Show the first admin password:

    ```sh
    kubectl -n signalith get secret signalith-secrets -o jsonpath='{.data.initial-admin-password}' | base64 -d; echo
    ```

2. Open Signalith. With the default `ClusterIP` service:

    ```sh
    kubectl -n signalith port-forward service/signalith 9000:9000
    ```

    then <https://localhost:9000>, and sign in as `signalithadmin`. The browser warns about the
    certificate until you trust Signalith's CA ([HTTPS](https.md#trust-the-certificate)).

3. So agents and devices outside the cluster can send to it, give it an address they
   reach (below) and set `server.publicURL` to it. The Add data page gives agents that
   address on the [agent port](sending-data.md#the-agent-port), 7779, which is kept apart
   from the web page's port, 9000 (`server.agentPort` and `server.port`).

The chart's settings are in its
[values.yaml](https://github.com/jrsamsanchez/Signalith/blob/main/deploy/helm/signalith/values.yaml),
each with a comment. Change them with a file of your own (`-f my-values.yaml`) on
`helm install` or `helm upgrade`.

## What it runs

| Part | Kubernetes objects | Notes |
| --- | --- | --- |
| Signalith servers | StatefulSet `signalith`, `server.replicas` pods | Each has its own volume for its master key, identity, detections and archived days |
| Scanners | StatefulSet `signalith-scanner`, off unless `scanner.enabled` | [Scanners](multi-server.md#cluster-servers-and-scanners) scan networks from inside the cluster and never run the background jobs |
| OpenSearch | StatefulSet `signalith-opensearch`, 1 or 3+ nodes | Off with `opensearch.enabled: false` |
| Setup | A Job before each install and upgrade | Makes the secrets (below), then is deleted with its rights |
| Services | `signalith` (web and API on 9000, agents on 7779), `signalith-syslog`, `signalith-pods`, `signalith-opensearch` | `signalith-agents` (agents only) with `server.agentService.enabled` |
| Ingress | `signalith`, off unless `ingress.enabled` | The web page and API only ([An ingress controller](#an-ingress-controller)) |
| Network policies | Around OpenSearch and the servers | Need a network plugin that enforces them |

## Exposing Signalith

The web Service is `ClusterIP` by default. To reach it from outside the cluster:

- **A load balancer**: `server.service.type: LoadBalancer`. It takes the web page on 9000
  and agents on 7779 at one address. Limit who can connect with
  `server.service.loadBalancerSourceRanges`, listing the admins' and the agents' networks
  (without it the sign-in page is open to every network the load balancer is on, and the
  install notes warn about it), then narrow each port with the network policies below.
  Keep each client's own address (which sign-in limits and the audit log use) with
  `server.service.externalTrafficPolicy: Local`.
- **Syslog**: the `signalith-syslog` Service takes syslog over TLS on 6514, with the same
  settings under `server.syslog.service`. `server.syslog.allow` lists the addresses that
  may send. Plain syslog over UDP and TCP 514 is unencrypted and can be forged, so a new
  install leaves it off: `server.syslog.plain: true` adds it to the Service, the pods
  (which listen on 5514) and the network policy, and `false` keeps it off. Left at `auto`,
  **an upgrade keeps plain syslog as it was**: on when the release's `signalith-syslog`
  Service already takes UDP or TCP 514, as releases before 0.3.1 did (the chart looks it
  up in the cluster). `helm template`, Argo CD and Flux render without the cluster, so
  they render a new install: set `server.syslog.plain: true` there if devices send to 514. The chart sets it in the
  servers' environment, so their Settings and Add data pages show it as set there.
- **An ingress controller**: for the web page only, with `ingress.enabled` (below).

Signalith makes and renews its own HTTPS certificate from a CA the servers share
([HTTPS](https.md)). To serve one of your own, such as one from cert-manager, name its
`kubernetes.io/tls` Secret in `server.tls.existingSecret`.

### An ingress controller

The chart can add an Ingress for the web page and API. It is off by default:

```yaml
server:
  publicURL: https://siem.example.com
  # The agent port on a LoadBalancer Service of its own (signalith-agents).
  agentService:
    enabled: true
    loadBalancerSourceRanges: [10.30.0.0/16]   # the agents' networks
ingress:
  enabled: true
  className: nginx
  annotations:
    nginx.ingress.kubernetes.io/backend-protocol: HTTPS
    nginx.ingress.kubernetes.io/proxy-body-size: 20m
  hosts:
    - host: siem.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: siem-example-com-tls   # from cert-manager, for example
      hosts: [siem.example.com]
```

- **Only the web port goes through it.** An Ingress carries HTTP to the web port, never the
  agent port, 7779. Agents outside the cluster need a TCP Service of their own:
  `server.agentService.enabled: true` adds `signalith-agents`, a LoadBalancer for the
  agent port alone. Point a name at its address and enter that name under **Agents send
  to** on the Add data page, which also adds it to Signalith's own certificate. (The web
  Service, `signalith`, carries both ports; making it a LoadBalancer would expose the web
  port as well.)
- **The controller must connect to Signalith over HTTPS.** Signalith serves HTTPS on the
  web port by default, and plain `http://` there only answers health checks and redirects.
  The chart's default annotation, `nginx.ingress.kubernetes.io/backend-protocol: HTTPS`,
  does this for ingress-nginx, and other controllers ignore it. Traefik uses HTTPS by
  itself, since the Service's port is named `https`. For other controllers, see their
  documentation for HTTPS to the backend (such as `haproxy.org/server-ssl: "true"`). The
  controller then serves its own certificate, from `ingress.tls`, to browsers. Without
  `ingress.tls` it may serve the sign-in page over plain HTTP, and the install notes warn.
- **Plain HTTP inside the cluster** is possible but not recommended: with
  `server.config.server.tls.mode: off`, Signalith speaks plain HTTP on the web port **and**
  the agent port, so agents' events and tokens would cross the cluster unencrypted. Keep
  the default.
- **Network policies**: with `networkPolicy.webFrom` set, list the ingress controller's
  namespace there, such as
  `- namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: ingress-nginx } }`.
  `networkPolicy.agentsFrom` is the same as `webFrom` when not set, which would leave
  agents out, so set it to the agents' networks. Use
  `server.agentService.externalTrafficPolicy: Local` so the policy sees the agents' own
  addresses.
- **Each person's address**: Signalith sees the controller's pods as the client. So that
  sign-in limits and the audit log use each person's address, list the controller's pod
  network under `server.trusted_proxies` and `server.shared_addresses` and set
  `server.client_header: x-forwarded-for` in `server.config` (see
  [Behind a reverse proxy](https.md#behind-a-reverse-proxy)).
- Signalith serves from `/` only, so keep the path at `/`.

Instead of an Ingress, a controller can also pass connections through without ending TLS
(TLS passthrough, such as ingress-nginx's `nginx.ingress.kubernetes.io/ssl-passthrough`),
so browsers see Signalith's own certificate.

## Several servers

```yaml
server:
  replicas: 3
```

The servers share OpenSearch, settings, users and detections, take turns running the
background jobs, and keep working when one of them stops ([Servers](servers.md)). They join
by themselves: each pod reads the **cluster key** from the chart's secret, so no join token
or **Add a server** is needed. The Servers page lists each pod by its name (`signalith-0`,
`signalith-1`, ...). Scale down by lowering `replicas`: the stopped server hands its jobs
over, and you can remove it from the Servers page afterwards
([Draining and removing a server](servers.md#draining-and-removing-a-server)).

With more than one server, a PodDisruptionBudget keeps at least one running while nodes are
drained, and the pods prefer different nodes.

**Scanners** in the cluster: `scanner.enabled: true`. Pick the networks each scans on the
Vulnerabilities page. A server outside Kubernetes (Linux, Windows or Docker) can still join
the same cluster with **Add a server**, once OpenSearch is reachable from it.
**Network sensors** (Zeek, Suricata) need a mirror port and run on machines of their own:
see [Network sensor](network-sensor.md).

## OpenSearch

The bundled OpenSearch (version 3.9) uses HTTPS on its API and TLS between its nodes, with
certificates from a CA of its own, and takes sign-ins only by certificate: Signalith's, and
an admin certificate used to load its security settings. Nothing outside the release may
connect to it. For a cluster that keeps working when a node stops, run three:

```yaml
opensearch:
  replicas: 3
  javaOpts: "-Xms4g -Xmx4g"
  resources:
    requests: { cpu: "2", memory: 8Gi }
    limits: { memory: 8Gi }
  persistence:
    size: 500Gi
```

Signalith keeps a copy of each day's events on a second node once there is one. Give
OpenSearch about half its memory limit as heap ([Performance and sizing](performance.md)).

**An OpenSearch you already run**, which must use HTTPS and a sign-in:

```yaml
opensearch:
  enabled: false
  external:
    urls: [https://opensearch.example.com:9200]
    existingSecret: signalith-opensearch   # ca.crt, plus username and password
    auth: password                          # or certificate: tls.crt and tls.key
```

Its user needs the rights in
[roles.yml](https://github.com/jrsamsanchez/Signalith/blob/main/deploy/docker/opensearch/security/roles.yml)
([Securing OpenSearch](opensearch-security.md)).

## Secrets

Nothing in the chart or its values is a secret. Before each install and upgrade, the setup
Job makes what it needs and keeps it in three Kubernetes Secrets:

| Secret | Holds | Mounted by |
| --- | --- | --- |
| `signalith-secrets` | The first admin password, the agents' ingest token, the cluster key, and Signalith's OpenSearch client certificate | Signalith's pods |
| `signalith-opensearch-certs` | OpenSearch's node certificate and the admin certificate | OpenSearch's pods |
| `signalith-opensearch-ca` | The OpenSearch CA's key | Nobody: only the setup Job reads it |

The Job keeps what is already there, and renews a certificate within 30 days of its
expiry (restart the pods afterwards: `kubectl -n signalith rollout restart statefulset`).
It runs with a service account that exists only while it runs and may only read and
write Secrets in its namespace. The pods copy their secrets into memory-only folders,
readable by their own user alone.

To use your own values, such as from an external secrets manager, create the Secrets
before installing, with the same names and keys: the Job keeps them and makes only what is
missing.

Helm does not own these Secrets or the volumes, so `helm uninstall` keeps them, and
installing again picks up where you left off. To remove everything:

```sh
helm uninstall signalith -n signalith
kubectl -n signalith delete pvc,secret -l app.kubernetes.io/instance=signalith
```

**Change the admin password** on the Users page, or with `signalith passwd` in a server's
pod (`kubectl -n signalith exec -it signalith-0 -- signalith passwd`); the first password
then stops working. Then delete it from the Secret, so nobody who can read Secrets finds
an old password there; the setup Job does not make it again:

```sh
kubectl -n signalith patch secret signalith-secrets --type=json \
  -p '[{"op":"remove","path":"/data/initial-admin-password"}]'
```

Turn on [two-factor sign-in](users.md) for every admin.

## Backup and volumes

Each pod keeps its data on a volume of its own (a PersistentVolumeClaim), which
`helm uninstall` keeps:

| Volume | Holds | Size |
| --- | --- | --- |
| `data-signalith-0`, `-1`, ... | Each server's **master key** (which decrypts the passwords and keys Signalith keeps) and its **identity** among the servers, with its detections, lookups, dashboards and archived days | `server.persistence.size` |
| `data-signalith-scanner-0`, ... | Each scanner's master key and identity | `scanner.persistence.size` |
| `data-signalith-opensearch-0`, ... | OpenSearch's data: events, findings, cases and settings | `opensearch.persistence.size` |

Losing a server's volume loses its master key, so the passwords and keys it encrypted
must be entered again. Back up both halves:

- **OpenSearch**: turn on [scheduled snapshots](backup.md#scheduled-snapshots), with a
  snapshot repository registered in OpenSearch that lives outside the cluster, such as an
  S3 bucket.
- **Each server's files**: `signalith backup` in each server's pod, then copy the zip and
  its master key file out and keep them apart
  ([Signalith's files](backup.md#signaliths-files), [The master key](backup.md#the-master-key)):

    ```sh
    kubectl -n signalith exec signalith-0 -- signalith backup -c /etc/signalith/signalith.yaml -o /tmp/backup.zip
    kubectl -n signalith exec signalith-0 -- cat /tmp/backup.zip > signalith-0-backup.zip
    kubectl -n signalith exec signalith-0 -- cat /tmp/backup.master-key.zip > signalith-0-master-key.zip
    kubectl -n signalith exec signalith-0 -- rm /tmp/backup.zip /tmp/backup.master-key.zip
    ```

**The size can't change with `helm upgrade`.** The volumes come from the StatefulSets'
`volumeClaimTemplates`, which Kubernetes does not let an upgrade change, so a new
`persistence.size` makes the upgrade fail. To grow a volume, when its StorageClass
allows it (`allowVolumeExpansion: true` in `kubectl get storageclass -o yaml`):

1. Ask for the new size on each pod's claim:

    ```sh
    kubectl -n signalith patch pvc data-signalith-opensearch-0 \
      -p '{"spec":{"resources":{"requests":{"storage":"100Gi"}}}}'
    ```

    `kubectl -n signalith get pvc` shows the new size once the storage has grown it; some
    storage needs the pod restarted first.
2. So new pods get the same size, delete the StatefulSet but keep its pods, then upgrade
   with the new size, which makes it again:

    ```sh
    kubectl -n signalith delete statefulset signalith-opensearch --cascade=orphan
    helm upgrade signalith oci://ghcr.io/jrsamsanchez/charts/signalith --version <release> -n signalith \
      --reset-then-reuse-values --set opensearch.persistence.size=100Gi
    ```

A StorageClass that does not allow expansion needs a new volume: restore a backup onto
a new install with the larger size.

## Security

- **Pods**: non-root users (Signalith 65532, OpenSearch 1000), read-only root file systems,
  every capability dropped, no privilege escalation, the runtime's seccomp profile, and no
  Kubernetes API token. They meet the restricted Pod Security Standard, so the namespace
  can enforce it:

    ```sh
    kubectl label namespace signalith pod-security.kubernetes.io/enforce=restricted
    ```

- **Security page**: the chart sets `SIGNALITH_CONTAINER=1`, so Signalith knows it runs
  in a container (Kubernetes' container runtimes leave none of the files Docker and Podman
  do), and the Security page checks the pod's protections instead of asking for a systemd
  service. Set the same variable for Signalith in any other container it doesn't
  recognize, or `SIGNALITH_CONTAINER=0` if it takes a computer for a container.
- **A namespace of its own**: install Signalith in a namespace used by nothing else. The
  network policies recognize Signalith's pods by their labels, so anyone who can create
  pods in the namespace could give one those labels and reach OpenSearch's port (it still
  needs a client certificate from OpenSearch's CA to sign in).
- **Network**: OpenSearch takes connections only from the release's Signalith pods (and its
  own nodes), and connects only to its own nodes. Signalith's pods take connections only on
  their web, agent and syslog ports. Limit who may reach those with `networkPolicy.webFrom`
  (the admins' networks), `networkPolicy.agentsFrom` (the agents' networks; when not set,
  the same as `webFrom`) and
  `networkPolicy.syslogFrom`, and where Signalith may connect with
  `networkPolicy.serverEgress` (threat intel downloads, CVE lookups, content updates and
  notifications need the internet).
- **Images**: Signalith's image is signed with Sigstore and has build provenance; pin it by
  digest with `image.digest`. OpenSearch's image is pinned by digest.
- **Secrets**: see above. Turn on encryption at rest for Secrets in your cluster, and keep
  `get secret` rights in the namespace to the people who run Signalith.

## Upgrading

```sh
helm upgrade signalith oci://ghcr.io/jrsamsanchez/charts/signalith --version <new release> -n signalith --reset-then-reuse-values
```

`--reset-then-reuse-values` (Helm 3.14 or newer) keeps the settings you gave and takes the
new release's defaults for the rest. With `--reuse-values` instead, settings added in the new
release are missing and the old defaults stay, such as the web port of an earlier chart.
The servers restart one at a time; each hands its jobs over as it stops. Read the release
notes first: when a release moves OpenSearch to a new major version, back up its volume.
Rolling back with `helm rollback` restarts the previous version; see
[Going back to the previous version](servers.md#going-back-to-the-previous-version) for
what a server keeps across that.

## Troubleshooting

- **Pods stay Pending**: no storage class makes their volumes. Set
  `server.persistence.storageClass` and `opensearch.persistence.storageClass`, or give
  the cluster a default one.
- **OpenSearch is not ready**: its `security` container loads OpenSearch's security
  settings and says what went wrong:
  `kubectl -n signalith logs signalith-opensearch-0 -c security`.
- **A server is not ready**: `/readyz` says why
  ([Load balancers](servers.md#load-balancers-readyz-and-livez)), and so does its log:
  `kubectl -n signalith logs signalith-0`.
- **The install fails in the setup Job**: `kubectl -n signalith logs job/signalith-setup`.
  It stays there after a failure, so the next install or upgrade replaces it.
