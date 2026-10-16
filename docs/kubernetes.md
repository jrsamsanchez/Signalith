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

    then <https://localhost:9000>, and sign in as `admin`. The browser warns about the
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
| Services | `signalith` (web and API on 9000, agents on 7779), `signalith-syslog`, `signalith-pods`, `signalith-opensearch` | |
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
- **Syslog**: the `signalith-syslog` Service takes UDP and TCP 514 and syslog over TLS on
  6514, with the same settings under `server.syslog.service`. `server.syslog.allow` lists
  the addresses that may send.
- **An ingress controller**: Signalith serves HTTPS itself and agents send their own token,
  so pass connections through (TLS passthrough, such as ingress-nginx's
  `nginx.ingress.kubernetes.io/ssl-passthrough`) rather than ending TLS in the ingress.
  Agents send to port 7779 at the same host, so expose that port too.

Signalith makes and renews its own HTTPS certificate from a CA the servers share
([HTTPS](https.md)). To serve one of your own, such as one from cert-manager, name its
`kubernetes.io/tls` Secret in `server.tls.existingSecret`.

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

## Security

- **Pods**: non-root users (Signalith 65532, OpenSearch 1000), read-only root file systems,
  every capability dropped, no privilege escalation, the runtime's seccomp profile, and no
  Kubernetes API token. They meet the restricted Pod Security Standard, so the namespace
  can enforce it:

    ```sh
    kubectl label namespace signalith pod-security.kubernetes.io/enforce=restricted
    ```

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
