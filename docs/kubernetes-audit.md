# Kubernetes audit logs

A Kubernetes cluster's API server can keep an **audit log**: every request made of it,
who made it, from where, and what came of it. Pods created and exec'd into, secrets
read, listed and changed, role bindings and admission webhooks edited, cron jobs and
DaemonSets added, services opened on a node port, and requests refused. Signalith takes
the audit log as the API server writes it, makes each event searchable and runs the
SigmaHQ and Splunk Kubernetes rules on it.

## How it works

The API server writes each request as an `audit.k8s.io/v1` **Event**, at the stages and
level its **audit policy** asks for. It can post them to a webhook, in batches (an
`EventList`), or write them to a file, one per line. Either way they reach Signalith's
agent port, `/api/ingest`, with an [agent token](agent-tokens.md) and the tag
`kubernetes`:

- **The webhook backend** (`--audit-webhook-config-file`) sends straight from the API
  server, with nothing to install. This needs access to the API server's flags, so it
  suits clusters you run yourself (kubeadm, k3s, RKE2, kops and the like).
- **Fluent Bit tailing the log file** (`--audit-log-path`) on each control plane node
  works where the API server already writes a file, and keeps events on disk while
  Signalith is out of reach.

An event sent twice (the webhook backend retries a batch it is not sure arrived) is
stored once.

## What you need

- A Signalith [agent token](agent-tokens.md). Create one on the **Add data** page, or
  with `sudo signalith tokens create "Kubernetes audit"`.
- The control plane nodes must reach Signalith's agent port (7779 by default) over
  HTTPS.
- Signalith's CA certificate, `/api/tls/ca.pem` on the server, unless its certificate is
  one the nodes already trust.

## Set it up

### 1. Choose what to record

The audit policy says which requests are recorded, and how much of each. Recording
everything at the `RequestResponse` level makes a great deal of data: start from a
policy that keeps the request body (`Request`) for changes, so rules can see a pod's
spec, and only the metadata for reads. Save it as
`/etc/kubernetes/audit-policy.yaml` on each control plane node:

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
# One event per request, when the answer is complete.
omitStages:
  - RequestReceived
rules:
  # Leave out the noisiest requests that say nothing about who did what.
  - level: None
    users: ["system:kube-proxy"]
    verbs: ["watch"]
  - level: None
    nonResourceURLs: ["/healthz*", "/livez*", "/readyz*", "/version"]
  - level: None
    resources:
      - group: ""
        resources: ["events"]
    verbs: ["get", "list", "watch"]
  # Secrets and ConfigMaps: who touched them, never their contents.
  - level: Metadata
    resources:
      - group: ""
        resources: ["secrets", "configmaps", "serviceaccounts/token"]
  # Token checks and new tokens carry the token itself.
  - level: Metadata
    resources:
      - group: "authentication.k8s.io"
        resources: ["tokenreviews"]
  # Changes, with the object that was sent (a pod's spec, a role binding's subjects).
  - level: Request
    verbs: ["create", "update", "patch", "delete", "deletecollection"]
  # Everything else, its metadata.
  - level: Metadata
```

Keep secrets and tokens at `Metadata`: at `Request` or `RequestResponse` the event would
carry the secret itself. Signalith replaces a Secret's values, a TokenReview's token and a
new service account token with `[redacted]` before storing an event, whatever the
policy, so they are never kept.

### 2a. Send with the webhook backend

Save this as `/etc/kubernetes/signalith-audit.yaml`, with Signalith's address, the CA
certificate's path and the agent token. It is a kubeconfig file, the format the API
server reads its webhook settings in:

```yaml
apiVersion: v1
kind: Config
clusters:
  - name: signalith
    cluster:
      server: https://siem.example.com:7779/api/ingest?tag=kubernetes
      certificate-authority: /etc/kubernetes/signalith-ca.pem
users:
  - name: signalith
    user:
      token: sgl_...
contexts:
  - name: signalith
    context:
      cluster: signalith
      user: signalith
current-context: signalith
```

The file holds the token: make it readable by root only (`chmod 600`). Then add these
flags to the API server. With kubeadm, they go in
`/etc/kubernetes/manifests/kube-apiserver.yaml`, which also needs the two files and the
CA certificate mounted into the API server's pod (`volumes` and `volumeMounts`); the
kubelet restarts the API server when the file changes.

```
--audit-policy-file=/etc/kubernetes/audit-policy.yaml
--audit-webhook-config-file=/etc/kubernetes/signalith-audit.yaml
--audit-webhook-mode=batch
--audit-webhook-batch-max-size=100
```

Each batch is one `EventList`, and Signalith reads its events one by one. A request can
be up to 16 MB, so keep batches small (`--audit-webhook-batch-max-size`) if the policy
records request bodies.

On k3s, pass the same flags with `--kube-apiserver-arg`; on RKE2, under
`kube-apiserver-arg` in its configuration file.

### 2b. Or tail the audit log with Fluent Bit

If the API server writes the log to a file (`--audit-log-path=/var/log/kubernetes/audit/audit.log`),
read it with Fluent Bit on each control plane node. Set up the agent from the **Linux**
card on the **Add data** page first, then add this input to the agent's
`fluent-bit.conf`, next to its other inputs, and restart Fluent Bit:

```
[INPUT]
    Name              tail
    Tag               kubernetes
    Path              /var/log/kubernetes/audit/audit.log
    DB                /var/lib/fluent-bit/signalith-kube-audit.db
    Buffer_Chunk_Size 64k
    Buffer_Max_Size   1M
    Skip_Long_Lines   On
    storage.type      filesystem
```

Each line of the file is one Event. Fluent Bit sends it as it is, under the
`kubernetes` tag, through the agent's output, and Signalith decodes it, so no parsers
file is needed. Lines longer than 1 MB are skipped. The
[OpenTelemetry Collector](opentelemetry.md) works too: its `filelog` receiver passes each
line on as a log record's body, and Signalith recognizes an Event there.

### Managed clusters

EKS, GKE and AKS don't let you set the API server's flags; they send the audit log
through their cloud's logging instead:

- **GKE** writes it to Google Cloud's audit logs, which Signalith reads through a log sink
  and Pub/Sub (see [Google Cloud](google-cloud.md)). Those entries are Google Cloud's,
  with `sourcetype=google:gcp:pubsub:message`, and SigmaHQ's Google Cloud Kubernetes rules
  run on them.
- **EKS** writes it to CloudWatch Logs when the cluster's `audit` log type is turned on
  (log group `/aws/eks/<cluster>/cluster`, streams `kube-apiserver-audit-*`). The
  OpenTelemetry Collector's `awscloudwatch` receiver can read that group; each record's
  body is one Event, which Signalith recognizes as one sent here.
- **AKS** sends it through the cluster's diagnostic settings (category `kube-audit`) to
  an Event Hub, which Signalith reads as Azure records (see [Entra ID and Azure](azure.md)),
  with the Event as text in `properties.log`; the Kubernetes rules don't read those.

## What you get

Each event becomes one event with `sourcetype=_json` and `source=kubernetes`: what
Splunk's own test data for its Kubernetes detections is, and what its `kube_audit` macro
searches. Its fields keep the Event's own names, with nested objects flattened into
dotted names:

| Field | Example |
| --- | --- |
| `verb`, `stage`, `level` | `create`, `ResponseComplete`, `Request` |
| `objectRef.resource`, `.subresource`, `.namespace`, `.name`, `.apiGroup` | `pods`, `exec`, `default`, `debug`, `rbac.authorization.k8s.io` |
| `kube_user.username`, `kube_user.groups{}` | `jane@example.com`, `system:authenticated` (the Event's `user` object, renamed because Signalith's `user` field holds text) |
| `impersonatedUser.username` | the user a request acted as |
| `sourceIPs{}`, `userAgent` | `203.0.113.7`, `kubectl/v1.30.2 (linux/amd64)` |
| `responseStatus.code`, `.reason`, `.message` | `201`, `403`, `Forbidden` |
| `requestURI` | `/api/v1/namespaces/default/pods/debug/exec?command=sh` |
| `annotations.authorization.k8s.io/decision`, `.../reason` | `allow`, why RBAC allowed it |
| `requestObject.spec.containers{}.image`, `requestObject.spec.hostNetwork`, `requestObject.spec.volumes{}.hostPath.path` | what a pod asked for |
| `requestObject.metadata.annotations.kubectl.kubernetes.io/last-applied-configuration` | the object as `kubectl apply` sent it, as JSON text |

Every value is kept as text. The objects sent and returned (`requestObject`,
`responseObject`) can be whole manifests: the fields rules read (containers' images and
security contexts, host namespaces and paths, a CronJob's schedule, a Service's type, a
role binding's subjects) are kept however deep they are, and up to 80 others; all of
the event stays in the raw message. A list keeps its first 50 values. Each event also
gets the data model fields of what it is:

- A request that **creates, changes or deletes** an object (`create`, `update`, `patch`,
  `delete`, `deletecollection`) is a **Change** event, with `action` (created, modified
  or deleted), `command` (the verb), `object` (the object's name), `object_category` (its
  resource, such as `pods`) and `change_type` `Kubernetes`.
- A request refused for **lacking valid credentials** (401) is an **Authentication**
  event with `action` failure.
- Everything else, such as reads and watches, is an **Other** event.

All of them have `user` and `src_user` (the user), `src` (the first source address),
`signature` (the verb and resource, such as `create pods/exec`), `user_agent`,
`object_path` (the request's URI), `result` (the response code), `status` (success, or
failure for a code of 400 or more), `reason` and `id` (the audit ID). Some searches to
start with:

```
sourcetype=_json source=kubernetes verb=create objectRef.subresource=exec | stats count by user, objectRef.namespace, objectRef.name
datamodel=Change sourcetype=_json source=kubernetes | stats count by signature, user
sourcetype=_json source=kubernetes responseStatus.code IN (401, 403) | stats count by src, user, userAgent
```

## Detections

The SigmaHQ pack has 15 Kubernetes rules (see [Detections](detections.md#kubernetes)):
admission controllers, cron jobs and jobs, role bindings and secrets created, changed or
deleted, deployments and events deleted, exec into a container, pods created with a
hostPath volume, with added capabilities or in `kube-system`, RBAC permissions listed,
secrets listed, service accounts created, sidecars patched into a deployment, and
requests refused as unauthorized or forbidden. One, potential enumeration activity, is
experimental and is left out.

The Splunk Security Content pack has 13 Kubernetes rules: secrets read with an unusual
user agent, by an unusual group or user, privileged and host-network pods created or
updated, cron jobs, DaemonSets and node port services created, pods created in the
default and system namespaces, suspicious images pulled, create requests refused, and
scanning: more than 5 refused anonymous requests from one address. The two scanning
rules group by the address's country and city (`iplocation`), so they need a GeoIP
database an admin adds (see [GeoIP database for iplocation](lookups.md#geoip-database-for-iplocation));
without one each run fails with an error the detection shows.
The rules that read an allowed list (`kube_allowed_user_agents` and the like) ship with
Splunk's sample values; set your own in the rule's search after turning it on. Of
Splunk's production rules that read the audit log, one is left out because it compares
the country after filling every empty field (`fillnull`); one more is experimental (`REPORT.md` in each pack
lists every rule left out and why). Turn them on from each pack's page like any other
rules.

## When nothing arrives

- **Look at the API server's log.** The webhook backend logs each batch it fails to
  send, with the HTTP status Signalith gave: `401` for a token Signalith doesn't know,
  `413` for a batch over 16 MB, and a certificate error when the CA file is not
  Signalith's.
- **Check the policy.** With no rule matching (or a first rule of `level: None`), the
  API server records nothing.
- **Search for the events by their tag**: `source=kubernetes` should find them. Events
  sent under another tag are still recognized by their shape (`kind: Event`,
  `apiVersion: audit.k8s.io/v1`).
