# Multi-tenant mode

Multi-tenant mode lets one Signalith install serve several separate customers, for
example as a managed security provider. Each customer is a **tenant**, with its own
events, findings, investigations, detections, dashboards, lists, playbooks,
notifications, retention and agent tokens, and its own users.

!!! note "Being built"
    Multi-tenant mode arrives in steps. This version runs tenants on a server that does
    not share its users with other servers; the Settings page and the tenant picker come
    next. An install without tenants works exactly as before.

## Who is who

| | Belongs to | Can |
| --- | --- | --- |
| **Provider users** | No tenant: the built-in admin, every user who existed before, and directory and single sign-on users | Work in the default tenant, switch to any tenant, and use the pages about the server itself (Settings, Servers, Security, Audit, sign-in setup, tenants). Their role applies in whichever tenant they are in. |
| **Tenant users** | One tenant | Work only in their tenant, with their role there. A tenant admin manages the tenant's detections, dashboards, agent tokens and so on, but never the server itself. |

The **default tenant** is the data an install had before it had tenants. It keeps the
configured index prefix and folders, so nothing moves when you upgrade.

## How tenants are kept apart

- **Indices.** Tenant `acme` of an install whose `opensearch.index_prefix` is `signalith`
  stores its data in indices that start with `signalith.t.acme`, such as
  `signalith.t.acme-authentication-2026.10.16` and `signalith.t.acme_findings`. The default
  tenant's start with `signalith-` and `signalith_`. Tenant IDs are letters and digits only,
  so no index pattern of one tenant can match another tenant's indices, and a search's
  `index=` must start with the tenant's own prefix. `opensearch.index_prefix` may not
  contain `.t.`.
- **Files.** Each tenant's files are in `tenants/<id>/` in the state folder: its lookups,
  detections, dashboards, archives, response scripts and settings files.
- **Its own server.** Signalith runs each tenant's data with a server of its own inside the
  same process, built from the tenant's own settings. A tenant's request is answered by
  that server only, with that tenant's stores, so nothing can fall back to another
  tenant's data. If it is not running, the request is refused (`503`, code
  `tenant_unavailable`).
- **Agents.** A tenant's agents send with agent tokens made in that tenant (Add data, while
  in the tenant). Their events go to the tenant's indices only. Tokens in `signalith.yaml`
  and the environment are the default tenant's.
- **Sign-in.** Everyone signs in on the same page. A tenant user's session can only ever
  work in their tenant. A provider analyst or admin can switch to any tenant (viewers
  cannot), and every switch is in the audit log. If the tenant a provider user switched
  to is turned off, their next request is refused (`409`, code `tenant_unavailable`) and
  the session goes back to the default tenant, never to another tenant's data silently.
- **Audit.** Every change made in a tenant other than the default one is in the audit log
  with `tenant=<id>`, and so is every log line of that tenant's server, searches
  included.
- **Users.** A tenant's admins see and manage only their tenant's users, and the users
  they add belong to their tenant. Only provider users add provider users. User names are
  unique across the install. A tenant's admins do not count toward the install's last
  admin.
- **Requests to other addresses.** Threat intel feeds, notification channels and response
  action settings make the server send requests to addresses someone types in. They are
  kept per tenant, but only provider users can change or test them, so a tenant's users
  can never make the server reach the provider's own network.
- **Pages about the server.** Tenant users get `403` (code `provider_only`) from every
  route about the server itself, whatever their role, and see only whether things work,
  never how the server runs (see [Roles of every route](users.md#roles-of-every-route)).
- **Turning a tenant off.** Its users cannot sign in (they are told their organization's
  access is turned off), its agents are refused, its background jobs stop, and its data
  stays.

Tenant IDs are 2 to 24 lower-case letters and digits, starting with a letter, such as
`acme` or `contoso2`. `default` is the default tenant's.

## Limits of this version

- Tenants work on a server that keeps its users in its own files. Once servers share
  their users in OpenSearch, which a server running the background jobs sets up on its
  own, tenants cannot be added and provider users cannot switch; the next version lifts
  this.
- Directory (LDAP) and single sign-on users are provider users.
- Syslog, Microsoft 365, vulnerability scans, network sensors, osquery hosts, API tokens and
  compliance notes are the default tenant's. Content updates of the detections go to the
  default tenant; tenants get the detections built into Signalith.
- Downgrading to a version without multi-tenant mode is not supported once there are
  tenant users: an older version would read them as provider users.

## API

`GET /api/tenants` lists the tenants a provider user can switch to, the default tenant
first, and the tenant the request works in:

```json
{"tenants": [{"id": "default", "name": "Default", "default": true},
             {"id": "acme", "name": "Acme"}],
 "active": "default", "enabled": true}
```

`POST /api/tenants/switch` with `{"tenant": "acme"}` moves the signed-in session to that
tenant (`404` for a tenant that does not exist or is turned off). Only a browser session
can switch, as an analyst or admin: API tokens and HTTP Basic sign-ins work in the default
tenant. Both routes are for provider users only.

`POST /api/tenants` with `{"id": "acme", "name": "Acme Corp"}` adds a tenant and starts its
data. `PATCH /api/tenants/{id}` with `{"name": "..."}` renames it, and with
`{"disabled": true}` turns it off (`false` on again). Both are for the provider's admins,
who confirm their password if they signed in a while ago.

`GET /api/me` says which tenant the user belongs to (`"tenant"`, empty for provider users)
and which they work in now (`"active_tenant"`).
