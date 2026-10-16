# Multi-tenant mode

Multi-tenant mode lets one Signalith install serve several separate customers, for
example as a managed security provider. Each customer is a **tenant**, with its own
events, findings, investigations, detections, dashboards, lists, playbooks,
notifications, retention and agent tokens, and its own users.

!!! note "Being built"
    Multi-tenant mode arrives in steps. This version knows about tenants, tenant users
    and the provider's pages, but cannot add tenants yet. An install without tenants
    works exactly as before.

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
- **Files.** Each tenant's files are in `tenants/<id>/` in the state folder.
- **Sign-in.** Everyone signs in on the same page. A tenant user's session can only ever
  work in their tenant. A provider user can switch to any tenant, and every switch
  is in the audit log.
- **Pages about the server.** Tenant users get `403` from every route about the server
  itself, whatever their role (see [Roles of every route](users.md#roles-of-every-route)).
- **Turning a tenant off.** Its users cannot sign in (they are told their organization's
  access is turned off) and its data stays.

Tenant IDs are 2 to 24 lower-case letters and digits, starting with a letter, such as
`acme` or `contoso2`. `default` is the default tenant's.

## Limits of this version

- Tenants work on a single server. While several servers share their settings in
  OpenSearch, tenants cannot be added and provider users cannot switch.
- Directory (LDAP) and single sign-on users are provider users.
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
can switch: API tokens and HTTP Basic sign-ins work in the default tenant. Both routes are
for provider users only.

`GET /api/me` says which tenant the user belongs to (`"tenant"`, empty for provider users)
and which they work in now (`"active_tenant"`).
