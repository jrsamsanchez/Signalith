# Users and sign-in

Everyone who signs in to Signalith has one of three roles. People can sign in in
three ways:

| Account | Where it lives | Managed on |
| --- | --- | --- |
| The **built-in admin** | `auth.admin_user` and `auth.admin_password_hash` in `signalith.yaml` | The server, with `signalith passwd` |
| **Local users** | `users.json` in the lookups folder | The **Users** page |
| **Directory users** | Your Active Directory or LDAP server; Signalith keeps a record after their first sign-in | The directory; on the **Users** page you can only disable or delete them |

## Roles

Each role can do everything the roles above it can.

| Role | For | Can |
| --- | --- | --- |
| **Viewer** | Managers, auditors, other teams | Run searches and see dashboards, findings, investigations, detections, risk and intel. Cannot change anything. |
| **Analyst** | SOC analysts | Also triage findings, work investigations, build dashboards, use **Ask** and add or remove intel indicators by hand. |
| **Admin** | Whoever runs Signalith | Also create and change detections, add and change threat intel feeds and upload intel, edit asset and identity lists, see the agent setup (it holds the ingest token), manage users and set up directory sign-in, and change server settings. |

By area:

| Area | Viewer | Analyst | Admin |
| --- | --- | --- | --- |
| Search, query builder, explain, field lists | Yes | Yes | Yes |
| **Ask** (plain English; can call a paid AI model) | No | Yes | Yes |
| Dashboards: view and run | Yes | Yes | Yes |
| Dashboards: create, edit, delete, add panels | No | Yes | Yes |
| Findings: view | Yes | Yes | Yes |
| Findings: status, owner, comments, bulk changes, create | No | Yes | Yes |
| Investigations: view | Yes | Yes | Yes |
| Investigations: create, edit, add findings, notes, entities | No | Yes | Yes |
| Investigations: remove someone else's note, pinned event or search | No | No | Yes |
| Detections and ATT&CK coverage: view | Yes | Yes | Yes |
| Detections: create, edit, delete, test, run, Sigma import | No | No | Yes |
| Risk, asset and identity context: view | Yes | Yes | Yes |
| Asset and identity lists: edit | No | No | Yes |
| Threat intel: view and look up | Yes | Yes | Yes |
| Threat intel: add or remove indicators by hand | No | Yes | Yes |
| Threat intel: add, change, test and refresh feeds, upload files | No | No | Yes |
| Playbooks: see runs, approve or reject steps that wait | No | Yes | Yes |
| Playbooks: create, edit, delete, turn on and off | No | No | Yes |
| Add data (agent setup and ingest token) | No | No | Yes |
| Users and directory sign-in | No | No | Yes |
| Server settings (Settings page, restart) | No | No | Yes |
| Change your own password (local users) | Yes | Yes | Yes |

Dashboards have no owner: any analyst can change or delete any custom dashboard.
Investigation notes, pinned events and saved searches are evidence: an analyst can
remove only the ones they added, and an admin any of them.

When someone tries something their role does not allow, Signalith answers
`403` and says what is needed, for example *"This needs the Analyst role, and your
role is Viewer. Ask an admin if you need access."* The [API section](#api) lists
the role of every route.

A role change, disabling or deleting a user takes effect on that user's next
request: Signalith looks up the role every time instead of remembering it in the
session. If they have Signalith open and try something their new role does not
allow, the page reloads to match the new role and says why.

## The built-in admin

The account in `auth.admin_user` (`admin` unless you changed it) always works, even
when the directory server is down or every other admin has been removed, so you can
always get back in. It shows on the Users page as **Built-in** and cannot be edited,
disabled or deleted there. Change its password on the server:

```sh
signalith passwd -c /etc/signalith/signalith.yaml
```

With the Docker quick start, run
`docker compose -f deploy/docker/docker-compose.yml exec signalith signalith passwd` and
then `docker compose -f deploy/docker/docker-compose.yml restart signalith`. There the
first password comes from a file the setup step made (`signalith initial-password` shows
it), and the new one is kept in `admin-password-hash` in the `signalith-data` volume,
where it replaces the first one.

Keep its password somewhere safe and use your own account day to day. No local user
or directory user can have the built-in admin's name.

## Managing local users

Admins manage users on the **Users** page.

**Add a user.** Enter a username, optionally a name and email address, and pick a
role (Viewer if you don't). Usernames are 1 to 64 lower-case letters, digits, dots,
dashes, underscores or `@`, starting with a letter or digit; they are not case
sensitive. Signalith makes up a temporary password and shows it once (or you can
type one, at least 8 characters). Give it to the person: at their first sign-in they
must choose their own password before they can do anything else.

**Change a user.** Edit their name and email, change their role, disable or enable
them, reset their password (they get a new temporary password and must change it at
the next sign-in), or delete them. Disabling, deleting or resetting a password signs
that user out everywhere at once.

To stop anyone locking everyone out:

- You cannot disable, delete or change the role of your own account. Ask another
  admin.
- Signalith always keeps at least one enabled admin, and the built-in admin counts
  as one.

Passwords are stored as bcrypt hashes and never shown again.

## Changing your password

Local users change their password from the user menu (**Change password**): enter
the current password and the new one (at least 8 characters, at most 72 bytes).
Every other browser signed in as you is signed out, on every server that shares the
users file too. Scripts using your old password with HTTP Basic auth stop working at
once.

Directory users change their password in the directory (for example with
Ctrl+Alt+Del on Windows). The built-in admin's password is changed with
`signalith passwd`.

## Signing in

Sign-in checks the name in this order:

1. **The built-in admin.** If the name is `auth.admin_user`, only its password works.
2. **Local users.** If a local user has the name, only the local password works.
   The directory is never asked about a local username, even with a domain in front
   (`CORP\jane`).
3. **The directory**, if directory sign-in is on.

Failed sign-ins all get the same answer, *"Username and password don't match."*, so
they do not reveal which usernames exist. Other answers are:

| `code` | When |
| --- | --- |
| `wrong_credentials` (401) | Wrong username or password, or an empty one |
| `disabled` (403) | The account is disabled in Signalith |
| `not_in_group` (403) | A directory user in no group mapped to a role: *"Your directory account is not in a group that can use Signalith."* |
| `password_expired` (403) | Active Directory says the password expired or must be changed |
| `directory_unavailable` (503) | The directory server could not be reached, or too many directory sign-ins are being checked at once |
| `locked_out` (429) | Too many wrong passwords; see below |

**Failed sign-in limits.** Wrong passwords are counted so that guessing stays slow,
but someone guessing your password cannot keep you out:

| Counted | Limit | Then |
| --- | --- | --- |
| One address, one account | 10 in 15 minutes | That account is refused from that address for 15 minutes, even with the right password |
| One address, any accounts | 30 in 15 minutes | That address is refused for 15 minutes |
| One account, from browsers and addresses that never signed in to it | 30 in an hour | Their next tries at that account wait: 1 second, then twice as long after each wrong password, up to 15 minutes. The account itself is never locked |

A successful sign-in clears only the count for its own address and account, so
signing in to one account never helps someone guess another's password. Sign-ins
still being checked count too, so a burst of parallel guesses cannot get past the
limit. Wrong directory passwords count; an unreachable directory does not. Basic
auth, **Test a user** with a password, and **Change password** share these limits.
An IPv6 address is counted with the rest of its /64 network, since one computer can
usually use any address in it.

**Browsers you signed in with keep working.** When you sign in, Signalith gives your
browser a cookie that says it has signed in to that account before. The cookie is
sent only over HTTPS, cannot be read by scripts on the page, and lasts a year from
your last sign-in. While someone elsewhere guesses your password, that browser is
not slowed down, and it keeps working even when its address is paused for wrong
passwords to other accounts. An address you signed in from in the last 30 days is not
slowed down either, which keeps scripts using HTTP Basic auth working (they keep no
cookies). Your own wrong passwords count against that browser or address only: 10 in
15 minutes pause it for 15 minutes. Browsers that signed in before share 30 wrong
passwords an hour per account, and addresses that did share another 30; past that
they wait like everyone else, so the guesses an account can take stay limited.
Someone else at an address you once used, such as an office or hotel network, can use
up the addresses' share, but not your browser's. Changing or resetting the password of
a local user or the built-in admin makes every browser and address sign in once more
before it is recognized again (the browser you change your own password in stays
recognized). A built-in admin password from `SIGNALITH_ADMIN_PASSWORD` or
`SIGNALITH_ADMIN_PASSWORD_FILE` keeps its browsers recognized across restarts while it
stays the same.
**Change password** counts against your signed-in browser, so it works while someone
else is guessing your password. The cookie needs HTTPS: over plain HTTP no browser
is remembered. Each server keeps its own key for these cookies, `signin.key` in its
state folder; deleting it only means every browser signs in once more before it is
recognized.

**Many people behind one address.** When people reach Signalith through one address,
such as a reverse proxy, a load balancer, a NAT gateway or Docker Desktop's port
forwarding, Signalith sees that address for all of them, and 30 wrong passwords
from anyone behind it would pause sign-ins for everyone. To avoid that, list the
address on the **Settings** page:

- **A reverse proxy** (nginx, Caddy, IIS, most load balancers): add it under
  **Trusted reverse proxies** (`server.trusted_proxies`). If the proxy sets
  `X-Forwarded-For` itself, also choose **X-Forwarded-For** under **Client address
  header** (`server.client_header`); for nginx that takes
  `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` (see
  [Behind a reverse proxy](https.md#behind-a-reverse-proxy)). Signalith then counts and
  logs each person by the address the proxy got the request from: the right-most
  address in the header that is not a trusted proxy, since the addresses further left
  come from the sender. It reads the header only from the addresses listed there, since
  anyone else could send a made-up one. Without **Client address header**, or for a
  request that comes from the proxy without the header, the proxy counts like an
  address under **Proxies and gateways**.
- **Anything else** (a NAT gateway, a proxy that cannot send the header): add it
  under **Proxies and gateways** (`server.shared_addresses`). Wrong passwords from
  that address are counted for each account only, so it is never refused as a whole,
  and one person's wrong passwords never affect another account.

When an address is refused as a whole, the server log says so and names these
settings.

The web UI keeps you signed in with a session cookie. Sessions end after
`auth.session_timeout` without activity (12 hours by default), after 7 days with
**Keep me signed in**, when you sign out, when your password is changed, or when an
admin disables, deletes or resets your account. Servers that share the users file end
them too, within a second or so.

Scripts and API clients can use HTTP Basic auth with the same username and password.
Signalith remembers a correct username and password briefly so it does not check
the hash or ask the directory on every request: for 10 minutes for local users and
the built-in admin, and 2 minutes for directory users. Changing or resetting a local
password, or changing the directory settings, ends that at once. A password changed
in the directory keeps working for Basic auth for up to 2 minutes. Group changes and
accounts disabled in the directory are picked up as described in
[Directory users who change or leave](#directory-users-who-change-or-leave).

**Temporary passwords.** Signing in with a temporary password works, but the reply
says `"must_change_password": true` and the sign-in page asks for a new password.
Until it is changed, every request other than `GET /api/me` and
`POST /api/me/password` answers `403` with code `password_change_required`.

## Sign in with Active Directory or LDAP

Directory sign-in lets people use their Active Directory or LDAP account, with their
role decided by the groups they are in.

### How it works

When someone signs in with a name that is not the built-in admin or a local user:

1. Signalith connects to the directory server (the failover server if the first
   cannot be reached), over TLS when set up to.
2. It signs in as the service account (or searches anonymously if there is none).
3. It searches under the user base DN with the user filter, the typed name in place
   of `{username}`. Exactly one entry must match; none or several refuse the
   sign-in. `CORP\jane` is looked up as `jane`, and with the Active Directory
   filter `jane@corp.example.com` works too.
4. It checks the password by signing in to the directory as that entry's DN. Empty
   passwords are refused before anything is sent: many LDAP servers treat a sign-in
   with an empty password as anonymous and let it through.
5. It finds the user's groups and maps them to a role. A user in several mapped
   groups gets the highest role. A user in none is refused, unless you choose to let
   such users in as viewers.
6. The user appears on the Users page as a directory user, with their name, email
   and DN from the directory. Their role is updated at every sign-in, and checked
   again every few minutes while they use Signalith (see below).

Directory users who have never signed in are not listed. You can disable a directory
user in Signalith (they stay out whatever the directory says), or delete their record
(it comes back at their next sign-in). Turning directory sign-in off signs out every
directory user at their next request.

### Directory users who change or leave

While a directory user is signed in, Signalith looks them up again with the service
account (without their password) every 5 minutes, and right away when the directory
settings are saved:

- **Groups changed.** Their role follows their groups from their next request.
- **No longer in a mapped group, disabled or deleted in the directory.** Their
  sessions end, and the Users page shows them with no role and the reason. With the
  Active Directory preset, disabled accounts are not found, so they count as
  deleted. A refused sign-in does the same at once.
- **The directory cannot be reached.** They keep the access they had and are checked
  again 5 minutes later. If the settings were changed since their role was last
  checked, their sessions end instead.

So someone who leaves keeps access for at most about 5 minutes. To stop someone at
once, disable them on the Users page.

### Set it up

On the **Users** page, open **Directory sign-in** and click **Set up directory sign-in**:

1. Pick **Active Directory** or **OpenLDAP**. This fills in the filter and attribute
   defaults below; change any of them if your directory differs.
2. Enter the server address and, if you have one, a failover server.
3. Enter the service account's DN and password. The saved password is only used
   with the saved servers, bind DN and TLS settings: change any of those and you
   type the password again, so it can never be sent to a server someone else chose.
4. Enter the user base DN. A group base DN is optional: when it is empty,
   Signalith searches for groups in the whole domain (the `DC=` part of the user's
   DN).
5. Map groups to roles by their full DN.
6. Click **Test connection**, then **Test a user** with your own account, then turn
   directory sign-in on and save.

Settings can be saved switched off while you work on them; they are only required to
be complete when directory sign-in is on.

**Use an encrypted connection.** Passwords are sent to the directory to check them.
Use `ldaps://host` (port 636), or `ldap://host` (port 389) with StartTLS. Signalith
accepts TLS 1.2 or newer and checks the server's certificate against the system's
trusted CAs plus any CA certificate you paste. Plain `ldap://` without StartTLS works
but shows a warning, and so does turning certificate checks off.

**The service account** needs only read access to users and groups. In Active
Directory any domain user account can do this; a dedicated account whose password
does not expire is best, so sign-in does not stop when it expires.

### Active Directory

| Setting | Example |
| --- | --- |
| Server | `ldaps://dc1.corp.example.com` |
| Failover server | `ldaps://dc2.corp.example.com` |
| Service account DN | `CN=svc-signalith,OU=Service Accounts,DC=corp,DC=example,DC=com` |
| User base DN | `DC=corp,DC=example,DC=com` |
| Admin groups | `CN=Signalith Admins,OU=Groups,DC=corp,DC=example,DC=com` |
| Analyst groups | `CN=SOC Analysts,OU=Groups,DC=corp,DC=example,DC=com` |
| Viewer groups | `CN=SOC Viewers,OU=Groups,DC=corp,DC=example,DC=com` |

The Active Directory preset:

- finds users by logon name or `user@domain`, and skips disabled accounts:
  `(&(objectCategory=person)(objectClass=user)(|(sAMAccountName={username})(userPrincipalName={username}))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))`
- reads `sAMAccountName` (username), `displayName` (name) and `mail` (email)
- reads groups from `memberOf`, and with **Nested groups** on (the default) also
  counts groups inside groups: if `IT Leads` is a member of `Signalith Admins`, members
  of `IT Leads` are admins. The domain controller works this out with the
  `LDAP_MATCHING_RULE_IN_CHAIN` rule (`1.2.840.113556.1.4.1941`).

Your domain controllers need an LDAPS certificate for `ldaps://` (most domains with
Active Directory Certificate Services have one). Paste your enterprise root CA's
certificate in **CA certificate** if the Signalith server does not trust it already.

### OpenLDAP

| Setting | Example |
| --- | --- |
| Server | `ldap://ldap.example.org` with StartTLS on, or `ldaps://ldap.example.org` |
| Service account DN | `cn=signalith,ou=services,dc=example,dc=org` |
| User base DN | `ou=people,dc=example,dc=org` |
| Group base DN | `ou=groups,dc=example,dc=org` |
| Admin groups | `cn=signalith-admins,ou=groups,dc=example,dc=org` |
| Analyst groups | `cn=soc,ou=groups,dc=example,dc=org` |

The OpenLDAP preset finds users with `(&(objectClass=inetOrgPerson)(uid={username}))`,
reads `uid`, `cn` and `mail`, and finds groups by searching the group base DN with a
filter that covers the three usual kinds of group:

```
(|(&(objectClass=groupOfNames)(member={dn}))(&(objectClass=groupOfUniqueNames)(uniqueMember={dn}))(&(objectClass=posixGroup)(memberUid={username})))
```

`{dn}` is the user's DN and `{username}` their username as stored in the directory.
If your server has the `memberof` overlay, you can set **Groups** to *memberOf
attribute* instead. Nested groups are only followed on Active Directory.

The same preset works for 389 Directory Server and FreeIPA (users under
`cn=users,cn=accounts,dc=...`, groups under `cn=groups,cn=accounts,dc=...`).

### Testing

**Test connection** connects to each server, signs in as the service account and
checks that the base DNs exist. It tests what is in the form, saved or not. Each step
says what worked or, in plain words, what went wrong and what to do: a name that
does not resolve, a port nothing listens on, a firewall, an untrusted certificate,
a certificate for another name, a refused service account password, a base DN that
does not exist.

**Test a user** looks a user up exactly as sign-in would and shows their DN, every
group found, the groups that matched a role, and the role they would get, or why
they would be refused. Enter their password too to check it; a wrong password there
counts toward the failed sign-in limit like a real sign-in.

### Setting it in signalith.yaml

Instead of the Users page you can put the settings in `signalith.yaml` under
`auth.ldap`, for example to deploy the same settings to several servers. The Users
page then shows them read-only, marked *From signalith.yaml*, and changes made in
the file apply when Signalith restarts.

```yaml
auth:
  ldap:
    type: ad
    url: ldaps://dc1.corp.example.com
    failover_url: ldaps://dc2.corp.example.com
    ca_cert_file: /etc/signalith/corp-root-ca.pem
    bind_dn: CN=svc-signalith,OU=Service Accounts,DC=corp,DC=example,DC=com
    # bind_password: set SIGNALITH_LDAP_BIND_PASSWORD instead
    user_base_dn: DC=corp,DC=example,DC=com
    admin_groups:
      - CN=Signalith Admins,OU=Groups,DC=corp,DC=example,DC=com
    analyst_groups:
      - CN=SOC Analysts,OU=Groups,DC=corp,DC=example,DC=com
    viewer_groups:
      - CN=SOC Viewers,OU=Groups,DC=corp,DC=example,DC=com
```

Directory sign-in is on whenever `auth.ldap` is present, unless it says
`enabled: false`. `type` defaults to `ad`. Keep the service account's password out
of the file with the `SIGNALITH_LDAP_BIND_PASSWORD` environment variable (for example
in the systemd unit's `EnvironmentFile`, or the container's environment). That
variable only applies to `auth.ldap` in `signalith.yaml`: settings made on the Users
page keep their own password in `directory.json`, and Signalith logs a warning at
start-up when the variable is set without `auth.ldap`.

`signalith validate` checks the settings, so run it with the same environment as the
service. `signalith passwd` works without the variable, so the built-in admin's
password can always be reset from a shell.

### Settings reference

The keys are the same in `signalith.yaml` and the API.

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | off on the Users page; on in `signalith.yaml` | Directory sign-in on or off |
| `type` | `ad` | `ad` or `openldap`; fills in the defaults marked *preset* |
| `url` | required | `ldaps://host[:port]` or `ldap://host[:port]` |
| `failover_url` | none | Tried when `url` cannot be reached (not when it refuses a password) |
| `start_tls` | `false` | Encrypt an `ldap://` connection before anything else is sent |
| `ca_cert` | none | PEM certificate(s) of the CA that issued the server's certificate, added to the system's trusted CAs |
| `ca_cert_file` | none | `signalith.yaml` only: read `ca_cert` from this file |
| `tls_skip_verify` | `false` | Accept any certificate. Only for testing: anyone who can intercept the connection can read passwords |
| `connect_timeout_seconds` | `5` | How long to wait for a server to answer a connection (1-120) |
| `timeout_seconds` | `10` | How long to wait for each request (1-300) |
| `bind_dn` | none (anonymous) | The service account that searches for users |
| `bind_password` | none | Its password. The API never returns it, only `bind_password_set`. Leave it empty to keep the saved one, which only works while `url`, `failover_url`, `bind_dn`, `start_tls`, `tls_skip_verify` and `ca_cert` are unchanged. In `signalith.yaml`, `SIGNALITH_LDAP_BIND_PASSWORD` can provide it instead |
| `user_base_dn` | required | Where to search for users |
| `user_filter` | preset | LDAP filter with `{username}` for the typed name (escaped, so `*` and `(` match only themselves) |
| `username_attribute` | preset | Attribute holding the username: `sAMAccountName`, `uid` |
| `name_attribute`, `email_attribute` | preset | `displayName` or `cn`; `mail` |
| `group_search` | preset | `memberof` (read the user's `memberOf`) or `search` (search with `group_filter`) |
| `nested_groups` | `true` for `ad` | Count groups inside groups (Active Directory only) |
| `group_base_dn` | the whole domain | Where to search for groups (nested groups and `search`). Empty uses the `DC=` part of the user's DN, such as `DC=corp,DC=example,DC=com` |
| `group_filter` | preset | Filter for `search`, with `{dn}` and/or `{username}` |
| `admin_groups`, `analyst_groups`, `viewer_groups` | none | Group DNs whose members get each role; the highest wins. Compared the way the directory compares DNs (case and spacing do not matter) |
| `default_role` | `none` | Role for users in no mapped group: `none` refuses them, `viewer` lets them in as viewers |

## Troubleshooting

Start with **Test connection** and **Test a user**; their messages name the problem.
Every sign-in failure is also in the server log with the reason (see
[Audit log](#audit-log)).

**"The server's TLS certificate is not trusted."** Paste the certificate of the CA
that issued the directory server's certificate (for Active Directory, usually the
enterprise root CA, exported as Base-64) under **CA certificate**.

**"The server's TLS certificate is for dc1.corp.example.com, not 10.0.0.5."** Use a
name that is on the certificate in the server address, not an IP address.

**"The server did not answer with TLS."** The port does not speak LDAPS. Use
`ldaps://` with port 636, or `ldap://` with port 389 and StartTLS.

**"refused the connection" or "did not answer within 5 seconds".** Check the address
and port, and that firewalls let the Signalith server reach the directory.

**"The directory refused the service account's bind DN or password."** Check the
full DN (not `CORP\svc-signalith`) and the password. Active Directory adds a reason,
such as *password expired* or *account disabled*.

**"The server does not allow anonymous searches."** Enter a service account. Active
Directory always needs one.

**"The server only accepts sign-ins over an encrypted connection."** Use `ldaps://` or
StartTLS. Active Directory with LDAP signing required refuses plain binds.

**"No user matches."** Check the user base DN (the user must be under it) and the
user filter. With the Active Directory preset, disabled accounts are never found.

**"More than one entry matches."** The filter is too loose, for example two accounts
with the same `uid` in different branches. Narrow the base DN or the filter.

**A user is refused with "Your account can’t use Signalith yet".** **Test a user**
lists every group found. Map one of them to a role, or set `default_role: viewer`.
Check that the DN in the mapping is the group's full DN. Group changes in the
directory apply within about 5 minutes, or at the user's next sign-in.

**Nested groups are not counted.** Nested groups only work on Active Directory with
**Nested groups** on. The groups must be under the group base DN; leave it empty to
search the whole domain. For OpenLDAP, map each group directly.

**"Enter the service account's password again."** You changed the server address,
the failover server, the bind DN or a TLS setting. The saved password is only sent
to the saved servers, so type it again.

**"Too many failed sign-ins."** See [failed sign-in limits](#signing-in). Wait the
time shown, or sign in as another admin, from another address, or as the built-in
admin if it is not the account being guessed. The log shows which address and
account failed. If everyone behind one proxy or NAT gets this message, list that
address as described under **Many people behind one address** in
[Signing in](#signing-in).

**"Many wrong passwords were tried for this account, so sign-ins to it from new
browsers are slowed down."** Someone is guessing that account's password. Sign in
from a browser you have signed in to the account with before, which is not slowed
down, or wait the time shown. The log's `sign-in failed` lines show where the guesses
come from.

**"Your directory password has expired or must be changed."** Active Directory
accepted the password but requires a new one first. The user changes it (for example
by signing in to Windows) and signs in again.

**"Signalith could not reach the directory server."** Sign-in with the built-in admin
and local users still works. Fix the connection, or add a failover server.

**A directory user who left still has access.** Signed-in directory users are looked
up again every 5 minutes (see
[Directory users who change or leave](#directory-users-who-change-or-leave)), and Basic
auth credentials are checked with the directory again after at most 2 minutes. If the
directory cannot be reached, they keep their access until it can. Disable them on
the Users page to stop them at once.

**`signalith validate` says to set `SIGNALITH_LDAP_BIND_PASSWORD`.** Your shell does
not have the service's environment. Load the service's environment file first, for
example `sudo sh -c 'set -a; . /etc/signalith/signalith.env; signalith validate -c /etc/signalith/signalith.yaml'`.

## Where user data is stored

| File | Holds | Default place |
| --- | --- | --- |
| `users.json` | Local users (with bcrypt password hashes), directory users seen so far, last sign-in times | The lookups folder (`lookups.dir`), or `auth.users_file` / `SIGNALITH_USERS_FILE` |
| `directory.json` | Directory sign-in settings from the Users page, including the service account's password | Next to `users.json` |

The lookups folder is:

| Install | Folder |
| --- | --- |
| Docker | `/var/lib/signalith/lookups` in the `signalith-data` volume |
| Linux (systemd) | `/var/lib/signalith/lookups` |
| Windows | `C:\ProgramData\Signalith\lookups` |
| Anywhere else | `lookups` next to `signalith.yaml` |

Both files are written with permissions `0600` (readable only by the account
Signalith runs as), by writing a new file and renaming it so a crash never leaves
half a file. Back them up with the rest of the lookups folder. Edit them only while
Signalith is stopped.

Signalith reads `directory.json` at start-up. It also looks at `users.json` while it
runs, because servers that share a lookups folder share that file (see
[servers.md](servers.md)): before every change it reads the file as it is now, and
otherwise it checks for changes about once a second. While a server changes
`users.json` it keeps a small `users.json.lock` file next to it; leave that file
alone, it goes away by itself.

If `users.json` is damaged, Signalith refuses to start and says so. If it becomes
damaged while Signalith runs, everyone signed in keeps working, but every change on
the **Users** page fails with a message that says so. Either way, fix the file, or
stop Signalith, move the file away and start Signalith again with only the
built-in admin.

## Audit log

Signalith logs every sign-in, sign-out and change to users or directory settings to
its log (journald, the Windows event log, or the container's output), with
`audit=true`, who did it and from which address. Passwords never appear. Changes on
the Settings page and restarts are logged the same way; see
[settings.md](settings.md#audit-log).

| Message | Fields |
| --- | --- |
| `signed in` | `user`, `role`, `source`, `client`, `method` (session or basic) |
| `sign-in failed` | `user`, `client`, `method`, `reason` (for example `wrong password`, `account disabled`, `directory: in no group mapped to a role`), `locked_out` (further tries are refused or slowed down for a while) |
| `sign-ins from this address are paused …` | `client`, `minutes` |
| `signed out` | `user`, `client` |
| `user created` | `by`, `user`, `role`, `must_change_password` |
| `user changed` | `by`, `user`, `fields` |
| `user role changed` | `by`, `user`, `from`, `to` |
| `user disabled`, `user enabled` | `by`, `user`, `sessions_ended` |
| `user deleted` | `by`, `user`, `source`, `role`, `sessions_ended` |
| `password reset` | `by`, `user`, `sessions_ended` |
| `password changed` | `by`, `user`, `other_sessions_ended` |
| `password change refused` | `user`, `client`, `reason`, `locked_out` |
| `directory settings changed` | `by`, `enabled`, `servers`, `fields` (names only) |
| `directory connection tested` | `by`, `servers`, `bind_dn`, `ok` |
| `directory user looked up` | `by`, `user`, `servers`, `ok`, `code`, `password_checked` |
| `directory user lost access` | `by=directory`, `user`, `reason`, `sessions_ended` |
| `directory user's role changed` | `by=directory`, `user`, `from`, `to` |

`client` is the address the request came from. Behind a reverse proxy listed under
**Trusted reverse proxies**, with **Client address header** chosen, it is the address
the proxy forwarded the request for, and `peer` names the proxy. When that header held
no usable address, such as `unknown`, `forwarded` shows what it held, and the request
counts under the proxy's own address.

For example:

```
level=INFO msg="user role changed" audit=true by=ann client=10.0.0.12 user=sam from=analyst to=admin
level=WARN msg="sign-in failed" audit=true user=dave client=10.0.0.40 method=session reason="directory: in no group mapped to a role" locked_out=false
level=WARN msg="sign-in failed" audit=true user=admin client=203.0.113.9 peer=10.0.0.5 method=session reason="wrong password" locked_out=false
```

## API

All routes need a signed-in user (session cookie or HTTP Basic auth) except
`POST /api/login`, `POST /api/logout`, `GET /api/tls/ca.pem`, `POST /api/ingest` and
`POST /api/otlp/v1/logs` (which take an ingest token), and osquery's routes under `/api/osquery/`
(`POST /api/osquery/enroll` takes an ingest token; the others take the node key a host got when it
enrolled; see [endpoints.md](endpoints.md)). Requests from a browser that change something must come from the Signalith
page itself.

### Roles of every route

**Every role** (also allowed while a password change is pending): `GET /api/me`,
`POST /api/me/password`.

**Viewer:** `GET /api/health`, `POST /api/search`, `POST /api/explain`,
`POST /api/build`, `POST /api/parse`, `GET /api/datamodels`, `GET /api/fields`,
`GET /api/fields/values`, `GET /api/language`, `GET /api/ask`,
`GET /api/detections`, `GET /api/detections/{id}`, `GET /api/detections/{id}/yaml`,
`GET /api/coverage`, `GET /api/detections/packs`, `GET /api/findings`, `GET /api/findings/summary`,
`GET /api/findings/{id}`, `GET /api/cases`, `GET /api/cases/summary`,
`GET /api/cases/{id}`, `GET /api/lookups/context`, `GET /api/lookups/{kind}`,
`GET /api/risk`, `GET /api/risk/object`, `GET /api/intel`, `GET /api/intel/feeds`,
`GET /api/intel/catalog`, `GET /api/intel/indicators`, `GET /api/intel/lookup`, `GET /api/posture`,
`GET /api/dashboards`, `GET /api/dashboards/{id}`, `GET /api/dashboards/{id}/yaml`,
`POST /api/dashboards/{id}/run`, `POST /api/panels/run`, and the web UI.

**Analyst:** `POST /api/ask`, `POST /api/findings`, `POST /api/findings/bulk`,
`PATCH /api/findings/{id}`, `POST /api/cases`, `PATCH /api/cases/{id}`,
`POST /api/cases/{id}/findings`, `DELETE /api/cases/{id}/findings/{fid}`,
`POST /api/cases/{id}/entries`, `DELETE /api/cases/{id}/entries/{entry}`,
`POST /api/cases/{id}/entities`, `POST /api/dashboards`, `PUT /api/dashboards/{id}`,
`DELETE /api/dashboards/{id}`, `POST /api/dashboards/{id}/panels`,
`POST /api/intel/indicators`, `DELETE /api/intel/indicators/{id}`, `GET /api/endpoints`,
`GET /api/endpoints/{id}`, `GET /api/endpoints/settings`, `GET /api/endpoints/checks`,
`GET /api/respond/actions`, `GET /api/respond/runs`, `POST /api/respond/run` (running
[response actions](response-actions.md)), `GET /api/playbooks/runs`,
`POST /api/playbooks/runs/{id}/approve`, `POST /api/playbooks/runs/{id}/reject`
(the Approvals page; see [playbooks.md](playbooks.md)).

**Admin:** `GET /api/agents/config`, `POST /api/tls/names`, `GET /api/security`,
`POST /api/security/ca`, `POST /api/detections`,
`POST /api/detections/test`, `POST /api/detections/sigma`, `POST /api/detections/enable`,
`PUT /api/detections/{id}`, `DELETE /api/detections/{id}`,
`POST /api/detections/{id}/run`, `PUT /api/lookups/{kind}`,
`POST /api/intel/feeds`, `PUT /api/intel/feeds/{name}`, `DELETE /api/intel/feeds/{name}`,
`POST /api/intel/feeds/test`, `POST /api/intel/feeds/{name}/refresh`, `POST /api/intel/catalog`,
`POST /api/intel/taxii/collections`, `POST /api/intel/upload`,
`GET /api/respond/config`, `PUT /api/respond/config`, `POST /api/respond/test`
(setting up [response actions](response-actions.md)),
`GET /api/playbooks`, `PUT /api/playbooks` (the Playbooks page; see [playbooks.md](playbooks.md)),
`GET /api/sample`, `POST /api/sample/load`, `POST /api/sample/remove`
(the one-click [sample data](sample-data.md)), `PUT /api/endpoints/settings`,
`DELETE /api/endpoints/{id}`, `GET /api/endpoints/blocked`, `DELETE /api/endpoints/blocked/{host}`,
`POST /api/endpoints/queries`, `GET /api/endpoints/queries/{id}` (the [Endpoints page](endpoints.md)),
`GET /api/cluster` (the Servers page; see [servers.md](servers.md)), every
`/api/notify` route (the Notifications page; see [notifications.md](notifications.md)), every
`/api/retention` route (see [retention.md](retention.md)), every
`/api/users` and `/api/auth/directory` route below, and every `/api/settings` route
(`GET` and `PUT /api/settings`, `POST /api/settings/test/opensearch`,
`POST /api/settings/test/assistant`, `POST /api/settings/restart`,
`GET /api/settings/export`; see [settings.md](settings.md#api)).

A route added without a role is admin-only, and a test fails until it gets one. That
includes routes registered outside the role table, straight on the server's outer
router: any `/api/` route there other than the public ones (sign-in, sign-out, agent
ingest and the CA certificate, `GET /api/tls/ca.pem`) is admin-only.

A refused request:

```json
{"error": "This needs the Analyst role, and your role is Viewer. Ask an admin if you need access.",
 "code": "forbidden", "role": "viewer", "required": "analyst"}
```

### The signed-in user

`GET /api/me`, and the reply to `POST /api/login`:

```json
{"username": "jlee", "user": "jlee", "name": "Jordan Lee", "email": "",
 "role": "analyst", "role_label": "Analyst", "source": "local",
 "must_change_password": true, "can_change_password": true, "auth": "session"}
```

`source` is `builtin`, `local` or `directory`; `auth` is `session` or `basic`.

`POST /api/me/password` with `{"current_password": "...", "new_password": "..."}`
returns the same object. Errors are `400` with a `code`: `wrong_password` (field
`current_password`), `same_password`, `invalid_password` (field `new_password`),
`builtin` or `directory` (those passwords are changed elsewhere).

### Users (admin)

`GET /api/users`:

```json
{
  "users": [
    {"username": "admin", "name": "", "email": "", "role": "admin", "source": "builtin",
     "disabled": false, "must_change_password": false, "created": null, "updated": null,
     "last_sign_in": "2026-10-12T15:35:22Z", "you": true, "actions": []},
    {"username": "alice", "name": "Alice Admin", "email": "alice@corp.example.com",
     "role": "admin", "source": "directory", "disabled": false, "must_change_password": false,
     "dn": "CN=Alice Admin,OU=Staff,DC=corp,DC=example,DC=com",
     "created": "2026-10-12T15:35:11Z", "updated": "2026-10-12T15:35:11Z",
     "last_sign_in": "2026-10-12T15:35:11Z", "you": false, "actions": ["disable", "delete"]}
  ],
  "roles": [{"id": "viewer", "label": "Viewer", "description": "..."}, ...],
  "directory": {"enabled": true, "from_config": false}
}
```

`actions` lists what the signed-in admin may do to that user: `edit` (name and
email), `role`, `reset_password`, `disable` or `enable`, and `delete`. A directory
user the directory no longer lets in has `"role": ""` and `"refused"` saying why, for
example `"in no group mapped to a role"`.

| Route | Body | Reply |
| --- | --- | --- |
| `POST /api/users` | `{"username", "name", "email", "role", "password", "must_change_password"}`; only `username` is required. `role` defaults to `viewer`, an empty `password` makes one up, `must_change_password` defaults to `true` | `201 {"user": {...}, "temporary_password": "kqpp-bsqy-b6hq-mwfm"}` (`temporary_password` only when made up) |
| `PUT /api/users/{username}` | Any of `{"name", "email", "role", "disabled"}` | `{"user": {...}}` |
| `POST /api/users/{username}/password` | Optional `{"password"}` | `{"user": {...}, "temporary_password": "..."}` |
| `DELETE /api/users/{username}` | | `{"deleted": "priya"}` |

Errors are `{"error": "..."}`, with `"field"` naming the form field when one value is
the problem (`username`, `name`, `email`, `role`, `password`): `400` for a bad value,
`404` for an unknown user, `409` for a taken name, the built-in admin, a change to
your own account, the last admin, or a directory user's name, email, role or
password.

### Directory sign-in (admin)

`GET /api/auth/directory` (and the reply to a successful `PUT`):

```json
{
  "settings": {"enabled": true, "type": "ad", "url": "ldaps://dc1.corp.example.com",
               "failover_url": "", "start_tls": false, "ca_cert": "", "tls_skip_verify": false,
               "connect_timeout_seconds": 5, "timeout_seconds": 10,
               "bind_dn": "CN=svc-signalith,OU=Service Accounts,DC=corp,DC=example,DC=com",
               "bind_password_set": true,
               "user_base_dn": "DC=corp,DC=example,DC=com", "user_filter": "(&(objectCategory=person)...)",
               "username_attribute": "sAMAccountName", "name_attribute": "displayName",
               "email_attribute": "mail", "group_search": "memberof", "nested_groups": true,
               "group_base_dn": "", "group_filter": "",
               "admin_groups": ["CN=Signalith Admins,OU=Groups,DC=corp,DC=example,DC=com"],
               "analyst_groups": [], "viewer_groups": [], "default_role": "none"},
  "from_config": false,
  "warnings": [],
  "presets": {"ad": {...}, "openldap": {...}},
  "directory_users": 3
}
```

`from_config` is `true` when the settings come from `signalith.yaml`; `config_file`
then names the file, and `PUT` answers `409`.

`PUT /api/auth/directory` takes the `settings` object (with `bind_password` instead
of `bind_password_set`; leave it empty to keep the saved one). Settings that need
fixing answer `400`:

```json
{"error": "Some settings need fixing: ...",
 "problems": ["\"http://x\" must be ldaps://host or ldap://host, with an optional :port and nothing after it"],
 "fields": {"url": "\"http://x\" must be ldaps://host or ldap://host, with an optional :port and nothing after it"}}
```

`POST /api/auth/directory/test` with an optional `{"settings": {...}}` (the unsaved
form; the saved settings when left out):

```json
{"ok": true, "message": "Connected and signed in as the service account.",
 "servers": [{"url": "ldaps://dc1.corp.example.com", "ok": true,
              "message": "Connected to dc1.corp.example.com over TLS 1.3.",
              "steps": [{"step": "connect", "ok": true, "message": "Connected to dc1.corp.example.com over TLS 1.3."},
                        {"step": "bind", "ok": true, "message": "Signed in as CN=svc-signalith,..."},
                        {"step": "user_base", "ok": true, "message": "Found DC=corp,DC=example,DC=com."}]}]}
```

A failed server has `"ok": false`, a `code` (`connect`, `tls_untrusted`,
`tls_hostname`, `tls_expired`, `tls_handshake`, `starttls_refused`, `ca_cert`,
`encryption_required`, `bind_refused`, `bind_failed`, `bind_required`,
`base_not_found`, `search_refused`, `search_failed`), a plain `message` and the
technical `detail`.

`POST /api/auth/directory/test-user` with `{"username": "alice", "password": "...",
"settings": {...}}` (`password` and `settings` optional):

```json
{"ok": true, "message": "alice would sign in as Admin. The password was not checked.",
 "user": {"username": "alice", "dn": "CN=Alice Admin,OU=Staff,DC=corp,DC=example,DC=com",
          "name": "Alice Admin", "email": "alice@corp.example.com",
          "groups": ["CN=All Staff,OU=Groups,DC=corp,DC=example,DC=com",
                     "CN=IT Leads,OU=Groups,DC=corp,DC=example,DC=com",
                     "CN=Signalith Admins,OU=Groups,DC=corp,DC=example,DC=com"],
          "matched_groups": ["CN=Signalith Admins,OU=Groups,DC=corp,DC=example,DC=com"],
          "role": "admin"},
 "password_checked": false}
```

When the user would be refused, `ok` is `false` and `code` is `user_not_found`,
`multiple_matches`, `wrong_password`, `password_expired`, `no_role`, `refused`, or
one of the connection codes above. `warning` is added when the name belongs to the
built-in admin or a local user, since sign-in would then never ask the directory.
