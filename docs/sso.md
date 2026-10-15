# Single sign-on

People can sign in to Signalith with an OpenID Connect identity provider, such as
Microsoft Entra ID, Okta, Google or Keycloak. The sign-in page then shows a
**Sign in with ...** button above the username and password. Local users, directory
sign-in ([users.md](users.md#sign-in-with-active-directory-or-ldap)) and the built-in
admin keep working beside it, so you can't lock yourself out by setting it up wrong.

Each person's role comes from their groups at the provider, checked at every sign-in.
Signalith can add people the first time they sign in, or only let in people an admin
has seen before.

## How it works

Signalith uses the authorization code flow with PKCE, the flow OpenID Connect
recommends for web applications:

1. The button opens `/api/auth/oidc/start`, which sends the browser to the provider
   with a fresh random `state`, `nonce` and PKCE challenge (S256). They are kept in a
   cookie for 10 minutes (HttpOnly, SameSite=Lax, and `__Host-` and Secure over HTTPS),
   so nothing is held on the server and any server of a cluster can finish the sign-in.
2. The person signs in at the provider, which sends the browser back to
   `/api/auth/oidc/callback` with a one-time code.
3. Signalith checks the `state` against the cookie, trades the code for tokens at the
   provider's token endpoint (with the PKCE verifier and, for a confidential client,
   the client secret), and checks the ID token:
    - its signature, with one of the keys the provider publishes (JWKS). Only RS256,
      RS384, RS512, PS256, PS384, PS512, ES256, ES384 and ES512 are accepted; an
      unsigned token (`none`) or one signed with a shared secret (HS256) is refused.
      RSA keys must be at least 2048 bits.
    - the issuer (`iss`) is exactly the one set up, and the provider's discovery
      document names the same issuer.
    - the audience (`aud`) includes the client ID, and `azp`, when there is one, is the
      client ID.
    - it has not expired, was not issued in the future, and is already valid (`exp`,
      `iat`, `nbf`), allowing two minutes of clock difference.
    - the `nonce` matches the one sent in step 1, so a token can't be replayed.
4. Signalith works out the username, email address and role from the claims, records
   the user and starts an ordinary session. The session follows the same idle sign-out
   and lifetime as any other (see [users.md](users.md#signing-in)).

After signing in, the browser goes back to the page it started from. Only a path on
Signalith itself is accepted there, so the sign-in can't be used to send anyone to
another site.

When something goes wrong, the sign-in page says what in plain words, and the server
log has the details (an `audit` line with `method=sso`).

## Set it up

1. Open **Settings > Single sign-on**.
2. Copy the **Redirect URI**. It is the web address on the Server tab (`server.public_url`)
   followed by `/api/auth/oidc/callback`, for example
   `https://siem.example.com:8080/api/auth/oidc/callback`. Most providers accept only
   `https://` addresses, except for `localhost`.
3. Register Signalith with your provider as a web application with that redirect URI,
   following the section for your provider below. The provider gives you a
   **client ID** and a **client secret**.
4. Choose the provider, enter the **issuer**, the client ID and the client secret, and
   press **Test**. The test reads the provider's discovery document and signing keys
   and checks that PKCE is supported. A full sign-in needs a person, so it isn't tried.
5. Under **Who gets in**, list the groups for each role, and pick what happens to
   anyone else.
6. Turn **Single sign-on** on and **Save**. Try it in a private window before you sign
   out.

Every setting can be saved while single sign-on is off, so you can set it up in
several steps.

### Roles

Each person's role comes from the groups claim of their ID token (or of the userinfo
endpoint, when the ID token has none), at every sign-in:

- **Admins**, **Analysts** and **Viewers** each take a list of groups. An entry can also
  be a verified email address, for a provider that sends no groups (Google) or for one
  person. Matching ignores case. Someone in several lists gets the highest role.
- **Anyone else** is what happens to someone in none of the lists: they are refused
  (the default), or they get the viewer role.
- **Allowed email domains**, when set, lets in only people whose verified email address
  is in one of them. With Google and **Anyone else** set to viewer, this is required,
  since otherwise anyone with a Google account could sign in.
- **Add users at first sign-in** (on by default) adds people the first time they sign in.
  Turned off, only people who have signed in before get in.

An email address only counts when the provider says it is verified
(`email_verified`). Entra ID doesn't send that claim; there, the address is used as
the tenant's own admins set it.

A role change at the provider applies at the person's next sign-in. To take access
away at once, disable the user on the **Users** page: their sessions end, and they
stay out until you enable them, whatever the provider says.

### Users

Single sign-on users show on the **Users** page with the source **Single sign-on**.
Their name, email address and role come from the provider at every sign-in, so you can
only disable or delete them there. They have no Signalith password.

A person is kept by their identity at the provider (the issuer and the `sub` claim),
not only by name. If the username they would get already belongs to someone else (a
local user, a directory user, the built-in admin, or another identity at the provider),
the sign-in is refused rather than taking that account over.

Changing the issuer, or turning single sign-on off, ends the sessions of every single
sign-on user at once.

### Claims

The usual values for each provider are filled in; change them only if your provider
sends something else.

| Setting | Default | What it is |
| --- | --- | --- |
| Scopes | `openid profile email` (Okta adds `groups`) | What Signalith asks the provider for. `openid` is always sent. |
| Username claim | `preferred_username` (`email` for Google) | The claim that becomes the Signalith username. |
| Groups claim | `groups` (none for Google) | The claim that lists the person's groups. A dotted path such as `realm_access.roles` reads a nested claim. |
| Button label | `Sign in with ` and the provider's name | The text on the sign-in page's button. |

## Microsoft Entra ID

1. In the Microsoft Entra admin center, open **App registrations > New registration**.
   Name it Signalith, choose **Accounts in this organizational directory only**, and
   under **Redirect URI** choose **Web** and paste the redirect URI.
2. On the app's **Overview**, copy the **Application (client) ID** and the
   **Directory (tenant) ID**.
3. Under **Certificates & secrets > Client secrets**, add a secret and copy its
   **Value** (not its ID).
4. Under **Token configuration**, choose **Add groups claim**, tick
   **Security groups**, and for the ID token pick **Group ID**.
5. In Signalith, choose **Microsoft Entra ID**. The issuer is
   `https://login.microsoftonline.com/<tenant ID>/v2.0` with your tenant ID (not
   `common` or `organizations`).
6. List the groups' **Object IDs** (GUIDs, as shown on each group's overview) under
   **Admins**, **Analysts** and **Viewers**.

If people belong to more than 200 groups, Entra ID leaves the groups out of the token.
Use app roles instead: under **App roles**, create roles such as `Signalith.Admin`,
assign them to groups under **Enterprise applications > Signalith > Users and groups**,
set the **Groups claim** in Signalith to `roles`, and list the role values.

## Okta

1. In the Okta admin console, open **Applications > Create App Integration**. Choose
   **OIDC - OpenID Connect** and **Web Application**.
2. Paste the redirect URI under **Sign-in redirect URIs**, and assign the groups that
   may use Signalith under **Assignments**.
3. Copy the **Client ID** and the **Client secret** from the app's **General** tab.
4. Under **Security > API > Authorization Servers**, open **default**, then **Claims**,
   and add a claim named `groups`, included in the **ID Token** always, with the value
   type **Groups** and a filter such as **Matches regex** `.*` (or **Starts with**
   `Signalith`).
5. In Signalith, choose **Okta**. The issuer is the authorization server's issuer, such
   as `https://<your org>.okta.com/oauth2/default`.
6. List Okta group names under **Admins**, **Analysts** and **Viewers**.

With the org authorization server (issuer `https://<your org>.okta.com`), add the
groups claim to the app's **Sign On** tab instead; Signalith also reads the groups from
the userinfo endpoint when the ID token has none.

## Google

1. In the Google Cloud console, open **APIs & Services > Credentials > Create credentials >
   OAuth client ID**, and choose **Web application**. (Set up the **OAuth consent screen**
   first if asked; for Google Workspace, choose **Internal**.)
2. Paste the redirect URI under **Authorized redirect URIs**, then copy the client ID
   and the client secret.
3. In Signalith, choose **Google**. Leave the issuer empty: it is always
   `https://accounts.google.com`.
4. Google sends no groups, so list people's email addresses under **Admins**,
   **Analysts** and **Viewers**. To let in everyone of your Google Workspace as a viewer,
   set **Anyone else** to viewer and list your domain under **Allowed email domains**.

The username is the person's email address.

## Keycloak

1. In your realm, open **Clients > Create client**. Keep **OpenID Connect**, enter a
   client ID such as `signalith`, then turn **Client authentication** on and keep only
   **Standard flow**.
2. Paste the redirect URI under **Valid redirect URIs**, then copy the secret from the
   client's **Credentials** tab.
3. Under **Client scopes**, open `signalith-dedicated`, choose **Add mapper > By
   configuration > Group Membership**, name it and set the **Token Claim Name** to
   `groups`. Leave **Full group path** on to match groups as `/soc-analysts`, or turn it
   off to match `soc-analysts`.
4. In Signalith, choose **Keycloak**. The issuer is
   `https://<keycloak host>/realms/<realm>`.
5. List the groups under **Admins**, **Analysts** and **Viewers**, as the mapper sends
   them.

To use realm roles instead of groups, set the **Groups claim** to `realm_access.roles`.

## Other providers

Any provider that supports OpenID Connect discovery and the authorization code flow
works, such as Auth0, Ping, OneLogin, Authentik, Authelia or Dex. Register a web
application with the redirect URI, enter the issuer (the address before
`/.well-known/openid-configuration`), and check which claim carries the groups.

## Several servers

Servers that share one OpenSearch share the single sign-on settings, and the users, like
other shared settings ([servers.md](servers.md)). The client secret is stored encrypted, and
is only ever sent to the issuer it was entered for: change the provider or the issuer and
you must enter it again.

Register the redirect URI of the address people use, normally the load balancer's (see
[load-balancers.md](load-balancers.md)). The sign-in can start and finish on different
servers. A browser that opens Signalith by another address is sent to that address first,
so the sign-in cookie is where the provider sends the browser back.

## Setting it in signalith.yaml

The settings live under `auth.oidc` in `signalith.yaml`:

```yaml
auth:
  oidc:
    enabled: true
    provider: entra            # entra, okta, google, keycloak or other
    issuer: https://login.microsoftonline.com/<tenant ID>/v2.0
    client_id: 00000000-0000-0000-0000-000000000000
    client_secret: ...          # stored encrypted; see below
    admin_groups: [<group object ID>]
    analyst_groups: [<group object ID>]
    viewer_groups: []
    default_role: none          # none or viewer
    allowed_domains: []
    create_users: true
    # scopes, username_claim, groups_claim and button_label default to the provider's
```

Store the client secret with `signalith secrets set auth.oidc.client_secret`, which keeps it
encrypted (see [encryption.md](encryption.md)), or set it in the
`SIGNALITH_OIDC_CLIENT_SECRET` environment variable where Signalith starts.

A provider with a certificate from a private certificate authority must be trusted by the
operating system Signalith runs on.

## Troubleshooting

| The sign-in page says | What to check |
| --- | --- |
| Single sign-on is off | Turn it on under **Settings > Single sign-on**, and save. |
| Signalith could not reach the identity provider | The issuer, and that the server can reach it (proxy, firewall, a private CA the operating system trusts). **Test** says which step failed. |
| The sign-in took too long or was started in another browser | Start again from the sign-in page. Cookies must be allowed for Signalith. |
| You are not in any group that may use Signalith | The groups the provider sent are in the server log; list one of them, or check the groups claim. |
| Your email address is not in an allowed domain | **Allowed email domains**, and that the provider says the address is verified. |
| You have not signed in to Signalith before | **Add users at first sign-in** is off. |
| Another Signalith user already has this name | A local or directory user has the same username. Rename one of them, or change the username claim. |
| The identity provider did not accept the sign-in | The redirect URI registered at the provider must match exactly, and the person must be assigned to the app. |

When the provider refuses at the token endpoint with `invalid_client`, the client secret
is wrong or expired. Signalith sends it as HTTP Basic, or in the form when the provider's
discovery document lists only `client_secret_post`.

## API

Both routes need an admin.

`GET /api/auth/oidc` returns the settings as saved (each with `key`, `value`, and for the
client secret only whether it is set), whether single sign-on is `on`, the `redirect_uri`
to register, the provider `presets`, and `sso_users`, how many single sign-on users there
are. Save changes with `PUT /api/settings` and the `auth.oidc.*` keys
([settings.md](settings.md#api)).

`POST /api/auth/oidc/test` takes `{"values": {...}, "clear": [...]}` with any unsaved
`auth.oidc.*` values, and returns `ok`, a `message` and the `steps` checked. It answers
`400` with `fields` when a value is missing or wrong.

The sign-in itself uses `GET /api/auth/oidc/start` (with an optional `next` path) and
`GET /api/auth/oidc/callback`, which need no sign-in.
