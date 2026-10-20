# Single sign-on

People can sign in to Signalith with an identity provider over OpenID Connect, such as
Microsoft Entra ID, Okta, Google or Keycloak, or over [SAML 2.0](#saml-20), such as AD FS,
Okta or Entra ID. Either or both can be on. The sign-in page then shows a
**Sign in with ...** button above the username and password. Local users, directory
sign-in ([users.md](users.md#sign-in-with-active-directory-or-ldap)) and the built-in
admin keep working beside it, so you can't lock yourself out by setting it up wrong.

Each person's role comes from their groups at the provider, checked at every sign-in.
Signalith can add people the first time they sign in, or only let in people an admin
has seen before. With [provisioning (SCIM)](#provisioning-with-scim) on, the provider can
also add people ahead of time, and disable or remove them, which signs them out at once.

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
   `https://siem.example.com:9000/api/auth/oidc/callback`. Most providers accept only
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
(`email_verified`). Entra ID doesn't send that claim: there, add the `xms_edov`
optional claim (step 4 below), which says the address is in a domain the tenant has
verified. Without it, Entra email addresses aren't used for roles or allowed domains.
When the username claim is `email`, as with Google, an address that isn't verified is
refused.

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
   **Security groups**, and for the ID token pick **Group ID**. If you list email
   addresses under the roles, or set allowed email domains, also choose
   **Add optional claim**, **ID**, and tick `email` and `xms_edov`.
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

## SAML 2.0

SAML suits identity providers that speak only SAML, above all AD FS, and organizations
that set up every application with SAML. It sits on its own **SAML 2.0** tab of
**Settings > Single sign-on** and can be on beside OpenID Connect; each shows its own
button on the sign-in page. Roles, **Add users at first sign-in** and
[provisioning](#provisioning-with-scim) work as they do for OpenID Connect.

How a sign-in goes (the Web Browser SSO profile):

1. The button opens `/api/auth/saml/start`, which sends the browser to the provider with
   a sign-in request (an `AuthnRequest`, HTTP-Redirect binding) that has a fresh random ID
   and RelayState. Both are kept in a cookie for 10 minutes, signed with a key the servers
   share so it can't be forged or changed (HttpOnly, Secure, SameSite=None so it survives
   the provider's post back, and `__Host-` over HTTPS).
2. The person signs in at the provider, which posts a signed response to
   `/api/auth/saml/acs` (HTTP-POST binding).
3. Signalith checks the response and its one assertion:
    - the signature, with a signing certificate from the provider's metadata, on the
      response, the assertion or both. An unsigned assertion, SHA-1 or MD5, a document with
      a DTD, an ID used twice, or more than one assertion is refused. Only the part a valid
      signature covers is read, which stops XML signature wrapping attacks.
    - that it answers the request in this browser's cookie (`InResponseTo`, on the response
      and in the signed assertion) with the same RelayState. Sign-ins the provider starts on
      its own (IdP-initiated) are refused, since nothing ties them to the browser.
    - the issuer, the audience (Signalith's entity ID), the recipient and destination (the
      ACS URL), and the time limits, allowing 3 minutes of clock difference.
    - that the assertion was not used before: each is accepted once, on every server (see
      [Several servers](#several-servers)).
4. Signalith starts an ordinary session, as with OpenID Connect.

Encrypted assertions are not supported; the response travels over HTTPS. SAML needs
HTTPS, because browsers keep a SameSite=None cookie only when it is Secure;
`http://localhost` works for trying it out.

On the **SAML 2.0** tab:

1. Copy the **Entity ID** and **ACS URL**. They come from the web address on the
   **Server** tab, so set that first. Signalith's own SAML metadata is at the entity ID
   address, for providers that can read it.
2. Add Signalith as an application at your provider with them (below), and send it the
   groups.
3. Choose the provider and enter its **Metadata URL**. Signalith reads it again every
   hour, so a new signing certificate is picked up by itself. If Signalith can't reach it,
   paste the metadata into **Metadata XML** instead, and paste it again when the
   certificate changes.
4. Map groups to roles, **Test**, turn SAML on and save. Try it in a private window
   before you sign out.

The username comes from the NameID, or from an attribute (**Username attribute**); a
transient NameID, new at every sign-in, can't name a user. Attribute names must match
exactly. The email address comes from `email`, `mail` or the `emailaddress` claim, and the
name from the display name, or the first and last names. Signalith takes the email address
as one the provider vouches for: it can map a role and match a
[provisioned](#provisioning-with-scim) user. Send it from a directory field people can't
change themselves.

A server reads the provider's metadata when it starts and when the SAML settings change.
Until it has, SAML users' sessions are refused there, so moving to another provider ends
the old provider's sessions at once.

### AD FS

1. In AD FS Management, **Relying Party Trusts > Add Relying Party Trust**, claims aware.
   Choose **Import data about the relying party published online** and enter Signalith's
   entity ID (its metadata address), or enter the data by hand: the entity ID as the
   relying party identifier, and the ACS URL as the SAML 2.0 WebSSO service URL.
2. Choose who may sign in (an access control policy).
3. **Edit Claim Issuance Policy > Add Rule > Send LDAP Attributes as Claims**, attribute
   store Active Directory: `User-Principal-Name` as **UPN**, `E-Mail-Addresses` as
   **E-Mail Address**, `Display-Name` as **Name**, and `Token-Groups - Unqualified Names`
   as **Group**.
4. In Signalith, choose **AD FS** and enter
   `https://<AD FS host>/FederationMetadata/2007-06/FederationMetadata.xml`. List group
   names such as `SOC Admins` under the roles.

AD FS signs the assertion with SHA-256 by default. If the relying party trust was set to
SHA-1, set it to SHA-256 on its **Advanced** tab.

### Microsoft Entra ID (SAML)

1. **Enterprise applications > New application > Create your own application**, "Integrate
   any other application you don't find in the gallery".
2. **Single sign-on > SAML**: under **Basic SAML Configuration**, set **Identifier (Entity
   ID)** to Signalith's entity ID and **Reply URL** to the ACS URL.
3. Under **Attributes & Claims**, **Add a group claim**: security groups, or groups
   assigned to the application. Entra ID sends group object IDs (GUIDs); list those under
   the roles. Someone in more than 150 groups gets a link instead of their groups, so
   prefer groups assigned to the application.
4. Copy the **App Federation Metadata Url** from **SAML Certificates** into Signalith,
   with **Microsoft Entra ID** chosen.
5. **Users and groups**: assign the people or groups who may sign in.

Signalith keeps Entra ID's object ID as the person's identity, so a renamed user stays the
same Signalith user. The username is the user principal name.

### Okta (SAML)

1. **Applications > Create App Integration > SAML 2.0**.
2. **Single sign-on URL**: the ACS URL; **Audience URI (SP Entity ID)**: the entity ID;
   **Name ID format**: EmailAddress or Unspecified, **Application username**: Okta
   username.
3. Under **Group Attribute Statements**, add `groups`, filter **Matches regex** `.*` (or
   only the groups Signalith needs). Add an attribute statement `email` with
   `user.email`, and `firstName` and `lastName` if you like.
4. On the **Sign On** tab, copy the **Metadata URL** into Signalith, with **Okta** chosen.
5. Assign the app to the people or groups who may sign in.

### Other SAML providers

Any SAML 2.0 identity provider works if it publishes metadata with a signing certificate
and a single sign-on address for the HTTP-Redirect binding, signs its assertions with
SHA-256 or better, and does not need signed sign-in requests. Send the groups in an
attribute and name it under **Groups attribute**.

## Provisioning with SCIM

Provisioning lets the identity provider manage single sign-on users for you, over SCIM 2.0:

- People assigned to the Signalith app are added to **Users** before they first sign in,
  shown as **Not signed in yet**.
- Name and email changes at the provider reach Signalith within the provider's next cycle.
- Unassigning or disabling someone at the provider disables them in Signalith and **ends
  their sessions at once**, instead of at their next sign-in. Removing them deletes them.

Roles still come from the groups claim at each sign-in, as above; groups are not provisioned.
A provisioned person's first sign-in links their identity, even when **Add users at first
sign-in** is off, but only when it matches what provisioning sent: the ID token's `sub` or
`oid` claim must equal the user's `externalId`, or its verified email address their email. A
matching username alone is not enough, since people can sometimes edit the claim it comes
from. A first sign-in that matches neither is refused, and the server log says so.

If you disable a provisioned user in Signalith, they stay disabled until an admin enables them
here: provisioning only re-enables users it disabled itself. Provisioning only sees single sign-on users: it cannot
change local users, directory users or the built-in admin, and a username one of them has is
refused.

To set it up, under **Settings > Single sign-on**, **Provisioning (SCIM)**:

1. Turn **Provisioning (SCIM)** on.
2. Click **Create token** and copy the token. It is shown only once: Signalith keeps only its
   SHA-256 fingerprint. Click **Save**.
3. Give the provider the **SCIM base URL** (your web address plus `/api/scim/v2`) and the
   token, as below.

Provisioning works only over HTTPS (or from the server itself), so the token is never sent in
the clear. To change the token, click **Replace token** and save; the old one stops working
when you save. Every change provisioning makes is in the audit log, by `scim`.

### Entra ID

1. In **Enterprise applications**, open the Signalith app (the one created with your app
   registration), then **Provisioning**, **Get started**, and set **Provisioning Mode** to
   **Automatic**.
2. Under **Admin Credentials**, enter the SCIM base URL as **Tenant URL** and the token as
   **Secret Token**. Click **Test Connection**, then **Save**.
3. Under **Mappings**, turn off **Provision Microsoft Entra ID Groups**. In the user mapping,
   keep `userPrincipalName` to `userName` (it must match the username claim, normally
   `preferred_username`), `Switch([IsSoftDeleted]...)` to `active`, `displayName` and
   `mail` to `emails[type eq "work"].value`, and change `externalId` to come from
   `objectId`, which Entra ID also sends at sign-in (`oid`); you can delete the others.
4. Set **Scope** to **Sync only assigned users and groups**, turn **Provisioning Status**
   on, and save.

### Okta

1. In the Signalith app, **General**, **Edit**, choose **SCIM** under **Provisioning**, and
   save.
2. Under **Provisioning**, **Integration**, enter the SCIM base URL as **SCIM connector base
   URL**, `userName` as **Unique identifier field for users**, tick **Push New Users**,
   **Push Profile Updates**, and leave **Push Groups** off. Choose **HTTP Header** as the
   authentication mode, paste the token, **Test Connector Configuration**, and save.
3. Under **To App**, enable **Create Users**, **Update User Attributes** and **Deactivate
   Users**.

Okta's username must be what the username claim sends at sign-in (Okta's
`preferred_username` is the login, normally the email address). Okta sends its user id as
`externalId`, which is also the `sub` of its ID tokens.

A username cannot change through provisioning: Signalith answers `400` (`mutability`). To
rename someone, remove them from the app and assign them again.

## Several servers

Servers that share one OpenSearch share the single sign-on settings, and the users, like
other shared settings ([servers.md](servers.md)). The client secret is stored encrypted, and
is only ever sent to the issuer it was entered for: change the provider or the issuer and
you must enter it again.

Register the redirect URI of the address people use, normally the load balancer's (see
[load-balancers.md](load-balancers.md)). The sign-in can start and finish on different
servers. A browser that opens Signalith by another address is sent to that address first,
so the sign-in cookie is where the provider sends the browser back. With SAML, register
the load balancer's address the same way. A SAML assertion is accepted once across every
server. The server that accepts it records it in OpenSearch, and a record OpenSearch
already holds refuses it on every other server, even when two servers get it at the same
moment. If that record can't be written, for example while OpenSearch is down or refuses
writes, the SAML sign-in is refused ("Signalith couldn't save your sign-in"). People can
try again once OpenSearch is back. Records are deleted an hour after their assertion
expires.

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

SAML is under `auth.saml`:

```yaml
auth:
  saml:
    enabled: true
    provider: adfs             # adfs, entra, okta or other
    metadata_url: https://adfs.example.com/FederationMetadata/2007-06/FederationMetadata.xml
    # metadata_xml: '<EntityDescriptor ...>'   instead, if Signalith can't reach the URL
    admin_groups: [SOC Admins]
    analyst_groups: [SOC Analysts]
    default_role: none
    create_users: true
    # username_attribute, groups_attribute and button_label default to the provider's
```

Provisioning is under `auth.scim`: `enabled: true` and `token_sha256`, the SHA-256 (hex) of
the token, which the Single sign-on tab writes for you.

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
| SAML sign-in needs HTTPS | Open Signalith at its `https://` address, and set that address on the **Server** tab. |
| That sign-in was already used | A SAML response was posted twice, such as with the browser's back button. Start again. |

With SAML, the server log says why a response was refused: often an entity ID or ACS URL
at the provider that differs from Signalith's, a clock more than 3 minutes off, or a
sign-in started from the provider's portal (IdP-initiated), which Signalith refuses. Start
from Signalith's sign-in page instead.

When the provider refuses at the token endpoint with `invalid_client`, the client secret
is wrong or expired. Signalith sends it as HTTP Basic, or in the form when the provider's
discovery document lists only `client_secret_post`.

## API

These routes need an admin.

`GET /api/auth/oidc` returns the settings as saved (each with `key`, `value`, and for the
client secret only whether it is set), whether single sign-on is `on`, the `redirect_uri`
to register, the provider `presets`, and `sso_users`, how many single sign-on users there
are. Save changes with `PUT /api/settings` and the `auth.oidc.*` keys
([settings.md](settings.md#api)).

`POST /api/auth/oidc/test` takes `{"values": {...}, "clear": [...]}` with any unsaved
`auth.oidc.*` values, and returns `ok`, a `message` and the `steps` checked. It answers
`400` with `fields` when a value is missing or wrong.

`POST /api/auth/scim/token` makes a new provisioning token and returns `token` and its
`sha256`; nothing changes until `auth.scim.token_sha256` is saved with `PUT /api/settings`.
`GET /api/auth/oidc` also returns `scim_url` and whether provisioning is on (`scim_on`).

`POST /api/auth/saml/test` takes the same body with any unsaved `auth.saml.*` values, reads
the provider's metadata, and returns `ok`, a `message`, the `steps` checked, and Signalith's
`entity_id` and `acs_url`. `GET /api/auth/oidc` also returns them (`saml_entity_id`,
`saml_acs_url`), whether SAML is on (`saml_on`), and the SAML presets (`saml_presets`).

The SCIM endpoints under `/api/scim/v2` take the token as `Authorization: Bearer <token>`
instead of a sign-in: `ServiceProviderConfig`, `ResourceTypes`, `Schemas`, `Users` (`GET`
with `filter` such as `userName eq "alice@example.com"`, `startIndex` and `count`; `POST`),
`Users/{id}` (`GET`, `PUT`, `PATCH`, `DELETE`) and `Groups` (always empty). A user's id is
their Signalith username.

The sign-in itself uses `GET /api/auth/oidc/start` (with an optional `next` path) and
`GET /api/auth/oidc/callback`, which need no sign-in, and so do the SAML ones:
`GET /api/auth/saml/start` (with an optional `next` path), `POST /api/auth/saml/acs`, and
`GET /api/auth/saml/metadata`, Signalith's SAML metadata.
