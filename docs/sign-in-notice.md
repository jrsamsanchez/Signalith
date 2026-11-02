# Sign-in notice

!!! note "Arriving with the next release"
    The sign-in notice is on `main` and comes with the release after 0.4.0.

Signalith can show a notice on its sign-in page, such as who may use the system,
that activity on it is monitored and recorded, and what signing in means. Many
policies ask for one: it is the system use notification of NIST SP 800-53
(AC-8), and the logon banner of the CIS Benchmarks and DISA STIGs. With
**Ask people to agree** on, nobody can sign in on the sign-in page until they
tick **I have read this notice and agree to it**.

The notice is **off** until you write one.

## Setting it

1. Open **Settings > Sign-in notice** (admins).
2. Write the notice, and a title if you want one other than **Notice**.
3. Turn on **Ask people to agree** if they must agree before signing in.
4. Select **Save**. Saving asks for your password or code again, as other
   sign-in settings do.

It applies at once, on every server of a cluster. The tab shows a preview of
the box the sign-in page shows. To turn the notice off, empty it and save.

In `signalith.yaml`:

```yaml
auth:
  notice:
    title: Authorized use only
    text: |
      This system is for authorized use only. Activity on it is monitored
      and recorded, and may be shared with law enforcement.

      By signing in you agree to these terms.
    agree: true
```

## What it shows

- **Plain text only.** The title and notice are shown exactly as typed, with
  their line breaks. Nothing in them is read as HTML, Markdown or a link.
- **Limits.** The notice can be up to 4,000 characters and the title up to 80.
  Control characters other than line breaks and tabs are refused, and so are
  invisible characters that hide words or change the direction of the text,
  so the notice cannot show something other than what was saved.
- A long notice scrolls inside its box, on phones too.

## Agreeing

With **Ask people to agree** on, the server checks the tick too, not only the
page: a sign-in from the sign-in page without it is refused with
`400` and `"code": "notice_not_agreed"`, before the password is checked, so it
counts toward no lockout. That covers every way in from the sign-in page:

- a username and password (and the two-step code after it),
- a passkey,
- single sign-on (OpenID Connect and SAML), checked when the sign-in starts,
- the one-click sign-in of a [public demo](demo.md).

People agree each time they sign in. Each of those sign-ins is logged with
`notice=agreed` in its `signed in` line of the [audit log](audit.md).

API tokens, agent tokens and HTTP Basic auth are for scripts and agents, which
read no page, so they are not asked. Use API tokens for scripts, and turn on
two-step sign-in for people (which stops Basic auth for them).

## Changes

A change to the notice is a settings change: it is in the audit log as
`settings saved`, with who saved it and the new title, text and agree setting.
Only admins can change it, and only the provider's admins on a
[multi-tenant](multi-tenant.md) install.

## API

`GET /api/auth/notice` (admins) returns `{"title", "text", "agree", "on",
"text_max", "title_max", "editable"}`. Save it with `PUT /api/settings` and the
settings `auth.notice.title`, `auth.notice.text` and `auth.notice.agree` (see
[settings.md](settings.md#api)).

The sign-in routes take `"agreed": true` in their body (`POST /api/login`,
`POST /api/login/passkey` and `POST /api/demo`), and the single sign-on starts
take `agreed=1` in their address (`GET /api/auth/oidc/start` and
`GET /api/auth/saml/start`).
