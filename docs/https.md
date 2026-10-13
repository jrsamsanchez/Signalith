# HTTPS

Signalith serves its web UI, API and agent ingest over HTTPS by default. Passwords,
sessions, the ingest token and events never cross the network in clear text, and there
is nothing to set up: the server makes its own certificate the first time it starts.

- [What happens by default](#what-happens-by-default)
- [Trust the certificate](#trust-the-certificate)
- [Names the certificate can cover](#names-the-certificate-can-cover)
- [How far the certificate authority reaches](#how-far-the-certificate-authority-reaches)
- [Switching to a new certificate authority](#switching-to-a-new-certificate-authority)
- [Agents and syslog](#agents-and-syslog)
- [Use your own certificate](#use-your-own-certificate)
- [Behind a reverse proxy](#behind-a-reverse-proxy)
- [Upgrading from plain HTTP](#upgrading-from-plain-http)
- [Settings](#settings)
- [Troubleshooting](#troubleshooting)

Every HTTPS setting described here can also be changed on the **Settings** page
(**Configure > Settings**, the **HTTPS** card), without editing `signalith.yaml`: see
[Settings page](#on-the-settings-page) below.

## What happens by default

With `server.tls.mode: auto` (the default), the first start creates a small certificate
authority for this server, **Signalith Local CA (*hostname*)**, valid for 10 years, and a
server certificate signed by it, valid for 397 days. Signalith renews the server
certificate by itself 30 days before it expires, with the same CA, so nothing has to be
trusted again. Both use ECDSA P-256 keys.

The server certificate covers:

- the host in `server.public_url`,
- this machine's host name and full DNS name,
- its IP addresses (not loopback or link-local ones),
- `localhost`, `127.0.0.1` and `::1`,
- every name in `server.tls.names`,
- every address entered under **Agents send to** (or **Devices send to**) on the **Add
  data** page. Signalith adds it once you have entered it (not while you type), and keeps
  the 32 most recent ones.

The CA can only sign names for this server and for private networks, never for public
websites; see [Names the certificate can cover](#names-the-certificate-can-cover). A
strict one signs only this server's own names; see
[How far the certificate authority reaches](#how-far-the-certificate-authority-reaches).

The files are kept in the `tls` folder of Signalith's state folder (`SIGNALITH_STATE_DIR`,
or else the folder that holds `lookups.dir`; [docs/servers.md](servers.md#identity) says
when another folder is used), next to the master key and this server's identity:

| Install | Folder |
| --- | --- |
| Linux (systemd unit) | `/var/lib/signalith/tls` |
| Windows service | `C:\ProgramData\Signalith\tls` |
| Docker quick start | `/var/lib/signalith/tls` in the `signalith-data` volume |
| Anything else | `tls` next to the `lookups` folder, by default next to `signalith.yaml` |

`ca.pem` is the CA certificate to trust; `server.pem` is the certificate being served.
The keys (`ca.key`, `server.key`) are readable by Signalith's user only (on Windows they
get the access list of the master key: SYSTEM, Administrators and the service). Treat
`ca.key` like a password: whoever has it can make certificates that computers trusting
the CA accept for this server's names. The master key does not encrypt it, so keep it
out of backups that many people can read, as you keep the master key (see
[Backing up the key](encryption.md#backing-up-the-key)). If it is lost, the next start
makes a new CA, and browsers and agents have to trust that one instead.

When Signalith starts it logs the CA file, its SHA-256 fingerprint, the names the
certificate covers and when it expires:

```
level=INFO msg="HTTPS certificate from Signalith's own certificate authority; ..." ca_file=/var/lib/signalith/tls/ca.pem ca_sha256=3A:F1:... names=siem,siem.example.com,192.168.1.20,localhost,127.0.0.1,::1 expires=2027-11-13
```

### One port for HTTPS and plain HTTP

Signalith keeps one port (8080 by default) and looks at the first byte each client sends
to tell HTTPS from plain HTTP, so old `http://` bookmarks and agents still reach it:

- A browser asking for a page over `http://` is sent to the same address over `https://`.
- Signing in, HTTP Basic credentials and session cookies are refused over plain HTTP
  (403, with a message to use `https://`). A password is never accepted in clear text.
- Agents sending events over plain HTTP are accepted or refused by
  `server.tls.plaintext_ingest`; see [Upgrading from plain HTTP](#upgrading-from-plain-http).
  A refused batch gets 503, so the agent keeps it and sends it again later. A batch with a
  wrong token, or none, gets 401, as over HTTPS.

Over HTTPS, browsers are told to use HTTPS only for this site (HSTS), and the session
cookie is `__Host-signalith_session`, which browsers only send over HTTPS. HSTS is not sent
for `localhost` or an IP address: it would apply to every port of that host, so other
tools on `http://localhost` would stop working in that browser.

## Trust the certificate

Until your computer trusts Signalith's CA, browsers show a warning such as "Your connection
is not private". Trust the CA once on each computer you use Signalith from; there is
nothing to do again when the server certificate is renewed.

**1. Get the CA certificate.** Any of these:

- On the sign-in page, click **Download the server certificate**. It saves Signalith's CA
  certificate as `signalith-ca.crt` in your Downloads folder.
- Download `https://<server>:8080/api/tls/ca.pem`; it needs no sign-in.
- Copy `ca.pem` from the server's `tls` folder (see above).

**2. Check it is the right one.** The browser warning means the download itself could
come from someone in the middle, so compare it with what the server says, read on the
server rather than over that same connection. On the computer you downloaded it to:

```sh
openssl x509 -in ~/Downloads/signalith-ca.crt -noout -fingerprint -sha256
```

On Windows, `certutil -dump "$env:USERPROFILE\Downloads\signalith-ca.crt"` prints it as
`Cert Hash(sha256)` (the same hex digits, in lower case and without colons).

It must match the `ca_sha256` Signalith logs when it starts. On the server:

| Install | Command |
| --- | --- |
| Docker quick start, in the Signalith folder | `docker compose -f deploy/docker/docker-compose.yml logs signalith \| grep ca_sha256` (PowerShell: `... logs signalith \| Select-String ca_sha256`) |
| Linux (systemd) | `journalctl -u signalith \| grep ca_sha256`, or `openssl x509 -in /var/lib/signalith/tls/ca.pem -noout -fingerprint -sha256` |
| Windows service | `Select-String ca_sha256 C:\ProgramData\Signalith\signalith.log`, or `certutil -dump C:\ProgramData\Signalith\tls\ca.pem` |

Once one computer trusts the CA, the fingerprint on the **Add data** page is a fine check
for the others: that page is then reached over a connection the browser has checked.

**3. Trust it.** The commands below expect the file in your Downloads folder.

Windows, for your own account (no administrator rights needed; click **Yes** on the
security prompt Windows shows):

```powershell
Import-Certificate -FilePath "$env:USERPROFILE\Downloads\signalith-ca.crt" -CertStoreLocation Cert:\CurrentUser\Root
```

Only if every user of the computer needs it, use `Cert:\LocalMachine\Root` in an elevated
PowerShell instead. Edge and Chrome use the Windows store; restart the browser afterwards.

macOS:

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/Downloads/signalith-ca.crt
```

Safari and Chrome use the keychain; restart the browser afterwards.

Linux, Debian and Ubuntu:

```sh
sudo cp ~/Downloads/signalith-ca.crt /usr/local/share/ca-certificates/signalith-ca.crt
sudo update-ca-certificates
```

Linux, RHEL, Fedora and similar:

```sh
sudo cp ~/Downloads/signalith-ca.crt /etc/pki/ca-trust/source/anchors/signalith-ca.crt
sudo update-ca-trust
```

Chrome and Chromium on Linux keep their own list; add it there too (the `certutil` here
comes from `libnss3-tools` or `nss-tools`):

```sh
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "Signalith Local CA" -i ~/Downloads/signalith-ca.crt
```

Firefox, on any system: **Settings > Privacy & Security > Certificates > View
Certificates > Authorities > Import**, choose the file and tick **Trust this CA to identify
websites**.

Command-line tools take the file directly, for example
`curl --cacert signalith-ca.crt -u admin https://siem.example.com:8080/api/health`.

Signalith's CA only ever signs certificates for this one server. It is limited to
websites (its extended key usage is server authentication only), and to this server's
names and to private network names and addresses (see below). Someone who took `ca.key`
from the server could therefore not use it to read your traffic to public websites, nor
to sign programs, email or client sign-in certificates that computers trusting it would
accept. They could still vouch for other websites on private networks (an intranet site
ending in `.corp` or `.internal`, or a device reached by a private IP address) to every
computer that trusts the CA. A CA made by a version before the website-only limit lacks
it; the Security page says so and offers to make a new one. So:

- trust it only on the computers and accounts that use Signalith (for your own account,
  not the whole computer, as above);
- keep the server's `tls` folder private (Signalith makes it readable by its own account
  only), and include it in what you protect like other secrets;
- if `ca.key` may have leaked, make a new CA and switch to it, then remove the old one
  from the computers that trusted it (see
  [Switching to a new certificate authority](#switching-to-a-new-certificate-authority)).

A strict CA, which vouches only for this server's own names and addresses, takes away
even the private network part; see
[How far the certificate authority reaches](#how-far-the-certificate-authority-reaches).

If you would rather not add a CA, [use your own certificate](#use-your-own-certificate).

## Names the certificate can cover

Computers that trust a CA accept every certificate it signs, so Signalith's CA is made
with limits that browsers, Fluent Bit and other TLS clients enforce. Its extended key
usage is server authentication only, so what it signs is good for websites and nothing
else. Its X.509 name constraints permit no email address or URI (only ones under
`invalid`, a name reserved never to exist), and it can only sign:

- the names and addresses this server had when the CA was made: its host name, full DNS
  name and IP addresses, the `server.public_url` host and `server.tls.names`;
- names that only mean something on a private network: `localhost`, and names ending in
  `.local`, `.localdomain`, `.internal`, `.intranet`, `.lan`, `.home`, `.home.arpa`,
  `.corp` or `.private`;
- private, shared and loopback addresses: `10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `::1`, `fc00::/7`
  and `fe80::/10`.

That is a standard CA, the default. A strict one can sign only the first kind; see
[How far the certificate authority reaches](#how-far-the-certificate-authority-reaches).

Entering another name under **Agents send to** says so, and Health lists any name in
`signalith.yaml` the certificate leaves out. To use such a name, either:

- [use your own certificate](#use-your-own-certificate) for it, or
- put it under `server.tls.names`, then make a new CA that includes it and switch to it,
  as in [Switching to a new certificate authority](#switching-to-a-new-certificate-authority).
  Every browser and agent has to trust the new CA, and the old one keeps working until
  they do.

## How far the certificate authority reaches

Every computer that trusts Signalith's CA accepts any certificate it signs. The
`server.tls.ca_scope` setting (**Certificate authority reaches** on the Settings page)
chooses how far a CA that Signalith makes may vouch. Neither choice lets it vouch for
other public websites: beyond private network names, it may vouch only for this
server's own names, each exactly, never the names under them. So a server named `dev`
gets a CA for `dev`, not for every `.dev` website.

- **Standard** (the default). It can vouch for this server and for private network
  names and addresses, as listed in
  [Names the certificate can cover](#names-the-certificate-can-cover). A new address
  for this server, a new DNS alias or the address Docker publishes works right away.
  If someone stole `ca.key` from the server, they could pose as other private sites,
  such as `intranet.corp` or `192.168.1.5`, to computers that trust the CA.
- **Strict**. It can vouch only for this server's names and addresses as they are when
  the CA is made: its host name and full DNS name, its IP addresses, `localhost`,
  `127.0.0.1` and `::1`, the `server.public_url` host, `server.tls.names`, and the
  addresses entered under **Agents send to** on Add data. Each name and address is
  allowed on its own: not the names under it, nor its whole network. A stolen `ca.key`
  then lets someone pose only as this server's website, to computers that trust the CA
  (the website-only limit above keeps it from vouching for anything else). But a
  new name or address later means a new CA, which every browser and agent must trust
  again.

Strict suits a server whose name and address won't change, especially when:

- the CA is trusted for every user of many computers, for example through Group
  Policy;
- several Signalith servers each have their own CA, all trusted by the same
  computers.

Standard suits Docker and addresses from DHCP. A container sees only its own names,
not the address agents use, such as `192.168.1.20`. With standard, entering that
address under **Agents send to** just works. With strict, put it under
`server.tls.names` before the CA is made, or make a new CA later.

Both keep a name from covering the names under it, such as `a.siem.example.com` under
`siem.example.com`, with the X.509 rule for excluded names. Current browsers, Go and
OpenSSL (which Fluent Bit and curl use on Linux) apply it; a program that ignores name
limits altogether ignores this one too. One exception: when two of the server's names are one
under the other, such as `example.com` and `siem.example.com`, the names under the
shorter one stay allowed, since excluding them would exclude the longer name too.
A CA made by an earlier version of Signalith doesn't have this rule; make a new one to
get it.

The setting is used only when a CA is made: on the first start, and when you make a new
one (see [below](#switching-to-a-new-certificate-authority)). Changing it never replaces
the CA in use, since browsers and agents must trust a new one first. Until you switch,
the Security page and `signalith security` say that the CA in use differs from your
choice (see [docs/security.md](security.md#certificate-authority)).

With a strict CA, a name it doesn't cover is refused under **Agents send to**, with what
to do instead. CAs made by versions before Signalith had limits can vouch for any
website. The Security page marks them **Needs attention**; switch to a new one.

## Switching to a new certificate authority

Make a new CA when:

- `ca.key` may have leaked;
- you need a name or address the CA in use can't cover;
- you want to change between standard and strict;
- the CA was made by an older version without limits, or its 10 years are nearly up.

Browsers and agents must trust a new CA before Signalith uses it. So the change takes a
few steps, and both CAs are trusted in between. Nothing stops working as long as every
computer trusts the new one before you switch.

Each step is on the Security page (**Configure > Security**), for the server that
serves the page. A script can take the same steps with `POST /api/security/ca`, as an
admin, with `{"action": "prepare"}` (and `"scope": "standard"` or `"strict"` if you
want to change it), then `switch`, `rollback`, `discard` or `prune`. Each step goes to
the audit log.

**1. Make the new one.** It uses the **Certificate authority reaches** setting, and
the CA in use keeps serving meanwhile. The new one is named
**Signalith Local CA (*hostname*, *date*)**, so you can tell it from the old one.
Signalith logs its fingerprint (`ca_sha256`) and keeps it in `tls/next/ca.pem` until
you switch.

**2. Share it.** Trust it on every computer that uses Signalith, as in
[Trust the certificate](#trust-the-certificate). Keep the old one trusted for now.

- The sign-in page shows **Download the new server certificate** while a new CA
  waits. It saves `signalith-ca-new.crt`. Without signing in,
  `https://<server>:8080/api/tls/ca.pem?which=next` gives the same file.
- On Linux, copy it as `signalith-ca-new.crt`, so it doesn't replace the old file.
  For Chrome's own list, give it another name: `-n "Signalith Local CA (new)"`.
- Agent configurations from **Add data** now carry both CAs, so give agents a new
  configuration. For devices and agents you set up by hand,
  `https://<server>:8080/api/tls/ca.pem?which=both` gives both in one file.
- Check the fingerprint as in [Trust the certificate](#trust-the-certificate),
  against the `ca_sha256` logged when it was made, or
  `openssl x509 -in /var/lib/signalith/tls/next/ca.pem -noout -fingerprint -sha256` on
  the server.

Fluent Bit keeps batches the server refused. An agent that doesn't trust the new CA
yet keeps its events and sends them once it does.

**3. Switch.** Signalith serves a certificate from the new CA at once, for HTTPS and
syslog over TLS, with no restart. Open connections finish on the old one. The old CA
is kept in `tls/previous`. Until you remove it, the Security page lists the computers
that refused the new certificate, so you can see who still needs it.

**4. Switch back, if you need to.** If something you missed refuses the new
certificate, switch back. The old CA serves again, and the new one waits, still
shared, until you switch again.

Trust the new CA in your own browser before you switch. Signalith tells browsers to
use HTTPS only for its name, so a browser that doesn't trust the new CA can't open the
Security page at that name, and offers no way past the warning. To switch back
without it, either:

- open the page by the server's IP address, such as `https://192.168.1.20:8080`, where
  the browser lets you continue past the warning; or
- run this on the server, which trusts the new CA from the state folder and asks for
  the admin's password (use your port if it isn't 8080):

  ```sh
  curl --cacert /var/lib/signalith/tls/ca.pem -u admin -H 'Content-Type: application/json' \
    -d '{"action":"rollback"}' https://localhost:8080/api/security/ca
  ```

  On Windows, in PowerShell, use `curl.exe` and
  `C:\ProgramData\Signalith\tls\ca.pem`. In Docker, run it on the computer that runs
  Docker with the `ca.pem` from `docker compose cp signalith:/var/lib/signalith/tls/ca.pem .`.

**5. Remove the old one.** Once nothing refuses the new certificate, remove the
previous CA. You can't switch back after that. Then take it out of the computers that
trusted it.

To give up on a new CA before you switch, discard it instead.

If the server stops in the middle of a switch, the next start finishes it or undoes
it, and logs which.

### Removing the old certificate authority from a computer

Windows: find the old one by its name and date, then remove it by its thumbprint, and
click **Yes** when Windows asks. Use `Cert:\LocalMachine\Root`, in an elevated
PowerShell, if you trusted it for every user.

```powershell
Get-ChildItem Cert:\CurrentUser\Root | Where-Object Subject -like '*Signalith Local CA*' | Format-List Subject, NotBefore, Thumbprint
Remove-Item Cert:\CurrentUser\Root\<thumbprint of the old one>
```

macOS: find the old one's SHA-1 hash, then delete it.

```sh
security find-certificate -a -Z -c "Signalith Local CA" /Library/Keychains/System.keychain | grep -E 'SHA-1|"labl"'
sudo security delete-certificate -Z <SHA-1 hash of the old one> /Library/Keychains/System.keychain
```

Linux, Debian and Ubuntu:

```sh
sudo rm /usr/local/share/ca-certificates/signalith-ca.crt
sudo update-ca-certificates --fresh
```

Linux, RHEL, Fedora and similar:

```sh
sudo rm /etc/pki/ca-trust/source/anchors/signalith-ca.crt
sudo update-ca-trust
```

Chrome and Chromium on Linux:

```sh
certutil -d sql:$HOME/.pki/nssdb -D -n "Signalith Local CA"
```

Firefox: **Settings > Privacy & Security > Certificates > View Certificates >
Authorities**. Under **Signalith**, select the old **Signalith Local CA**, then
**Delete or Distrust**.

Agents set up while both CAs were shared trust both until they get a new
configuration from **Add data**. If the old `ca.key` may have leaked, give them one
soon.

## Agents and syslog

The Fluent Bit setup on the **Add data** page checks the server's certificate:

- The configuration sends with `tls On` and `tls.verify On`, with `tls.ca_file` set to
  Signalith's CA (`/etc/fluent-bit/signalith-ca.pem` on Linux,
  `C:\Program Files\fluent-bit\conf\signalith-ca.pem` on Windows).
- When agents send to a name rather than an IP address, it also sets `tls.vhost` to that
  name and `tls.verify_hostname On`, so the agent checks the certificate is for this
  server and not just from a CA it trusts. That needs Fluent Bit 3.1 or later, which the
  install steps get.
- Fluent Bit cannot check an IP address against a certificate. With Signalith's own CA,
  which signs nothing but this server's certificate, checking the CA is enough. With
  [your own certificate](#use-your-own-certificate), whose CA also vouches for other
  computers, an agent sending to an IP address sets `tls.vhost` to a host name the
  certificate carries and checks that instead, so a certificate the same CA issued to
  another computer is refused. A certificate that covers only IP addresses gives it
  nothing to check, so Add data won't make the configuration: use a certificate that
  also includes a host name (agents can keep the IP address), or send to a name.
- One of the steps saves the CA next to the configuration. The page shows its fingerprint,
  **Download** and **Copy** buttons, and the certificate itself under **Show certificate**.
- The steps also make the configuration readable only by root (Linux) or SYSTEM and
  Administrators (Windows), since it holds the ingest token. On Windows they do the same
  for the agent's buffer in `C:\ProgramData\fluent-bit`, which holds Security log events
  until they are sent.

When the certificate comes from a CA the agent's system already trusts (see
[Use your own certificate](#use-your-own-certificate)), there is no CA file to save.

Syslog over TLS (`syslog.tls`, port 6514 in new configs) uses the same certificate. In
**Add data > Syslog**, the rsyslog and syslog-ng setups send over TLS when it is on, with
the CA to save on each server. For other devices, give them `ca.pem` the way their manual
describes, or use UDP or TCP.

## Use your own certificate

To serve a certificate from your company's CA or a public one, set:

```yaml
server:
  tls:
    mode: files
  tls_cert: /etc/signalith/tls/server.pem  # the certificate, then the rest of its chain
  tls_key: /etc/signalith/tls/server.key
```

Relative paths are relative to `signalith.yaml`. Signalith checks the pair when it starts
(`signalith validate` too) and reloads the files within a minute of them changing, so a
renewal needs no restart. Syslog over TLS uses the same certificate.

What agents get depends on the chain:

- A certificate from a CA every system already trusts: agents need no CA file, and the
  sign-in page offers nothing to download.
- A certificate from a private CA, with that CA's certificate at the end of `tls_cert`:
  Add data and the sign-in page offer that CA, as for Signalith's own.
- A private CA that is not in the file: the agent steps ask you to save the CA you got
  from whoever issued the certificate.

The certificate must cover the address agents send to. If it does not, the Add data page
says so and names what it covers. Agents sending to a name check that the certificate is
for that name (`tls.verify_hostname`), so a certificate for another site, even one from
the same CA, is refused. Agents sending to an IP address check one of the certificate's
host names instead, so it must include at least one (see
[Agents and syslog](#agents-and-syslog)).

## Behind a reverse proxy

If a reverse proxy (nginx, Caddy, IIS, a load balancer) adds HTTPS in front of Signalith,
you can keep Signalith on HTTPS too: point the proxy at `https://` and trust Signalith's CA
in the proxy, or simply forward the plain connection to the same port and list the proxy
under `server.trusted_proxies`.

To have Signalith speak plain HTTP to the proxy instead, turn HTTPS off and keep the port
private to the proxy:

```yaml
server:
  listen: 127.0.0.1:8080              # only the proxy on this machine reaches it
  public_url: https://siem.example.com
  tls:
    mode: off
  trusted_proxies: [127.0.0.1]
  client_header: x-forwarded-for      # only if the proxy sets it, see below
```

The proxy must send `X-Forwarded-Proto: https`. Signalith believes that header only from
the addresses in `server.trusted_proxies`; from anyone else it is ignored, since any
client can send it. With it, Signalith sends HSTS and uses the HTTPS-only session cookie.

The proxy should also set `X-Forwarded-For` to the address it got the request from. Then
set `server.client_header: x-forwarded-for` (**Client address header** on the Settings
page), and the failed sign-in limits and the log use each person's own address instead
of the proxy's (see [failed sign-in limits](users.md#signing-in)). The proxy must *set*
the header, not only pass on one the browser sent: otherwise anyone could pick the
address their wrong passwords are counted under. With `server.client_header` empty, the
default, Signalith reads no such header and everyone reaching it through a trusted proxy
counts as one shared address, so nobody can pause sign-ins for the others. For nginx:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    client_max_body_size 20m;
}
```

Without the `X-Forwarded-For` line, nginx passes on whatever the browser sent, so add the
line before you set `server.client_header`. Caddy and Traefik set `X-Forwarded-For`
themselves; HAProxy needs `option forwardfor`; IIS with Application Request Routing sets
it when **Preserve client IP in the following header** is on. A proxy that writes
`Forwarded` (RFC 7239) instead can use `server.client_header: forwarded`.

**Upgrading with a proxy already listed.** Earlier versions did not read
`X-Forwarded-For`, and neither does this one until you set `server.client_header`, so
nothing changes on its own. Until then, wrong passwords through the proxy count against
each account only, not against anyone's address. To count each person by their own
address, add the `X-Forwarded-For` line above to the proxy (if it is nginx), then choose
**X-Forwarded-For** under **Client address header** on the Settings page.

With `mode: off`, `server.listen` reachable from other machines and no
`server.trusted_proxies`, `signalith validate` and the **Health** page warn that passwords
and events cross the network unencrypted.

A `signalith.yaml` from before HTTPS was the default (no `server.tls` section) and without
`server.trusted_proxies` also believes `X-Forwarded-Proto: https` from this machine and
private networks, so a proxy set up the way older versions described keeps working. The
**Health** page then names the proxy; add it under `server.trusted_proxies` and restart.

## Upgrading from plain HTTP

Earlier versions served plain HTTP unless `server.tls_cert` was set. Nothing breaks when
you upgrade:

- **A config without `server.tls` and without `tls_cert`** (the usual case) gets
  `mode: auto` on the same port. An `http://` `public_url` is read as
  `https://` with the same host and port (`:80` when it had no port); the file is not
  changed, and the **Health** page asks you to change it. Browsers on old `http://`
  bookmarks are redirected, and are signed out once, since the session cookie changes.
  Agents set up for `http://` keep sending: for these configs `plaintext_ingest` is
  `allow`.
- **A config with `tls_cert`** gets `mode: files` and works as before.
- **A config without `tls_cert` whose `public_url` is `https://`** was behind a proxy that
  adds HTTPS, so it gets `mode: off` and works as before.
- **Settings saved on the Settings page by an earlier version** count as the config they
  were saved on, with two differences. Certificate files saved there mean `mode: files`,
  as in `signalith.yaml`. An `https://` public address saved there does not turn HTTPS
  off, as one in `signalith.yaml` would, since the page now offers `https://` for every
  address while HTTPS is on: Signalith serves HTTPS on the same port, and a proxy on this
  machine or a private network that sends `X-Forwarded-Proto: https` keeps working (see
  above). Behind a proxy elsewhere, list it under `server.trusted_proxies` in
  `signalith.yaml`, or under **Trusted reverse proxies** on the page opened at
  Signalith's own `https://` address.
- **The Docker quick start** has HTTPS set in its own files now. Updating it also brings
  generated passwords and a secured OpenSearch; see
  [Upgrading the Docker quick start](https://github.com/jrsamsanchez/Signalith/blob/main/README.md#upgrading-the-docker-quick-start).
  Its agents keep sending over `http://`, with the example token
  `change-this-ingest-token` they were given, until you refuse agents on plain HTTP,
  which ends that token for good. A new install refuses both; see
  [The Docker quick start's old example token](#the-docker-quick-starts-old-example-token).

While agents still send over plain HTTP, the **Health** page names them (by address, and
by the host names in their events) and says how to move them over:

1. On **Add data**, build the agent setup again. It now sends to `https://` and checks
   the server with Signalith's CA.
2. Put the CA and the new configuration on each agent and restart it.
3. When the Health page no longer lists any agent, add this to `signalith.yaml`, change
   `public_url` to `https://` if it still says `http://`, and restart Signalith:

   ```yaml
   server:
     tls:
       mode: auto
       plaintext_ingest: deny
   ```

   An agent you missed is then turned away with 503: it keeps its events and sends them
   again, and the Health page names it, until it gets a new configuration.

New configs from `signalith init` and `install.ps1` already have `mode: auto` and
`plaintext_ingest: deny`.

### The Docker quick start's old example token

Older versions of the Docker quick start gave every agent the same ingest token,
`change-this-ingest-token`, over plain HTTP. Anyone can look it up, so it is accepted only
where agents may still have it: on a Docker quick start upgraded from such a version.

On its first start after the update, Signalith asks the quick start's own OpenSearch (the
`opensearch` service in `docker-compose.yml`) when it made each of Signalith's event
indices. One made before the quick start's setup step first ran can only come from the
older version, which had no setup step. A quick start set up to use another OpenSearch,
such as one shared with other servers, counts as new without asking: other servers' events
there say nothing about this install's agents. Then:

- **Upgraded** (there is such an index): agents on plain HTTP are accepted, and the old
  token from them, until you choose **Refuse them** under **Agents on plain HTTP** on the
  Settings page, or set `plaintext_ingest: deny`. That ends the old token for good, even if
  you accept agents on plain HTTP again later. Over HTTPS the old token gets 503, so the
  agent keeps its events.
- **New** (there is none): agents on plain HTTP are refused, and the old token is a wrong
  token like any other (401), over plain HTTP too.

Signalith decides this once and keeps the answer in its state folder (`docker-upgrade.json`
in the `signalith-data` volume), so nothing that happens later changes it: not sample data,
whose events are dated up to a week back but whose indices are made when it loads, nor a
test right after installing, nor anyone sending events. If OpenSearch does not answer on
that first start, Signalith waits up to a minute, then starts anyway and keeps asking; until
it knows, it tells agents on plain HTTP, and agents with the old token, to try again later
(503), so they keep their events. The **Security** page (Agent tokens) says which applies.

Scripts that used `http://` with a user name and password are refused (403) until they
use `https://`; give them the CA, for example `curl --cacert ca.pem`.

## Settings

| Setting | Default | Meaning |
| --- | --- | --- |
| `server.tls.mode` | `auto` | `auto`: Signalith makes and renews its own certificate. `files`: `server.tls_cert` and `tls_key`. `off`: plain HTTP, only behind a reverse proxy that adds HTTPS |
| `server.tls.names` | none | Extra host names or IP addresses for the `auto` certificate, such as a DNS alias or the address a NAT or Docker publishes. Best set before the first start (see [Names the certificate can cover](#names-the-certificate-can-cover)) |
| `server.tls.ca_scope` | `standard` | How far a certificate authority Signalith makes may vouch: `standard` (this server and private network names) or `strict` (only this server's own names and addresses). Used on the first start and when you make a new CA; see [How far the certificate authority reaches](#how-far-the-certificate-authority-reaches) |
| `server.tls.plaintext_ingest` | `deny` (`allow` for configs from before HTTPS was the default, and on a Docker quick start upgraded from one that served plain HTTP, until agents on plain HTTP are first refused) | Whether agents may still send events over plain HTTP |
| `server.trusted_proxies` | none | IPs or CIDRs of reverse proxies whose `X-Forwarded-Proto` header is believed |
| `server.client_header` | none | `x-forwarded-for` or `forwarded`: the header the trusted proxies set to each person's address, for the failed sign-in limits and the log. Only for a proxy that sets it itself (see [Behind a reverse proxy](#behind-a-reverse-proxy)) |
| `server.tls_cert`, `server.tls_key` | none | Your certificate (with its chain) and key, for `mode: files` |
| `syslog.tls` | off (`init` sets `0.0.0.0:6514`) | Syslog over TLS, with the same certificate |
| `SIGNALITH_STATE_DIR` | the folder holding `lookups.dir` | Where the `tls` folder is kept |

### On the Settings page

The **HTTPS** card of the **Settings** page has the same settings: **HTTPS** (`mode`),
**Extra certificate names**, **Certificate authority reaches** (`ca_scope`),
**Certificate file** and **Key file** (used only with your own certificate files),
**Agents on plain HTTP** and **Trusted reverse proxies**. What
is saved there wins over `signalith.yaml` (see [the Settings page](settings.md)); an
`http://` public address saved there is read as `https://` and the page offers to change
it, as for `signalith.yaml`.

- **Certificate authority reaches** changes nothing for browsers or agents when it is
  saved. It is used when you make a new CA on the Security page, which then helps you
  switch to it (see
  [Switching to a new certificate authority](#switching-to-a-new-certificate-authority)).
- **Agents on plain HTTP** and **Trusted reverse proxies** apply as soon as they are
  saved. A list of trusted proxies that leaves out the proxy you opened the page through
  is refused while HTTPS is on, since that proxy would stop working at once.
- The mode, the extra names and the certificate files apply after a restart, which the
  page does in place. The certificate keeps coming from the same certificate authority,
  so nothing has to be trusted again; a restart with new names gives a certificate that
  has them, and a name taken out of the list leaves the certificate at the next restart.
- A public address saved on the page joins the certificate at once, as one entered on
  **Add data** does. A name Signalith's own CA may not sign is shown as a warning on the
  page.
- Turning HTTPS off or on moves the page between `http://` and `https://` on the same
  port, so you sign in again there (behind a trusted reverse proxy the page stays at the
  proxy's address); going between Signalith's own certificate and your
  files asks first, since agents set up to check one do not trust the other. A
  certificate that cannot be loaded or made stops the restart before anything stops.
- Below the settings, **In use now** shows the mode in use, the names the certificate
  covers and the CA's fingerprint, with a link to download the CA.

## Troubleshooting

**The browser still warns after trusting the CA.** Restart the browser. Check you trusted
`signalith-ca.crt`, the file the sign-in page's **Download the server certificate** link
saves (or `ca.pem` from the server), not `server.pem`. Check too that you open Signalith
by a name or address the certificate covers (it is listed in the startup log). To add a
name, enter it under **Agents send to** on Add data, or put it under `server.tls.names`
and restart Signalith; see [Names the certificate can cover](#names-the-certificate-can-cover).

**An agent logs `certificate verify failed`.** The CA file is missing from the path in
`tls.ca_file`, or the agent sends to an address the certificate does not cover. Enter the
address the agent uses under **Agents send to** on Add data, which adds it to the
certificate, and put the new configuration on the agent.

**An agent logs `unknown configuration property 'tls.verify_hostname'`.** Its Fluent Bit
is older than 3.1. Update Fluent Bit with the install step on Add data.

**An agent gets 503 and the Health page says it was turned away.** It sends over plain HTTP
while `plaintext_ingest` is `deny`, or with the old example token from an earlier Docker
quick start. It keeps its events and retries; give it a new configuration from Add data.

**An agent gets 401.** Its ingest token is wrong; on a Docker quick start that started new,
that includes the old example token `change-this-ingest-token` (see
[The Docker quick start's old example token](#the-docker-quick-starts-old-example-token)).
Fluent Bit drops what is refused this way. Give it a new configuration from Add data.

**Signalith cannot write its certificate.** The error names the folder. Give Signalith's
user write access to it, or set `SIGNALITH_STATE_DIR` to a folder it can write.
