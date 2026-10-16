# Response actions

A **response action** is something Signalith does outside itself when an analyst
asks: block an IP on the firewall, disable a user in Active Directory, isolate a
host, or start a workflow in a SOAR. Admins set the actions up on the **Response
actions** page (under Detect & respond). Analysts run them from a finding or a case with
**Respond**.

Every run goes the same way:

1. The analyst picks an action, and the target is filled in from the finding's or the
   case's entities with the right kind (an IP for a block action, a user for a
   disable action). They can change it.
2. Actions marked **disruptive** need a reason. Every action that changes something
   is disruptive unless an admin says otherwise; "enable" (undo) actions are not
   by default.
3. A confirm step says exactly what will happen, for example *Disable the AD account
   jdoe in corp.example.com.* Nothing runs before the analyst confirms.
4. The server checks the target strictly for its kind, writes the run to the audit
   log, runs the action, and shows the result and output.
5. The run is noted on the case timeline (where it cannot be removed) or in the
   finding's activity, and kept in the audit log with who ran it, why, on what, and
   what came back.

Signalith does not run actions by itself. Playbooks, which will run actions
automatically, are planned; they will call the same code and be recorded the same
way, as `playbook <name>`.

## Who can do what

| Role | Can |
| --- | --- |
| Viewer | See the timeline entries of runs on a case. |
| Analyst | Run actions from a finding or a case, see past runs. |
| Admin | Add, change, test and delete actions on the **Response actions** page. |

Each user may start at most **30 runs a minute**; more are refused with
`429 Too Many Requests` until the minute is over.

## Targets

An action acts on one kind of target, or on `any`:

| Kind | Accepted | Refused |
| --- | --- | --- |
| `ip` | One IPv4 or IPv6 address (IPv4-mapped IPv6 is turned into IPv4) | Ranges, zones (`fe80::1%eth0`), `0.0.0.0` and `::`, loopback, multicast, broadcast |
| `domain` | Two or more DNS labels: letters, digits and hyphens, up to 253 characters; lower-cased, trailing dot removed | Internationalized names (use their `xn--` form), a last label that is a number |
| `host` | A host name (one or more labels as above) or an IP address | The same as `domain` and `ip` |
| `user` | Letters and digits of any script, `.` `_` `-` `@` `\` and single spaces, up to 256 characters; one `@` and one `\` at most (`jdoe@corp.example.com`, `CORP\jdoe`) | A leading `-` or `.`, quotes, control characters, shell or template syntax |
| `any` | Any of the above. The kind is the one of the entity the analyst picked, else guessed: an address is `ip`, a value with `@`, `\` or a space is `user`, one with a dot is `domain`, anything else is `host`. | |

These rules apply to every action, whatever it does with the target, so a value can
never be read as an option (`-rf`), a second argument or a template.

## Connector kinds

### Send a webhook

Kind `http`. Sends one HTTP request: a method, a URL, headers, and a body built
from a template.

- **Placeholders**: `{{.ip}}`, `{{.domain}}`, `{{.user}}`, `{{.host}}` (the target,
  under its kind), `{{.target}}` and `{{.target_kind}}`, `{{.finding_id}}`,
  `{{.case_id}}`, `{{.actor}}` (who ran it) and `{{.reason}}`. A placeholder of
  another kind is empty: `{{.ip}}` is empty when the target is a user.
- **No template injection**: the text is read once and each placeholder is replaced
  by its value escaped for where it stands. The result is never read again, so a
  value can never add placeholders, template code, JSON or URL syntax.
  - In the **URL**, values are path-escaped before the `?` and query-escaped after
    it. Placeholders cannot stand in the scheme, host or port, so a target can't
    send the request elsewhere.
  - In a **JSON** body, values are escaped as the inside of a JSON string; put
    placeholders between quotes: `{"ip": "{{.ip}}"}`. The body must be valid JSON
    once filled in, which is checked when you save.
  - A **form** body query-escapes values; a **text** body takes them as they are.
- **Headers** are saved encrypted and never shown again. Use `Authorization:
  Bearer <token>` for a token, or the user name and password fields for Basic
  sign-in (not both). Signalith sets `Host`, `Content-Length`, `Content-Type`,
  `Transfer-Encoding` and `Connection` itself.
- The request must use the target, in the URL or the body.
- **Success** is any 2xx answer. The answer's first 64 KB are kept as the run's
  output, with every saved secret replaced by `[hidden]`.

Outbound safety rules, for every request (tests too):

- A 10-second timeout, no proxy, TLS certificates always checked. An action may
  trust one more CA: paste its PEM under **Advanced**.
- Redirects are followed (up to three) only on the same scheme, host and port, so
  a redirect cannot carry the headers to another server.
- Private networks (10/8, 172.16/12, 192.168/16, fc00::/7) are allowed: firewalls
  and automation servers live there. The server's own addresses (loopback) are
  refused unless **Allow this server's own addresses** is ticked, and cloud metadata
  addresses (169.254.169.254 and the like) and OpenSearch's own address are always
  refused. Addresses are checked after the name is looked up, on the connection
  itself, so DNS cannot be used to get around it.

#### Block an IP on OPNsense or pfSense

The **Block IP on OPNsense/pfSense** template adds the IP to a firewall alias:

1. In OPNsense, **Firewall › Aliases**: add a **Host(s)** alias named
   `signalith_block`, empty.
2. **Firewall › Rules** on the WAN (and LAN, for outbound): add a rule that blocks
   source (or destination) `signalith_block`, at the top.
3. **System › Access › Users**: make a user with only the **Firewall: Alias: Edit**
   privilege, then add an API key for it. The key and secret download as a file.
4. In Signalith, pick the template, set the URL to your firewall
   (`https://fw.example.lan/api/firewall/alias_util/add/signalith_block`), and paste
   the key as **API key** and the secret as **API secret**.
5. Add the **Unblock IP on OPNsense (undo)** template the same way, so analysts can
   take a block back.

On pfSense, install the REST API package (`pfSense-pkg-RESTAPI`) and point the URL
at its firewall alias endpoint, with its body format; the template is a starting
point.

#### Shuffle

[Shuffle](https://shuffler.io) is an open-source SOAR. Signalith doesn't include
it: run it as its own program, on its own server, under its own license (AGPL).
To start a workflow from Signalith:

1. In Shuffle, add a **Webhook** trigger to the workflow, start it, and copy its URL.
2. On the **Response actions** page, add the **Shuffle workflow webhook** template
   and paste the URL. It sends the target, its kind, the finding, the case, who ran
   it and why as JSON; use them in the workflow as `$exec.target` and so on.

The webhook answers at once; what the workflow does later shows in Shuffle, not in
the run's output.

### Run a script

Kind `script`. Runs a program on the Signalith server that handled the request.

- **Only programs in the scripts folder can run.** It is `<state>/scripts`
  (`/var/lib/signalith/scripts` on Linux, `C:\ProgramData\Signalith\scripts` on
  Windows), or `response.scripts_dir` in signalith.yaml, or the
  `SIGNALITH_RESPONSE_SCRIPTS_DIR` environment variable. It cannot be changed on a
  page. That is the point: an admin who can change actions on the page still
  can't make Signalith run any program they like, only the ones someone with
  access to the server's files put in that folder.
- The program is a path inside that folder, such as `isolate-host.sh` or
  `edr/isolate.ps1`. It is resolved with every link followed, and must still be
  inside the folder (a symlink to `/bin/sh` is refused), a regular file, and on
  Linux executable and not writable by everyone.
- **No shell.** The program gets the target as its one argument. It also gets
  `SIGNALITH_TARGET`, `SIGNALITH_TARGET_KIND`, `SIGNALITH_FINDING_ID`,
  `SIGNALITH_CASE_ID`, `SIGNALITH_ACTOR` and `SIGNALITH_RUN_ID` in a small
  environment: `PATH` and the few variables programs need (`HOME`, `USER`, `LANG`,
  `TZ`, `TMPDIR`; on Windows `SystemRoot`, `TEMP`, `PSModulePath` and the like). None of Signalith's own
  environment (keys, passwords) is passed on.
- It runs in its own folder, for 60 seconds unless the action says otherwise,
  and at most 10 minutes; then it is stopped, with any programs it started (on
  Linux, its whole process group). Exit code 0 means success.
- Its standard output and error, the first 16 KB, are the run's output.
- **Windows**: `.ps1` scripts run with `powershell.exe -NoProfile -NonInteractive
  -ExecutionPolicy Bypass -File <script> <target>`; `.exe` files run directly.
  `.cmd` and `.bat` files are refused: cmd.exe reads its arguments again, so a
  target could not be passed safely.

Put scripts in the folder with an administrator account, and keep it writable
only by administrators (the **Security** page checks it). Scripts run as the
Signalith service account, so give that account only the rights the scripts need.

#### Example: isolate a Linux host

`isolate-host.sh`, for hosts you manage over SSH with a key the Signalith account
holds. It cuts the host off except for SSH from the management network:

```sh
#!/bin/sh
# isolate-host.sh <host>: firewall a Linux host off the network.
set -eu
host="$1"
case "$host" in -*|*[!A-Za-z0-9.:-]*) echo "bad host: $host" >&2; exit 2;; esac
ssh -o BatchMode=yes -o ConnectTimeout=10 "isolate@$host" -- sudo /usr/local/sbin/isolate-me
echo "Isolated $host (run $SIGNALITH_RUN_ID by $SIGNALITH_ACTOR)."
```

On each host, `/usr/local/sbin/isolate-me` (allowed for the `isolate` user in
sudoers, and nothing else) keeps SSH from the management network and drops the
rest:

```sh
#!/bin/sh
set -eu
nft -f - <<'EOF'
table inet isolate {
  chain input  { type filter hook input priority -10; policy drop;
                 iif lo accept; ct state established,related accept;
                 ip saddr 10.0.10.0/24 tcp dport 22 accept; }
  chain output { type filter hook output priority -10; policy drop;
                 oif lo accept; ct state established,related accept; }
}
EOF
```

`nft delete table inet isolate` on the host undoes it.

#### Example: isolate a Windows host

`isolate-host.ps1`, for domain-joined hosts with PowerShell remoting, run by a
service account allowed to remote into them. It turns on Windows Firewall with
everything blocked except the management network:

```powershell
# isolate-host.ps1 <host>: firewall a Windows host off the network.
param([Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9.-]+$')][string]$ComputerName)
$ErrorActionPreference = 'Stop'
Invoke-Command -ComputerName $ComputerName -ScriptBlock {
    New-NetFirewallRule -DisplayName 'Signalith isolation: management' -Group 'Signalith isolation' `
        -Direction Inbound -RemoteAddress 10.0.10.0/24 -Action Allow | Out-Null
    New-NetFirewallRule -DisplayName 'Signalith isolation: management out' -Group 'Signalith isolation' `
        -Direction Outbound -RemoteAddress 10.0.10.0/24 -Action Allow | Out-Null
    Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block
}
"Isolated $ComputerName (run $env:SIGNALITH_RUN_ID by $env:SIGNALITH_ACTOR)."
```

To undo, set `-DefaultOutboundAction Allow` again and remove the rules of the
`Signalith isolation` group. If you have an EDR, its own isolate API (an `http`
action) is usually the better choice.

#### Velociraptor

[Velociraptor](https://docs.velociraptor.app) can quarantine a host
(`Windows.Remediation.Quarantine`, `Linux.Remediation.Quarantine`) and collect
evidence from it. Like Shuffle it is a separate program you run yourself; Signalith
only calls it. Use its API from a script: give the Signalith account an API client
config (`velociraptor config api_client`) with the **investigator** role, and have
the script start the artifact on the client whose host name is the target with
`velociraptor --api_config api.yaml query "SELECT collect_client(...) FROM ..."`.

### Disable a directory account

Kind `disable_user`. Disables (or enables again) an account in the directory set
up under **Users › Directory sign-in**, by LDAP.

- **Active Directory**: it sets the `ACCOUNTDISABLE` bit (`0x2`) of
  `userAccountControl`; enable clears it. Other bits are left as they are. The
  account is found by `sAMAccountName` or `userPrincipalName` under the user base
  DN, among people (`objectCategory=person`, `objectClass=user`), disabled ones
  included. An account already in the asked state is left alone and reported so.
- **Other LDAP directories** (OpenLDAP, 389 Directory Server, FreeIPA): there is no
  standard "disabled" flag, so the action names the attribute and value that lock an
  account in yours, such as `nsAccountLock: TRUE` on 389 DS and FreeIPA. Disable
  sets it; enable removes it. The account is found with the directory's user filter.
- **Writes need encryption**: the directory must use `ldaps://` or StartTLS, with
  certificates checked. Without it the action refuses to run, and the page says why.
- The action refuses a name that matches more than one account, and refuses to
  change the account it signs in as.

It signs in as the directory sign-in account, or as an account of its own (bind DN
and password on the action, saved encrypted). That account must be allowed to change
users. In Active Directory, delegate only that:

1. In **Active Directory Users and Computers**, right-click the OU that holds the
   users (not the domain, and not one that holds admins) and choose **Delegate
   Control**.
2. Add the service account, choose **Create a custom task to delegate**, **Only the
   following objects in the folder**, tick **User objects**.
3. Under permissions, tick **Property-specific** and then **Read
   userAccountControl** and **Write userAccountControl** (shown together as
   "Read/Write userAccountControl").

Accounts in protected groups (Domain Admins and the like) are guarded by
AdminSDHolder and stay out of reach, which is what you want. If the account lacks
the right, the run fails with *the directory refused the change* and says which
right to delegate.

**Test** on the page signs in and looks the user up (`jdoe`, or what you type),
and changes nothing.

## Templates

**Add action** offers templates; each fills in the form, and you change what you
need:

| Template | Kind | Acts on |
| --- | --- | --- |
| Block IP on OPNsense/pfSense (alias API) | http | ip |
| Unblock IP on OPNsense (undo) | http | ip |
| Block IP via generic webhook | http | ip |
| Shuffle workflow webhook | http | any |
| Isolate host with a script | script | host |
| Disable AD user | disable_user | user |
| Enable AD user (undo) | disable_user | user |

## Testing an action

**Test** on the edit form checks an action without changing anything, as far as its
kind allows: an `http` action fills in its request (shown with secrets hidden) and
checks the server's address; a `script` action finds its program; a `disable_user`
action signs in and finds the user. **Send test request** really sends an `http`
action's request, after asking; it is recorded in the audit log like any run.

## Audit log

Every run is a document in the `<prefix>_actions` OpenSearch index, created at
startup. It is written before the action runs and again when it ends; if it can't
be written, the action does not run. A run holds its ID (`RUN-20261013-…`), the
action, kind, target and its kind, who ran it (or the playbook, and who approved
it), the reason, the finding and case, the status (`running`, `succeeded`,
`failed`), a summary, the output, the error, the server that ran it, and start and
end times. A run left `running` by a server that stopped is shown as
`interrupted`: check the target, since it may or may not have happened.

Each run is also logged (`response action started`, then `response action
succeeded` or `response action failed`, with `audit=true`), and so are changes to the actions (`response
actions changed`) and tests.

## Settings

Actions added on the page are saved in `lookups/response.yaml`, with passwords,
headers and bind passwords encrypted with the server's key. It is not meant to be
edited by hand; if it can't be read, the page says so and nothing runs. To move it,
set:

```yaml
response:
  file: /var/lib/signalith/lookups/response.yaml   # or SIGNALITH_RESPONSE_FILE
  scripts_dir: /var/lib/signalith/scripts          # or SIGNALITH_RESPONSE_SCRIPTS_DIR
```

`signalith rotate-master` re-encrypts the file with the rest.

**Several servers**: each server reads its own `response.yaml` and its own scripts
folder, and an action runs on whichever server handled the analyst's request. Copy
the file (with the same master key) and the scripts to each server that serves the
web UI, or put them on a shared folder.

## API

| Method and path | Role | |
| --- | --- | --- |
| `GET /api/respond/actions` | analyst | The actions analysts can run, without their settings. |
| `POST /api/respond/run` | analyst | Run one: `{"action", "target", "target_kind"?, "finding_id"?, "case_id"?, "reason"}`. Returns the run. |
| `GET /api/respond/runs` | analyst | Past runs, newest first: `?finding_id=`, `?case_id=`, `?action=`, `?limit=` (50, at most 500). |
| `GET /api/respond/config` | admin | The actions with their settings (secrets show only as set or not), templates, scripts. |
| `PUT /api/respond/config` | admin | Replace the actions: `{"actions": [...]}`. A secret is `{"value": "..."}` to set it or `{"keep": true}` to keep the saved one. |
| `POST /api/respond/test` | admin | Test one action: `{"action", "target", "send"}`. |

A saved secret is kept only while the action still sends it to the same place:
the same scheme, host and port for an `http` action (and the same user name for
its password), the same bind DN for a `disable_user` action. Change the URL to
another server and the page asks for the secrets again, so whoever can change an
action can't have its key sent somewhere else.

A run refused before it starts answers `400` (with the `field` at fault), `404`
(no such action, finding or case), `429` (too many runs) or `503` (the audit log
can't be written). A run that started always answers `200` with the run, whose
`status` says how it went.
