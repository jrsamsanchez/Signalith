# AI tools (MCP)

`signalith mcp` is a read-only [Model Context Protocol](https://modelcontextprotocol.io)
server. It lets AI tools such as Claude Desktop, Claude Code, VS Code or Cursor look
things up in Signalith while you chat: run searches, and read findings, cases,
detections, assets and risk.

It **cannot change anything**. It has no tool that writes, it sends only reads to
Signalith's API, and it signs in as a Signalith user, so that user's role decides what
it can see.

## What the AI tool can do

| Tool | What it does |
| --- | --- |
| `whoami` | Shows the Signalith user and role the tools read as |
| `query_help` | Explains the [query language](query-language.md) and lists the data models and their fields |
| `check_query` | Checks a query without running it |
| `search` | Runs a search (50 rows by default, 500 at most) |
| `list_findings`, `get_finding`, `findings_summary` | The findings queue, one finding in full, and counts by status and severity |
| `list_cases`, `get_case` | Investigation cases |
| `list_detections`, `get_detection` | Detections, filtered by text, severity, ATT&CK technique or whether they are on |
| `list_assets`, `lookup_entity` | The asset and identity lists, and the context of one host or user |
| `risk_objects`, `risk_object` | The riskiest users and systems, and the risk events of one |
| `intel_lookup` | Whether a value is a known threat intel indicator |

Every tool needs only the **Viewer** role. Long values and long lists are cut short so
that one large event does not fill the model's context.

## Set it up

### 1. Make a user for the AI tool

Give the AI tool its own Signalith user, so you can see what it does in the audit log
and turn it off on its own.

1. In Signalith, open **Settings > Users** and click **Add user**.
2. Name it, for example `ai-assistant`, and give it the **Viewer** role.
3. If the user must choose a new password at their next sign-in (a temporary
   password), sign in to Signalith once as that user in a private browser window and
   choose its password. The MCP server cannot sign in until
   the temporary password is replaced.

A directory (Active Directory or LDAP) account works too. See [users.md](users.md).

### 2. Get the `signalith` program

The MCP server runs on the computer where the AI tool runs, not on the Signalith server.

- **Windows:** download `signalith-windows-amd64.exe` from the
  [latest release](https://github.com/jrsamsanchez/Signalith/releases/latest), for
  example to `C:\Tools\signalith.exe`.
- **Linux:** download `signalith-linux-amd64`, save it as `/usr/local/bin/signalith`
  and run `chmod +x /usr/local/bin/signalith`.
- **Docker:** see [Running it with Docker](#running-it-with-docker).

On a computer with Signalith installed from a package, the `signalith` program is
already there.

### 3. Trust Signalith's certificate

The MCP server checks Signalith's HTTPS certificate. If you already trust Signalith's
certificate authority in your browser on this computer (see
[Trust the certificate](https.md#trust-the-certificate)), there
is nothing to do on Windows.

Otherwise, download the CA from the link on Signalith's sign-in page
(`signalith-ca.crt`) and point the MCP server at it with `SIGNALITH_CA_FILE`, as in the
examples below.

### 4. Check the settings

In PowerShell:

```powershell
$env:SIGNALITH_URL = "https://siem.example.com:8080"
$env:SIGNALITH_USER = "ai-assistant"
$env:SIGNALITH_PASSWORD = "the password"
C:\Tools\signalith.exe mcp -check
```

On Linux:

```sh
SIGNALITH_URL=https://siem.example.com:8080 SIGNALITH_USER=ai-assistant \
SIGNALITH_PASSWORD='the password' signalith mcp -check
```

It prints the user and role it signed in as, or says what is wrong.

### 5. Add it to your AI tool

#### Claude Desktop

Open **Settings > Developer > Edit Config** in Claude Desktop. That opens
`claude_desktop_config.json` (on Windows, `%APPDATA%\Claude\claude_desktop_config.json`).
Add Signalith under `mcpServers`:

```json
{
  "mcpServers": {
    "signalith": {
      "command": "C:\\Tools\\signalith.exe",
      "args": ["mcp"],
      "env": {
        "SIGNALITH_URL": "https://siem.example.com:8080",
        "SIGNALITH_USER": "ai-assistant",
        "SIGNALITH_PASSWORD": "the password"
      }
    }
  }
}
```

Add `"SIGNALITH_CA_FILE": "C:\\Users\\you\\Downloads\\signalith-ca.crt"` to `env` if
you needed it in step 3. Quit and restart Claude Desktop. Signalith's tools then show
under the tools button in the chat box. Try asking "Which users had the most failed
logins in Signalith in the last day?"

#### Claude Code

```sh
claude mcp add signalith \
  --env SIGNALITH_URL=https://siem.example.com:8080 \
  --env SIGNALITH_USER=ai-assistant \
  --env SIGNALITH_PASSWORD='the password' \
  -- signalith mcp
```

#### Other AI tools

Any tool that runs local (stdio) MCP servers works: give it the command `signalith`
with the argument `mcp`, and the settings below as environment variables.

## Settings

Each setting can be a flag or an environment variable.

| Flag | Environment variable | Meaning |
| --- | --- | --- |
| `-url` | `SIGNALITH_URL` | Signalith's web address, such as `https://siem.example.com:8080`. Plain `http://` is refused except to `localhost`, since it would send the password unencrypted |
| `-user` | `SIGNALITH_USER` | The Signalith user to read as |
| | `SIGNALITH_PASSWORD` | That user's password |
| `-password-file` | `SIGNALITH_PASSWORD_FILE` | A file holding the password, instead of `SIGNALITH_PASSWORD` |
| `-ca` | `SIGNALITH_CA_FILE` | A PEM file of a certificate authority to trust, besides the system's |
| `-check` | | Check the settings, print the user and exit |

The password is not taken as a flag, so it does not show in process lists.

## Running it with Docker

The Signalith image runs the MCP server too. In the AI tool's config, use `docker` as
the command:

```json
"signalith": {
  "command": "docker",
  "args": ["run", "-i", "--rm",
           "-e", "SIGNALITH_URL", "-e", "SIGNALITH_USER", "-e", "SIGNALITH_PASSWORD",
           "ghcr.io/jrsamsanchez/signalith:main", "mcp"],
  "env": {
    "SIGNALITH_URL": "https://siem.example.com:8080",
    "SIGNALITH_USER": "ai-assistant",
    "SIGNALITH_PASSWORD": "the password"
  }
}
```

To trust Signalith's CA, mount it and name it:
`"-v", "C:\\Users\\you\\Downloads\\signalith-ca.crt:/ca.crt:ro", "-e", "SIGNALITH_CA_FILE=/ca.crt"`.
A Signalith server on the same computer is `https://host.docker.internal:8080` from
inside the container.

## Security

- **Read only.** The MCP server sends only GET requests, plus searches and query checks,
  to Signalith. It refuses to send anything else, whatever the user's role allows.
- **The user's role applies.** Signalith checks every request against the user's role,
  as for a person. A Viewer account is enough for every tool.
- **What the model sees goes to its provider.** Search results, findings and cases the
  model reads are sent to whoever runs the model, like anything else in the chat. Unlike
  [Investigate with AI](investigate.md), nothing is masked first. Use a model you are
  allowed to send this data to, or one you run yourself.
- **Event data is untrusted.** Logs can hold text an attacker wrote, such as a user name
  or a command line made to look like instructions. The server tells the model never to
  follow instructions in data, and because every tool only reads, such text cannot make
  the tools change anything. Still check what the model tells you against Signalith
  itself before you act on it.
- **The password is in the AI tool's config file.** Keep that file private. To cut the
  AI tool off, disable its user on **Settings > Users**.
- **Audit.** Requests show in Signalith's log under the AI tool's user, with the user
  agent `signalith-mcp/<version>`.

## Troubleshooting

| Message | What to do |
| --- | --- |
| `Signalith did not accept the username and password` | Check `SIGNALITH_USER` and `SIGNALITH_PASSWORD`. Too many wrong passwords lock the account for a while; see [users.md](users.md#signing-in) |
| `This Signalith user must choose a new password first` | Sign in to Signalith once as this user in a browser and choose a password (step 1) |
| `certificate signed by unknown authority` | Trust Signalith's CA, or set `SIGNALITH_CA_FILE` (step 3) |
| `could not reach Signalith` | Check the address and port, and that this computer can reach the server (try the address in a browser) |
| `This needs the Analyst role` | Not expected for these tools; check that the server runs the same Signalith version |

Claude Desktop keeps each MCP server's messages in its logs: on Windows in
`%APPDATA%\Claude\logs\mcp-server-signalith.log`.
