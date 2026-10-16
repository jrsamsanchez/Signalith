# AI tools (MCP)

`signalith mcp` is a read-only [Model Context Protocol](https://modelcontextprotocol.io)
server. It lets AI tools such as Claude Desktop, Claude Code, VS Code or Cursor look
things up in Signalith while you chat: run searches, and read findings, cases,
detections, assets and risk.

It **cannot change anything**. It has no tool that writes, it sends only reads to
Signalith's API, and it signs in with an [API token](#api-tokens) that Signalith lets
only read. The token's role decides what it can see.

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

### 1. Make an API token

Give each AI tool its own token, so you can see what it does in the audit log and cut
it off on its own.

1. In Signalith, open **Settings > API tokens** and click **New token**.
2. Name it after the tool and where it runs, for example `Claude Desktop on Ana's
   laptop`, and keep the **Viewer** role.
3. Click **Create token** and copy the token (it starts with `sgl_api_`). Signalith
   shows it only once and keeps only a fingerprint of it. If you lose it, revoke it and
   make a new one.

The dialog also shows the command that adds Signalith to Claude Code with the token
filled in. See [API tokens](#api-tokens) for how tokens work.

!!! note "Signing in as a user instead"
    The MCP server can also sign in as a Signalith user with `SIGNALITH_USER` and
    `SIGNALITH_PASSWORD`, as before. Make the user a **Viewer** on **Settings > Users**,
    and if it has a temporary password, sign in once as that user in a browser to choose
    its own. A token is better: it can't sign in to the web page, it only reads, and you
    can revoke it without touching anyone's password.

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
$env:SIGNALITH_URL = "https://siem.example.com:9000"
$env:SIGNALITH_TOKEN = "sgl_api_..."
C:\Tools\signalith.exe mcp -check
```

On Linux:

```sh
SIGNALITH_URL=https://siem.example.com:9000 SIGNALITH_TOKEN=sgl_api_... signalith mcp -check
```

It prints the name and role it reads as (`api-token:<name>` for a token), or says what
is wrong.

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
        "SIGNALITH_URL": "https://siem.example.com:9000",
        "SIGNALITH_TOKEN": "sgl_api_..."
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
  -e SIGNALITH_URL=https://siem.example.com:9000 \
  -e SIGNALITH_TOKEN=sgl_api_... \
  -- signalith mcp
```

Add `--scope user` to use it in every project. Run `/mcp` in Claude Code to check that
it connected.

#### VS Code

Run **MCP: Open User Configuration** from the command palette, or make `.vscode/mcp.json`
in a workspace. VS Code can ask for the token the first time and keep it in its secret
storage, so it is not saved in the file:

```json
{
  "inputs": [
    { "type": "promptString", "id": "signalith-token", "description": "Signalith API token", "password": true }
  ],
  "servers": {
    "signalith": {
      "type": "stdio",
      "command": "signalith",
      "args": ["mcp"],
      "env": {
        "SIGNALITH_URL": "https://siem.example.com:9000",
        "SIGNALITH_TOKEN": "${input:signalith-token}"
      }
    }
  }
}
```

#### Cursor

Open **Cursor Settings > MCP > Add new MCP server**, or edit `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "signalith": {
      "command": "signalith",
      "args": ["mcp"],
      "env": {
        "SIGNALITH_URL": "https://siem.example.com:9000",
        "SIGNALITH_TOKEN": "sgl_api_..."
      }
    }
  }
}
```

#### Other AI tools

Any tool that runs local (stdio) MCP servers works: give it the command `signalith`
with the argument `mcp`, and the settings below as environment variables.

#### Keeping the token out of the config file

Instead of `SIGNALITH_TOKEN`, put the token alone in a file only you can read and set
`SIGNALITH_TOKEN_FILE` to its path (or pass `-token-file`). On Linux:

```sh
install -m 600 /dev/null ~/.config/signalith-token
printf '%s' 'sgl_api_...' > ~/.config/signalith-token
```

On Windows, save it in your user folder, which other users can't read by default.

## Settings

Each setting can be a flag or an environment variable.

| Flag | Environment variable | Meaning |
| --- | --- | --- |
| `-url` | `SIGNALITH_URL` | Signalith's web address, such as `https://siem.example.com:9000`. Plain `http://` is refused except to `localhost`, since it would send the token or password unencrypted |
| | `SIGNALITH_TOKEN` | An [API token](#api-tokens) to read with |
| `-token-file` | `SIGNALITH_TOKEN_FILE` | A file holding the token, instead of `SIGNALITH_TOKEN` |
| `-user` | `SIGNALITH_USER` | Or, without a token, the Signalith user to read as |
| | `SIGNALITH_PASSWORD` | That user's password |
| `-password-file` | `SIGNALITH_PASSWORD_FILE` | A file holding the password, instead of `SIGNALITH_PASSWORD` |
| `-ca` | `SIGNALITH_CA_FILE` | A PEM file of a certificate authority to trust, besides the system's |
| `-check` | | Check the settings, print the user and exit |

The token and the password are not taken as flags, so they do not show in process lists.
When a token is set, the user and password are ignored.

## Running it with Docker

The Signalith image runs the MCP server too. In the AI tool's config, use `docker` as
the command:

```json
"signalith": {
  "command": "docker",
  "args": ["run", "-i", "--rm",
           "-e", "SIGNALITH_URL", "-e", "SIGNALITH_TOKEN",
           "ghcr.io/jrsamsanchez/signalith:main", "mcp"],
  "env": {
    "SIGNALITH_URL": "https://siem.example.com:9000",
    "SIGNALITH_TOKEN": "sgl_api_..."
  }
}
```

To trust Signalith's CA, mount it and name it:
`"-v", "C:\\Users\\you\\Downloads\\signalith-ca.crt:/ca.crt:ro", "-e", "SIGNALITH_CA_FILE=/ca.crt"`.
A Signalith server on the same computer is `https://host.docker.internal:9000` from
inside the container.

## API tokens

API tokens let a program read through Signalith's API without a person's password. An
admin makes and revokes them on **Settings > API tokens**.

- **Read only.** Whatever its role, a request made with a token may only read: `GET`
  requests, searches and query checks. Anything else gets
  `403 API tokens can only read`. A token can't sign in to the web page.
- **Role.** A token is a **Viewer** or an **Analyst**, never an Admin. Viewer is enough
  for every AI tool.
- **Shown once.** Signalith keeps only the token's SHA-256 fingerprint and its last
  four characters, to tell tokens apart. Tokens start with `sgl_api_`, so secret
  scanners can find one that leaks.
- **Every server.** Tokens are kept in the [shared settings](servers.md), so every
  server in a cluster accepts them, and a revoked token is refused on all of them within
  a few seconds. Tokens need every server on a version that supports them; until then
  the page says to upgrade the others first.
- **Audit.** Making and revoking a token is in the audit log with the token's name.
  What a program does with a token is logged as the user `api-token:<name>`.

To use a token from your own scripts, send it as a bearer token:

```sh
curl -H "Authorization: Bearer sgl_api_..." https://siem.example.com:9000/api/me
```

## Security

- **Read only.** The MCP server sends only GET requests, plus searches and query checks,
  to Signalith. It refuses to send anything else, whatever the user's role allows.
- **The token's role applies.** Signalith checks every request against the token's role,
  as for a person, and lets a token only read. A Viewer token is enough for every tool.
- **What the model sees goes to its provider.** Search results, findings and cases the
  model reads are sent to whoever runs the model, like anything else in the chat. Unlike
  [Investigate with AI](investigate.md), nothing is masked first. Use a model you are
  allowed to send this data to, or one you run yourself.
- **Event data is untrusted.** Logs can hold text an attacker wrote, such as a user name
  or a command line made to look like instructions. The server tells the model never to
  follow instructions in data, and because every tool only reads, such text cannot make
  the tools change anything. Still check what the model tells you against Signalith
  itself before you act on it.
- **The token is in the AI tool's config file.** Keep that file private, or use
  `SIGNALITH_TOKEN_FILE`. To cut the AI tool off, revoke its token on
  **Settings > API tokens**.
- **Audit.** Requests show in Signalith's log as `api-token:<name>` (or the AI tool's
  user), with the user agent `signalith-mcp/<version>`.

## Troubleshooting

| Message | What to do |
| --- | --- |
| `Signalith did not accept the API token` | The token was revoked or mistyped. Make a new one on **Settings > API tokens** |
| `SIGNALITH_TOKEN is not an API token` | Use a token from **Settings > API tokens**; they start with `sgl_api_`. Agent tokens (`sgl_` without `api_`) only send events |
| `API tokens can only read` | Not expected from the MCP server; a script sent something other than a read |
| `Signalith did not accept the username and password` | Check `SIGNALITH_USER` and `SIGNALITH_PASSWORD`. Too many wrong passwords lock the account for a while; see [users.md](users.md#signing-in) |
| `This Signalith user must choose a new password first` | Sign in to Signalith once as this user in a browser and choose a password, or use an API token |
| `certificate signed by unknown authority` | Trust Signalith's CA, or set `SIGNALITH_CA_FILE` (step 3) |
| `could not reach Signalith` | Check the address and port, and that this computer can reach the server (try the address in a browser) |
| `This needs the Analyst role` | Not expected for these tools; check that the server runs the same Signalith version |

Claude Desktop keeps each MCP server's messages in its logs: on Windows in
`%APPDATA%\Claude\logs\mcp-server-signalith.log`.
