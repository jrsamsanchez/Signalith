# Security policy

Signalith is a security product, so reports of weaknesses in it are very
welcome.

## Reporting a vulnerability

Please report it privately, not in a public issue:

- On GitHub, open the repository's **Security** tab and choose
  **Report a vulnerability**
  ([direct link](https://github.com/jrsamsanchez/signalith/security/advisories/new)).

Say what you found, which version or commit, and how to reproduce it. The
aim is to answer within a week. Once a fix is out, the advisory is
published and you are credited unless you ask not to be.

## Supported versions

Security fixes go to the `main` branch and to the latest release: the newest
minor version (0.2 now, starting with v0.2.0), as a new patch release. Older
releases, such as 0.1, are not patched, so please upgrade to the latest release
to get a fix.

| Version          | Gets security fixes |
| ---------------- | ------------------- |
| `main`           | Yes                 |
| 0.2.x (latest)   | Yes                 |
| 0.1.x and older  | No                  |

Each release's files and container image are signed, and you can check that
what you downloaded is what GitHub Actions built: see
[Check a download](docs/install-packages.md#check-a-download).

## What is in scope

The Signalith server, its web UI and API, the `signalith` command, the agent
configs it generates, and the Docker and Windows install files in `deploy/`.
Weaknesses in OpenSearch, Fluent Bit or other projects Signalith uses belong
with those projects, but tell us too if Signalith's defaults make them worse.

How Signalith protects data and what to check on your own install:
[docs/security.md](docs/security.md).
