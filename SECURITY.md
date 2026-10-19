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
minor version (0.3 now, starting with v0.3.0), as a new patch release. Older
releases, such as 0.2, are not patched, so please upgrade to the latest release
to get a fix.

| Version          | Gets security fixes |
| ---------------- | ------------------- |
| `main`           | Yes                 |
| 0.3.x (latest)   | Yes                 |
| 0.2.x and older  | No                  |

Each release's files and container image are signed, and you can check that
what you downloaded is what GitHub Actions built: see
[Check a download](docs/install-packages.md#check-a-download).

## What is in scope

The Signalith server, its web UI and API, the `signalith` command, the agent
configs it generates, and the Docker and Windows install files in `deploy/`.
Weaknesses in OpenSearch, Fluent Bit or other projects Signalith uses belong
with those projects, but tell us too if Signalith's defaults make them worse.

How Signalith protects data and what to check on your own install:
[docs/security.md](docs/security.md). What it defends against, what it trusts and its
known limits: [docs/threat-model.md](docs/threat-model.md).

## Independent review

Signalith has not had an independent security audit yet. One is planned after
the 1.0 release; until then, every security-sensitive change is reviewed before it
is merged, as the threat model describes.
