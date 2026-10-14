# Code signing policy

Signalith's releases are signed so you can check that what you downloaded is exactly
what the project built from its public source.

| Download | Signed with |
| --- | --- |
| Windows installer (`.msi`) and `signalith-windows-amd64.exe` | Authenticode, once Windows code signing is set up (below) |
| Linux packages (`.deb`, `.rpm`) and the apt and dnf repositories | The Signalith release GPG key, once it is set up |
| Container images on GHCR | Sigstore, with build provenance |
| Every release file (through `SHA256SUMS`) | Sigstore and GitHub build provenance (and GPG, once set up) |

[Check a download](install-packages.md#check-a-download) shows how to verify each one.

## Windows

Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by
[SignPath Foundation](https://signpath.org).

Until that is in place, the Windows files are not Authenticode-signed and Windows
SmartScreen warns before running the installer; the checksums and their Sigstore
signature still let you check them.

Only files built by the project's GitHub Actions **Release** workflow from a tagged
commit in [jrsamsanchez/Signalith](https://github.com/jrsamsanchez/Signalith) are sent
for signing, and a maintainer approves each signing request. Every signed file is named
Signalith and carries the release's version.

## Team roles

- **Committers and reviewers:** the
  [repository owner](https://github.com/jrsamsanchez). Most code is written with
  [Claude Code](https://claude.ai/code), an AI coding tool, through pull requests that
  must pass the project's tests before they are merged. Pull requests from other people
  are reviewed before they are merged.
- **Approvers:** the [repository owner](https://github.com/jrsamsanchez) approves each
  release and each signing request.

Everyone in these roles uses multi-factor authentication for GitHub and SignPath.

## Privacy

Signalith does not send information to other networked systems unless you set it up to.
It only connects to the systems you configure: your OpenSearch, the agents and devices
that send it data, threat intel feeds you add, notification channels you add, an AI
provider if you turn on the assistant (only the question is sent), directory servers
for sign-in, and, if you choose **Daily** content updates (the default is **Manual**),
the project's GitHub releases to check for newer detection rules. There is no telemetry.

## Reporting a problem

To report a signed file that behaves maliciously, or any security problem, see the
[security policy](https://github.com/jrsamsanchez/Signalith/security/policy).
