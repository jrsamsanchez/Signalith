# Code signing policy

Signalith's releases are signed so you can check that what you downloaded is exactly
what the project built from its public source.

| Download | Signed with |
| --- | --- |
| Windows installer (`.msi`) and `signalith-windows-amd64.exe` | Not yet Authenticode-signed (below) |
| Linux packages (`.deb`, `.rpm`) and the apt and dnf repositories | The Signalith release GPG key, once it is set up |
| Container images on GHCR | Sigstore, with build provenance |
| Every release file (through `SHA256SUMS`) | Sigstore and GitHub build provenance (and GPG, once set up) |

[Check a download](install-packages.md#check-a-download) shows how to verify each one.

## Windows

The Windows files are not yet Authenticode-signed, so Windows SmartScreen warns before
running the installer; the checksums and their Sigstore signature still let you check
them.

When Authenticode signing is added, only files built by the project's GitHub Actions
**Release** workflow from a tagged commit in
[jrsamsanchez/Signalith](https://github.com/jrsamsanchez/Signalith) will be signed, and
every signed file is named Signalith and carries the release's version.

## Team roles

- **Committers and reviewers:** the
  [repository owner](https://github.com/jrsamsanchez). Most code is written with
  [Claude Code](https://claude.ai/code), an AI coding tool, through pull requests that
  must pass the project's tests before they are merged. Pull requests from other people
  are reviewed before they are merged.
- **Approvers:** the [repository owner](https://github.com/jrsamsanchez) approves each
  release and each signing request.

Everyone in these roles uses multi-factor authentication for GitHub.

## Privacy

Signalith sends nothing to the Signalith project: there is no telemetry. It connects to
the systems you configure (your OpenSearch, agents, threat intel feeds, notification
channels, an AI provider, directory servers) and, by default, to one public download:
the iptoasn.com IP database for behavior baselines, which can be turned off or replaced
with a local file. Vulnerability scans add CISA's KEV catalog, EPSS scores and NVD CVE
lookups, and **Daily** content updates (the default is **Manual**) check the project's
GitHub releases. [Outbound connections](outbound.md) lists every host, and
[Where your data goes](data-residency.md) what each feature sends.

## Reporting a problem

To report a signed file that behaves maliciously, or any security problem, see the
[security policy](https://github.com/jrsamsanchez/Signalith/security/policy).
