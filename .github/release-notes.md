## Install

| System | Download |
| --- | --- |
| Debian, Ubuntu | `signalith_{VERSION}-1_amd64.deb` or `_arm64.deb`, then `sudo apt install ./signalith_{VERSION}-1_amd64.deb` |
| Red Hat, Rocky, Alma, Fedora, SUSE | `signalith-{VERSION}-1.x86_64.rpm` or `.aarch64.rpm`, then `sudo dnf install ./signalith-{VERSION}-1.x86_64.rpm` |
| Windows | `signalith-{VERSION}-x64.msi`, double-click it |
| Docker | `docker pull ghcr.io/jrsamsanchez/signalith:{VERSION}` |

Then `sudo signalith initial-password` (on Windows, `signalith initial-password` in PowerShell as Administrator) shows the first admin password. Signalith needs OpenSearch 2.x; see [Install from packages](https://signalith.io/docs/install-packages/).

{GPG}Already using Signalith's [apt or dnf repository](https://signalith.io/docs/install-packages/)? `sudo apt upgrade` or `sudo dnf upgrade` installs this release.

## Check your download

```sh
gh attestation verify <file> --repo jrsamsanchez/Signalith
```

or check `SHA256SUMS` against `SHA256SUMS.sigstore.json` (Sigstore), as [the docs](https://signalith.io/docs/install-packages/#check-a-download) show. See the [code signing policy](https://signalith.io/docs/code-signing/).
{GPG}`SHA256SUMS.asc` is a GPG signature of the same file, made with the key in `signalith-release-key.asc`.

The SBOM is in `signalith-{VERSION}.spdx.json` (SPDX) and `signalith-{VERSION}.cdx.json` (CycloneDX).

