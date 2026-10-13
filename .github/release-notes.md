## Install

| System | Download |
| --- | --- |
| Debian, Ubuntu | `signalith_{VERSION}-1_amd64.deb` or `_arm64.deb`, then `sudo apt install ./signalith_{VERSION}-1_amd64.deb` |
| Red Hat, Rocky, Alma, Fedora, SUSE | `signalith-{VERSION}-1.x86_64.rpm` or `.aarch64.rpm`, then `sudo dnf install ./signalith-{VERSION}-1.x86_64.rpm` |
| Windows | `signalith-{VERSION}-x64.msi`, double-click it |
| Docker | `docker pull ghcr.io/jrsamsanchez/signalith:{VERSION}` |

Then `sudo signalith initial-password` (on Windows, `signalith initial-password` in PowerShell as Administrator) shows the first admin password. Signalith needs OpenSearch 2.x; see [Install from packages](https://signalith.io/docs/install-packages/).

## Check your download

```sh
gh attestation verify <file> --repo jrsamsanchez/Signalith
```

or check `SHA256SUMS` against `SHA256SUMS.sigstore.json` (Sigstore) or `SHA256SUMS.asc` (GPG, key `signalith-release-key.asc`), as [the docs](https://signalith.io/docs/install-packages/#check-a-download) show. The SBOM is in `signalith-{VERSION}.spdx.json` (SPDX) and `signalith-{VERSION}.cdx.json` (CycloneDX).

