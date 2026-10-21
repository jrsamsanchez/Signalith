## Install

| System | Download |
| --- | --- |
| Debian, Ubuntu | `signalith_{VERSION}-1_amd64.deb` or `_arm64.deb`, then `sudo apt install ./signalith_{VERSION}-1_amd64.deb` |
| Red Hat, Rocky, Alma, Fedora, SUSE | `signalith-{VERSION}-1.x86_64.rpm` or `.aarch64.rpm`, then `sudo dnf install ./signalith-{VERSION}-1.x86_64.rpm` |
| Windows | `signalith-{VERSION}-x64.msi`, double-click it |
| Docker | `signalith-{VERSION}-docker.tar.gz`, the quick start locked to this release's image: unpack it, then `docker compose -f deploy/docker/docker-compose.yml up -d` in its folder; see [The quick start locked to a release](https://signalith.io/docs/install-packages/#the-quick-start-locked-to-a-release). The image alone: `docker pull ghcr.io/jrsamsanchez/signalith:{VERSION}` |
| Kubernetes | `helm install signalith oci://ghcr.io/jrsamsanchez/charts/signalith --version {VERSION} -n signalith --create-namespace`; see [Kubernetes](https://signalith.io/docs/kubernetes/) |

Then `sudo signalith initial-password` (on Windows, `signalith initial-password` in PowerShell as Administrator) shows the first admin password. Signalith needs OpenSearch 2.x or 3.x; see [Install from packages](https://signalith.io/docs/install-packages/).

Adding a server to a cluster? Use **Add a server** on the Servers page: it gives one line to run on the new computer. `install.sh` and `signalith-{VERSION}-windows-amd64.zip` (the program and `install.ps1`) are the same install scripts, for automation; see [Adding servers](https://signalith.io/docs/multi-server/).

{GPG}Already using Signalith's [apt or dnf repository](https://signalith.io/docs/install-packages/)? `sudo apt upgrade` or `sudo dnf upgrade` installs this release.

## Check your download

```sh
gh attestation verify <file> --repo jrsamsanchez/Signalith
```

or check `SHA256SUMS` against `SHA256SUMS.sigstore.json` (Sigstore), as [the docs](https://signalith.io/docs/install-packages/#check-a-download) show. See the [code signing policy](https://signalith.io/docs/code-signing/).
{GPG}`SHA256SUMS.asc` is a GPG signature of the same file, made with the key in `signalith-release-key.asc`.

The SBOM is in `signalith-{VERSION}.spdx.json` (SPDX) and `signalith-{VERSION}.cdx.json` (CycloneDX).

