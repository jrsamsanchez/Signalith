# Install from packages

Each [release](https://github.com/jrsamsanchez/Signalith/releases) has ready-made
packages that install Signalith as a service in one step:

| System | Package |
| --- | --- |
| Debian, Ubuntu (amd64, arm64) | `signalith_<version>-1_amd64.deb`, `signalith_<version>-1_arm64.deb` |
| Red Hat, Rocky, Alma, Fedora, SUSE (x86_64, aarch64) | `signalith-<version>-1.x86_64.rpm`, `signalith-<version>-1.aarch64.rpm` |
| Windows 10, 11, Server 2019 and later (64-bit) | `signalith-<version>-x64.msi` |
| Docker | `ghcr.io/jrsamsanchez/signalith:<version>` |

Signalith keeps its events in [OpenSearch](https://opensearch.org) 2.x, which you install
first ([Linux](https://opensearch.org/docs/latest/install-and-configure/install-opensearch/index/),
[Windows](https://opensearch.org/docs/latest/install-and-configure/install-opensearch/windows/)).
The packages expect it at `http://127.0.0.1:9200`; if yours is elsewhere, change the
address afterwards on the **Settings** page (**OpenSearch** > **Address**). Then
[secure OpenSearch](opensearch-security.md) and give Signalith a certificate to sign in
with.

Want to try Signalith without installing anything? Use the
[Docker quick start](getting-started.md#docker-quick-start) instead.

## Debian and Ubuntu

Add Signalith's apt repository once, then install. `apt upgrade` brings each new
release from then on:

```sh
sudo install -d -m 0755 /etc/apt/keyrings
sudo curl -fsSL -o /etc/apt/keyrings/signalith.asc https://signalith.io/apt/signalith.asc
echo "deb [signed-by=/etc/apt/keyrings/signalith.asc] https://signalith.io/apt stable main" | sudo tee /etc/apt/sources.list.d/signalith.list
sudo apt update
sudo apt install signalith
sudo signalith initial-password
```

Or install a downloaded package (upgrades are then by hand, with the next one):

```sh
sudo apt install ./signalith_0.1.0-1_amd64.deb
```

## Red Hat, Rocky, Alma, Fedora and SUSE

Add Signalith's repository once, then install. `dnf upgrade` brings each new release
from then on (`dnf` asks you to accept the Signalith key the first time):

```sh
sudo curl -fsSL -o /etc/yum.repos.d/signalith.repo https://signalith.io/rpm/signalith.repo
sudo dnf install signalith
sudo signalith initial-password
```

On SUSE: `sudo zypper addrepo https://signalith.io/rpm/signalith.repo`, then
`sudo zypper install signalith`.

Or install a downloaded package (upgrades are then by hand, with the next one):

```sh
sudo dnf install ./signalith-0.1.0-1.x86_64.rpm
```

### What the Linux packages do

- Put the program in `/usr/bin/signalith` and the service in
  `/usr/lib/systemd/system/signalith.service` (the same sandboxed unit as a manual
  install).
- Create the `signalith` system account the service runs as.
- On a first install, write `/etc/signalith/signalith.yaml` with HTTPS on, a new ingest
  token and syslog on ports 514 and 6514, make the master key in
  `/var/lib/signalith/keys`, and start the service. The first admin password is kept in
  `/etc/signalith/initial-admin-password`, readable only by root, and
  `sudo signalith initial-password` shows it until you change it.
- On an upgrade, keep the config, encrypt any passwords an older version kept as plain
  text, and restart the service.
- On removal, stop the service and keep `/etc/signalith` and `/var/lib/signalith`, so
  installing again picks up where you left off. Delete them by hand to remove
  everything; events stay in OpenSearch.

## Windows

Double-click `signalith-0.1.0-x64.msi` and follow the steps (it asks for administrator
rights). When it finishes, Signalith is running as the **Signalith** service. Open
**Signalith** from the Start menu (https://localhost:8080) and sign in as `admin`. To see
the first password, open PowerShell **as Administrator** and run:

```powershell
signalith initial-password
```

The installer is not yet signed with a Windows code-signing certificate (see the
[code signing policy](code-signing.md)), so Windows SmartScreen may say "Windows
protected your PC". [Check the download](#check-a-download) first, then click
**More info** > **Run anyway**.

For a silent install, for example from a deployment tool:

```powershell
msiexec /i signalith-0.1.0-x64.msi /qn OPENSEARCHURL=https://opensearch.example.com:9200
```

### What the Windows installer does

It puts `signalith.exe` in `C:\Program Files\Signalith` (and on the system `PATH`), then
runs the same `install.ps1` as a manual install: the config and state go to
`C:\ProgramData\Signalith`, which only SYSTEM, Administrators and the service can read;
the service runs as its own account, `NT SERVICE\Signalith`; and firewall rules open
the web UI and syslog ports. Its output is in `C:\Windows\Temp\signalith-install.log`.

To upgrade, run the newer `.msi`: it stops the service, replaces the program, keeps the
config, and starts the service again. **Settings > Apps** uninstalls it; that removes
the service and its firewall rules and keeps `C:\ProgramData\Signalith`.

## Docker image

Each release is also a container image for amd64 and arm64:

```sh
docker pull ghcr.io/jrsamsanchez/signalith:0.1.0
```

The [Docker quick start](getting-started.md#docker-quick-start) runs this image with
OpenSearch: the newest code on `main` by default (the `:main` image, rebuilt on every
change), or a release when you set `SIGNALITH_VERSION`, for example
`SIGNALITH_VERSION=0.1.0`.

## Check a download

Every release is built by GitHub Actions from the tagged source, and you can check that
what you downloaded is exactly what it built.

**With the GitHub CLI** (any file from the release, or the image):

```sh
gh attestation verify signalith_0.1.0-1_amd64.deb --repo jrsamsanchez/Signalith
gh attestation verify oci://ghcr.io/jrsamsanchez/signalith:0.1.0 --repo jrsamsanchez/Signalith
```

**With the checksums**: download `SHA256SUMS` and its signatures from the release, then
check the signature and the files.

```sh
# Sigstore (no key to fetch: the signature names the workflow that made it)
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/jrsamsanchez/Signalith/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
# or GPG, with the release key published with each release
gpg --import signalith-release-key.asc
gpg --verify SHA256SUMS.asc SHA256SUMS

sha256sum --check --ignore-missing SHA256SUMS
```

On Windows, `Get-FileHash signalith-0.1.0-x64.msi` prints the SHA-256 to compare with the
line in `SHA256SUMS`.

The `.rpm` packages are signed with the same GPG key, so `dnf` and `rpm -K` can check
them once it is imported (`sudo rpm --import signalith-release-key.asc`). The apt and
dnf repositories are signed with it too, and `apt` and `dnf` check every download
from them.

## Software bill of materials

Each release lists what Signalith is built from (its Go modules and the Go version) as
an SBOM in two formats: `signalith-<version>.spdx.json` (SPDX) and
`signalith-<version>.cdx.json` (CycloneDX). Feed either to a scanner such as
[Grype](https://github.com/anchore/grype) or
[OSV-Scanner](https://github.com/google/osv-scanner) to check for known
vulnerabilities. The container image carries its own SBOM and provenance as image
attestations.
