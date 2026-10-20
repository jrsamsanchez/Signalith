# Install from packages

Each [release](https://github.com/jrsamsanchez/Signalith/releases) has ready-made
packages that install Signalith as a service in one step:

| System | Package |
| --- | --- |
| Debian, Ubuntu (amd64, arm64) | `signalith_<version>-1_amd64.deb`, `signalith_<version>-1_arm64.deb` |
| Red Hat, Rocky, Alma, Fedora, SUSE (x86_64, aarch64) | `signalith-<version>-1.x86_64.rpm`, `signalith-<version>-1.aarch64.rpm` |
| Windows 10, 11, Server 2019 and later (64-bit) | `signalith-<version>-x64.msi` |
| Docker | `ghcr.io/jrsamsanchez/signalith:<version>` |

Signalith keeps its events in [OpenSearch](https://opensearch.org) 2.x or 3.x. The
Windows installer sets it up for you ([OpenSearch on Windows](#opensearch-on-windows)),
from the next release (0.3.1) on; with 0.3.0 and older, install OpenSearch first and give
the installer its address with `OPENSEARCHURL`.
On Linux, install it first
([instructions](https://opensearch.org/docs/latest/install-and-configure/install-opensearch/index/)):
the Linux packages expect it at `http://127.0.0.1:9200`; if yours is elsewhere, change the
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
  token and syslog over TLS on port 6514, make the master key in
  `/var/lib/signalith/keys`, and start the service. The first admin password is kept in
  `/etc/signalith/initial-admin-password`, readable only by root, and
  `sudo signalith initial-password` shows it until you change it. The first sign-in
  with it asks you to choose your own before anything else, and the file is removed
  when you change the password with `sudo signalith passwd` (the service may not remove
  it itself; it no longer works either way).
- On an upgrade, keep the config, encrypt any passwords an older version kept as plain
  text, and restart the service. An install made before 0.3.1 keeps plain syslog on
  port 514 if its config has it. While the admin password is still the first one
  Signalith made, the next sign-in with it asks for a new one, also on an install that
  has used it for a long time.
- On removal, stop the service and keep `/etc/signalith` and `/var/lib/signalith`, so
  installing again picks up where you left off. Delete them by hand to remove
  everything; events stay in OpenSearch.

## Windows

Double-click `signalith-0.1.0-x64.msi` and follow the steps (it asks for administrator
rights). It installs OpenSearch as well, which it downloads (about 1 GB), so the first
install takes a few minutes. When it finishes, Signalith and OpenSearch are running as
the **Signalith** and **SignalithOpenSearch** services. Open
**Signalith** from the Start menu (https://localhost:9000) and sign in as `signalithadmin`. To see
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
msiexec /i signalith-0.1.0-x64.msi /qn
```

To use an OpenSearch you already run instead of installing one, give its address (then
[secure it](opensearch-security.md) and give Signalith a certificate to sign in with):

```powershell
msiexec /i signalith-0.1.0-x64.msi /qn OPENSEARCHURL=https://opensearch.example.com:9200
```

### What the Windows installer does

It puts `signalith.exe` in `C:\Program Files\Signalith` (and on the system `PATH`), then
runs the same `install.ps1` as a manual install: the config and state go to
`C:\ProgramData\Signalith`, which only SYSTEM, Administrators and the service can read;
the service runs as its own account, `NT SERVICE\Signalith`; and firewall rules open
the web UI, agent and syslog ports. Its output is in `C:\Windows\Temp\signalith-install.log`.

A new install takes syslog over TLS on port 6514 only, and opens only that syslog port.
Plain syslog over UDP and TCP 514 is unencrypted and can be forged, so it is off; turn it
on later on **Add data** > **Syslog** (the page then gives the firewall rules for 514), or
from the start with `install.ps1 -SyslogUdp 0.0.0.0:514 -SyslogTcp 0.0.0.0:514`.

To upgrade, run the newer `.msi`: it stops the service, replaces the program, keeps the
config (with plain syslog on, if it was), and starts the service again. It upgrades the OpenSearch it installed too, when
the new release pins a newer one, keeping its data. An install from 0.3.0 or older that never reached an
OpenSearch (it still has the address `http://127.0.0.1:9200` the older installer wrote, and
nothing answers there) gets one too, set up as on a new install on port 9201 or the next
free one; an OpenSearch you set up yourself is left as it is. The config as it was is kept
as `signalith.yaml.before-opensearch`: if you do run an OpenSearch of your own at that
address that was only stopped, copy that file back over `signalith.yaml` and restart the
**Signalith** service. **Settings > Apps** uninstalls it;
that removes the services, OpenSearch's program and the firewall rules, and keeps
`C:\ProgramData\Signalith` and `C:\ProgramData\SignalithOpenSearch` (OpenSearch's
settings, certificates and events), so installing again carries on with them. Delete
those folders by hand to remove everything.

### OpenSearch on Windows

On a new install, unless you gave `OPENSEARCHURL`, the installer sets up OpenSearch for
Signalith the same way the [Docker quick start](getting-started.md#docker-quick-start)
does:

- It downloads the official OpenSearch release for Windows (version 3.9.0) from
  `artifacts.opensearch.org` and installs it only if its SHA-512 is the one pinned in
  Signalith, so a changed download is refused. OpenSearch is open source under the
  Apache License 2.0; it is downloaded from OpenSearch, not shipped inside the `.msi`,
  which keeps the installer small.
- The program goes to `C:\Program Files\Signalith\OpenSearch`, where only
  administrators can change it. Its settings, data and logs go to
  `C:\ProgramData\SignalithOpenSearch`, which only SYSTEM, Administrators and OpenSearch's
  service can use.
- It runs as the **SignalithOpenSearch** service under its own account,
  `NT SERVICE\SignalithOpenSearch`, which may change only its own settings, data and logs.
- It listens on this computer only (`127.0.0.1`, port 9200, or the next free one), over
  HTTPS with certificates from a CA of its own that the installer makes. It accepts only
  certificates from that CA: Signalith's, and an admin certificate for OpenSearch's
  security tools. There are no passwords and no demo users; the CA's key and the admin
  certificate stay in `C:\ProgramData\SignalithOpenSearch\ca`, which neither service can
  read. The download is checked and unpacked from a folder only administrators can change.
- Its Java heap is a quarter of the computer's memory, from 1 to 8 GB.

A computer without internet access: download
`opensearch-3.9.0-windows-x64.zip` from
[opensearch.org](https://opensearch.org/downloads.html) on another computer, copy it
over, and install with:

```powershell
msiexec /i signalith-0.1.0-x64.msi OPENSEARCHZIP=C:\Downloads\opensearch-3.9.0-windows-x64.zip
```

`signalith opensearch status`, in PowerShell as Administrator, shows what is installed.
OpenSearch's own log is `C:\ProgramData\SignalithOpenSearch\logs\signalith.log`.

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
