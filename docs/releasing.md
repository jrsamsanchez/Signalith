# Releasing

How a Signalith release is made, for maintainers. Users want
[Install from packages](install-packages.md).

## What a release contains

The **Release** workflow (`.github/workflows/release.yml`) runs when a tag such as
`v0.1.0` is pushed. It:

1. Builds the programs for Linux (amd64, arm64) and Windows (amd64), the `.deb` and
   `.rpm` packages (`deploy/packages`, built with [nFPM](https://nfpm.goreleaser.com)) and
   the `.msi` (`deploy/windows/msi`, built with the [WiX Toolset](https://wixtoolset.org) v5).
2. Tests each package: installs the latest earlier release, upgrades it to the new one,
   signs in, removes it and installs it again, on Ubuntu with systemd, in Rocky Linux 9
   and Fedora containers, and on Windows Server. CI runs the same tests on every pull
   request (the **Packages** workflow), upgrading from the latest release.
3. Builds the container image for amd64 and arm64, pushes it to
   `ghcr.io/jrsamsanchez/signalith:<version>` (and `:latest` unless the version has a
   `-` suffix such as `-rc.1`), signs it with Sigstore and attaches its SBOM and
   provenance.
4. Writes the SBOM (SPDX and CycloneDX, made by [Syft](https://github.com/anchore/syft)
   from the Linux program), `SHA256SUMS`, its Sigstore signature, its GPG signature when
   the key is set up (below), and GitHub build provenance for every file.
5. Publishes it all on the [Releases page](https://github.com/jrsamsanchez/Signalith/releases),
   with install and verify steps (`.github/release-notes.md`) above the generated
   list of changes. A version with a `-` suffix is marked as a pre-release.

**Run workflow** on the Release workflow's page (Actions > Release) is a dry run: it
builds and tests everything for the version you enter and keeps the files as a workflow
artifact named `release`, and publishes nothing.

## Making a release

1. Make sure CI is green on `main`.
2. Tag and push:

    ```sh
    git checkout main && git pull
    git tag -a v0.1.0 -m "Signalith 0.1.0"
    git push origin v0.1.0
    ```

3. Watch Actions > Release. When it is green, the release is on the Releases page and
   the image on GHCR.

The first time an image is pushed, check that the package is public: the repository's
**Packages** list > **signalith** > **Package settings** > **Change visibility** >
**Public**.

## Signing keys

Every release is signed with [Sigstore](https://www.sigstore.dev) and has GitHub build
provenance without any setup: GitHub vouches for the workflow that built it.

### GPG (Linux packages and checksums)

`apt`, `dnf` and `rpm` check packages with GPG keys. When the repository has a
`SIGNALITH_GPG_PRIVATE_KEY` secret, the `.rpm` and `.deb` packages and `SHA256SUMS` are
signed with it, and the public key is published with each release as
`signalith-release-key.asc`.

To make the key (with Docker, on any computer), in an empty folder:

```sh
docker run --rm -v "${PWD}:/out" alpine:3.20 sh -c "apk add -q gnupg && gpg --batch --passphrase '' --quick-gen-key 'Signalith releases <releases@signalith.io>' rsa4096 sign 3y && gpg --armor --export-secret-keys > /out/signalith-release-private.asc && gpg --armor --export > /out/signalith-release-key.asc"
```

Then on GitHub: the repository's **Settings** > **Secrets and variables** > **Actions** >
**New repository secret**, name `SIGNALITH_GPG_PRIVATE_KEY`, and paste the whole of
`signalith-release-private.asc` (from `-----BEGIN` to the last `-----`). Keep a copy of
that file somewhere safe and offline, then delete it from the computer. If the key has a
passphrase, add it as `SIGNALITH_GPG_PASSPHRASE`. The key expires after three years;
make a new one before then.

### Windows code signing

The `.msi` is not yet signed with an Authenticode certificate, so Windows SmartScreen
warns before running it. Free and low-cost routes for an open-source project:

- [SignPath Foundation](https://signpath.org) signs open-source releases for free, after
  an application.
- [Azure Trusted Signing](https://learn.microsoft.com/azure/trusted-signing/) is a
  low-cost monthly service, with identity validation.

Code-signing certificates bought elsewhere now live on hardware tokens, which a cloud
build cannot use.

## Version numbers

Versions are `MAJOR.MINOR.PATCH`, with an optional `-rc.N` style suffix for
pre-releases. Windows Installer uses only the three numbers, so a pre-release and its
final release share an MSI version; the installer allows that, and the final one
replaces the pre-release.

## Licences of the build tools

nFPM (MIT), Syft (Apache 2.0), Sigstore cosign (Apache 2.0) and MkDocs Material (MIT)
are open source. The WiX Toolset is MS-RL; from v6 its prebuilt binaries come with an
Open Source Maintenance Fee agreement for revenue-making users, so the build pins WiX
v5, which has none. None of these tools is shipped inside Signalith.
