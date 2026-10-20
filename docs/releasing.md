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
   provenance. (Between releases, the **Image (main)** workflow publishes the same kind
   of signed image as `:main` on every push to `main`; the public demo runs it.)
4. Packages the Helm chart (`deploy/helm/signalith`) with the release's version, which
   also picks the image it runs, pushes it to `oci://ghcr.io/jrsamsanchez/charts/signalith`
   and signs it with Sigstore. Its `.tgz` goes on the release page with the other files.
   (The **Helm chart** workflow installs the chart on kind for pull requests that change
   it, and weekly; see [Kubernetes](kubernetes.md).)
5. Writes the SBOM (SPDX and CycloneDX, made by [Syft](https://github.com/anchore/syft)
   from the Linux program), `SHA256SUMS`, its Sigstore signature, its GPG signature when
   the key is set up (below), and GitHub build provenance for every file. Before the
   checksums it makes `signalith-<version>-docker.tar.gz`, the Docker quick start with
   the image locked to the digest pushed in step 3 (`.github/scripts/docker-release.sh`).
6. Publishes it all on the [Releases page](https://github.com/jrsamsanchez/Signalith/releases),
   with the version's own notes (`.github/releases/<version>.md`, such as `0.3.0.md`,
   when there is one), install and verify steps (`.github/release-notes.md`) and the
   generated list of changes. A version with a `-` suffix is marked as a pre-release
   and uses the notes of the version it leads to.
7. Once it has published, the **Website** workflow adds the new packages to the apt and
   dnf repositories on signalith.io (below), so `apt upgrade` and `dnf upgrade` find them.

**Run workflow** on the Release workflow's page (Actions > Release) is a dry run: it
builds and tests everything for the version you enter and keeps the files as a workflow
artifact named `release`, and publishes nothing. Its summary shows the release notes the
version would get.

## Making a release

1. Make sure CI is green on `main`, and `.github/releases/<version>.md` says what's new
   and what to do before upgrading.
2. Tag and push:

    ```sh
    git checkout main && git pull
    git tag -a v0.1.0 -m "Signalith 0.1.0"
    git push origin v0.1.0
    ```

3. Watch Actions > Release. When it is green, the release is on the Releases page and
   the image on GHCR.
4. Move the Docker quick start to it: set the version in `${SIGNALITH_VERSION:-<version>}`
   in `deploy/docker/docker-compose.yml`, `docker-compose.server.yml` and
   `docker-compose.cluster.yml` to the new one and merge that, so `git pull` moves
   quick-start users to the release. It waits for the release because the image must
   exist first (CI starts the quick start from it). Until then the quick start runs the
   previous release, so a change to those files that needs a newer image waits for this
   step. The release's own `signalith-<version>-docker.tar.gz` always runs its own image.

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
`signalith-release-key.asc`. It also signs the apt and dnf repositories at
https://signalith.io/apt and https://signalith.io/rpm, which the **Website** workflow
rebuilds from the five newest releases after every **Release** run
(`deploy/repos/build.sh`; packages from before the key existed are signed there). Until
the secret is set, the website has no repositories. The **Package repositories** workflow then
installs the latest release from them on four Linux distributions, after every website
publish and weekly, so a broken publish or an expiring key shows up there.

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

### Content updates

The weekly **Content** workflow (`.github/workflows/content.yml`) rebuilds the SigmaHQ
and Splunk packs from the newest upstream rules, runs every pack check, and publishes
them as a signed bundle on the `content` release, which servers check for (see
[Content updates](detections.md#content-updates)). It signs with an Ed25519 key in the
`SIGNALITH_CONTENT_KEY` secret; without the secret it builds and tests but publishes
nothing. Servers only take bundles signed by a key listed in
`internal/content/trusted.keys`, so a new key reaches them with the next release.

To make the key (with Docker, on any computer; the same line works in PowerShell):

```sh
docker run --rm alpine:3.20 sh -c 'apk add -q openssl && openssl genpkey -algorithm ed25519 -outform DER -out /k && echo private: $(tail -c 32 /k | base64) && echo public: $(openssl pkey -inform DER -in /k -pubout -outform DER | tail -c 32 | base64)'
```

(`signalith content keygen` prints the same pair.) Then on GitHub: the repository's **Settings** > **Secrets and variables** > **Actions** >
**New repository secret**, name `SIGNALITH_CONTENT_KEY`, and paste the private key line.
Add the public key line to `internal/content/trusted.keys` (the workflow log also prints
it, and warns while it is missing). Keep a copy of the private key somewhere safe and
offline. To replace a key, add the new public key next to the old one, release, switch
the secret, and remove the old key in a later release.

### Agent updates

[Signalith Agents](signalith-agent.md#updates) update themselves only to agent programs
listed in a manifest signed with the release key, an Ed25519 key of the same kind as the
content key. With the `SIGNALITH_AGENT_KEY` secret set, the **Release** workflow, run
from a version tag, signs the agent programs in the `.deb` and `.rpm` packages and in the container
image (`signalith agent-programs sign -version <version> -dir <folder of agent
programs>`, which reads the key from the environment only; the image build gets it as a
build secret, so it stays out of the image). Agents trust the public keys in
`internal/agentproto/release.keys`; `sign` refuses a key that is not listed there, so a
release with the secret set but its public key missing fails instead of shipping
updates no agent would take. Without the secret, nothing is signed and agents do not
update themselves. CI never gets the key.

The key is a secret of the `release` environment, not of the whole repository, so that
only a run of a version tag can read it: no branch, pull request or dry run can. To set
it up, on GitHub open **Settings** > **Environments** > **New environment**, name it
`release`, and under **Deployment branches and tags** choose **Selected branches and
tags** and add a rule of type **Tag** with the pattern `v*`. Then, in the environment,
**Add environment secret** named `SIGNALITH_AGENT_KEY` with the private key. If the key
is also a repository secret, delete that one.

To set it up, make a new key the same way as the content key (or with
`signalith agent-programs keygen`); use a key of its own, never the content key, so each
key signs one kind of thing, add the private key line as the `SIGNALITH_AGENT_KEY`
repository secret, and add the public key line to `internal/agentproto/release.keys`.
Agents built with that file trust the key from then on, so keep a copy of the private
key somewhere safe and offline. To replace it, add the new public key next to the old
one, release, switch the secret, and remove the old key in a later release.

### Windows code signing

The **Release** workflow signs the `.msi` and `signalith-windows-amd64.exe` with
Authenticode through [SignPath Foundation](https://signpath.org), which signs
open-source projects for free; the [code signing policy](code-signing.md) is the page it
asks projects to publish. SignPath declined Signalith's first application (October 2026),
so the Windows files are released unsigned for now and SmartScreen warns before running
the installer. The steps below stay for a later application.

To set it up:

1. Apply at [signpath.org](https://signpath.org/apply) for the Signalith repository.
2. Once accepted, in SignPath: create the project `signalith`, connect it to GitHub as
   its trusted build system, add the artifact configuration from
   `deploy/windows/signpath/artifact-configuration.xml`, and create the signing policy
   `release-signing` with yourself as approver. Make an API token for a CI user that
   may submit requests.
3. On GitHub, **Settings** > **Secrets and variables** > **Actions**: add the secret
   `SIGNPATH_API_TOKEN`, and on the **Variables** tab the variable
   `SIGNPATH_ORGANIZATION_ID`. (`SIGNPATH_PROJECT_SLUG` and
   `SIGNPATH_SIGNING_POLICY_SLUG` change the two names above if you chose others.)

From then on, each release run sends the two files to SignPath and waits up to four
hours for you to approve the request there (SignPath emails you), checks the signatures
on Windows, and publishes the signed files. Every `signalith.exe` carries its name and
version (made by [go-winres](https://github.com/tc-hib/go-winres) at build time), which
the artifact configuration requires.

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
