# Supported platforms

What the Signalith server, the Signalith Agent and the network sensor run on, and which
OpenSearch versions Signalith works with. **Checked** says what the installer itself
refuses, and **Tested in CI** what the project's GitHub workflows run on every change.

## Server

Each release builds the server for three platforms: Linux on 64-bit x86 (amd64) and
64-bit ARM (arm64), and Windows on 64-bit x86. The container image is for linux/amd64
and linux/arm64.

| Install | Systems | Processors | Checked | Tested in CI |
| --- | --- | --- | --- | --- |
| `.deb` package or apt repository | Debian, Ubuntu, with systemd | amd64, arm64 | Nothing: no distribution or version check | Install, upgrade and removal on the Ubuntu runner (amd64); install from the apt repository in `ubuntu:24.04` and `debian:12` containers |
| `.rpm` package or dnf repository | Red Hat, Rocky, Alma, Fedora, SUSE, with systemd | x86_64, aarch64 | Nothing: no distribution or version check | Install, upgrade and removal, and install from the dnf repository, in `rockylinux:9` and `fedora:42` containers (x86_64, without systemd). Not on SUSE |
| By hand (`deploy/linux/install.sh`) | Linux with systemd | amd64, arm64 | The processor only | |
| `.msi` or `install.ps1` | Windows 10, 11, Server 2019 and later, 64-bit (as [Install from packages](install-packages.md) says) | x64 | The 64-bit installer only: no Windows version check (see below) | Install, upgrade, uninstall and reinstall on the `windows-latest` runner |
| Docker image | Docker on Linux, Windows or macOS | amd64, arm64 | | The Docker quick start, in many jobs |
| [Helm chart](kubernetes.md) | Kubernetes 1.27 or newer, Helm 3.8 or newer | amd64, arm64 | Kubernetes version (`kubeVersion: >=1.27.0-0`) | Install on a kind cluster |

Not supported, because no server is built for them:

- **macOS.** Run the server in Docker instead, for a trial. The agent runs on macOS
  ([below](#agent)).
- **Windows on ARM (arm64).**
- **32-bit** systems, and Linux on other processors.

The deb and rpm packages list no Linux versions: they need systemd, and the program has
no other system libraries to link against (it is built with `CGO_ENABLED=0`). Versions
older than the ones CI tests are untested.

### Windows versions

The `.msi` is documented for Windows 10, 11 and Server 2019 and later, while the agent is
documented and checked for Windows 10, 11 and Server 2016 and later. Neither the `.msi`
nor the server's `install.ps1` checks the Windows version, so they install on Server
2016 too. The server is not tested on Server 2016, so use Server 2019 or later.

## Agent

The [Signalith Agent](signalith-agent.md#what-it-runs-on) is built for Linux (amd64,
arm64), Windows (amd64, and arm64 on Windows 11 from the release after 0.3.2) and macOS (amd64, arm64). Its install line checks the system
before it changes anything and stops on any other.

| System | Versions | Processors |
| --- | --- | --- |
| Ubuntu | 22.04, 24.04 | amd64, arm64 |
| Debian | 12, 13 | amd64, arm64 |
| Red Hat Enterprise Linux, Rocky Linux, AlmaLinux, Oracle Linux | 8, 9 | amd64, arm64 |
| Amazon Linux | 2023 | amd64, arm64 |
| Windows | 10, 11, Server 2016 and later (build 14393 or later); Windows 11 on ARM from the release after 0.3.2 | x64; arm64 on Windows 11 |
| macOS | 12 and later | Apple silicon, Intel |

Linux needs systemd. Windows 10 on ARM is refused, and so is Windows 11 on ARM up to 0.3.2. On any other system, send logs with
Fluent Bit or osquery set up by hand ([Agents and syslog](sending-data.md),
[Endpoints](endpoints.md)).

## Network sensor

The [network sensor's install line](network-sensor.md) runs on:

| System | Versions | Processors | Notes |
| --- | --- | --- | --- |
| Ubuntu | 22.04, 24.04 | amd64, arm64 | |
| Debian | 12, 13 | amd64, arm64 | |
| Rocky Linux, AlmaLinux | 9 | amd64, arm64 | Zeek publishes no packages for them: use `--no-zeek` (Suricata only) or `--docker` |

It needs systemd. The script also accepts Red Hat Enterprise Linux 9, with EPEL turned on
for Suricata, but it is not tested there.

## OpenSearch

Signalith keeps its events in OpenSearch **2.17 or newer, 3.x included**.

| | Version |
| --- | --- |
| Docker quick start, Helm chart, Windows installer (from 0.3.1) | OpenSearch 3.9.0, pinned |
| Tested in CI | **3.9.0 only.** Every job that starts an OpenSearch (end-to-end tests, the cluster and mixed-version tests, the nightly load tests, Helm, content updates) uses the 3.9.0 image |
| Not tested in CI | OpenSearch 2.x. The [cloud test lab](cloud-lab.md) can install 2.17.1 for a manual test (`opensearch_version`); it installs 3.9.0 by default |

Signalith does not check the version when it connects. Some features need a newer
OpenSearch:

- [Cold storage](cold-storage.md) needs OpenSearch 3.
- Searching long PowerShell script blocks needs OpenSearch 2.15 or later
  ([Detections](detections.md)); 2.17 has it.

Moving from 2.x to 3.x is one way: see [Moving to OpenSearch 3.x](opensearch-security.md#moving-to-opensearch-3x).
