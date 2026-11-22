---
description: Signalith is written with an AI coding tool, Claude Code, and directed by one person. This page says who does what, how changes are checked and what has not been checked yet.
---

# Built with AI

Signalith is written with AI. Nearly all of its code, its tests, this documentation and
the website were written by [Claude Code](https://claude.ai/code), Anthropic's AI coding
tool, working from instructions by the project's one maintainer, Samuel Sanchez Jr. This
page says plainly who does what and how the work is checked, so you can decide how far to
trust it.

## Who does what

**The maintainer** decides what gets built and why, sets the security bar, tries the
result, and is responsible for every change that is merged, whoever or whatever wrote it.
Only the maintainer publishes a release.

**Claude Code** writes the code, the tests and the docs, opens the pull requests, fixes
what the checks find, and runs most of the reviews described below.

**Other people's work** is used as it is and credited: the detection packs are rules
written by the [SigmaHQ](https://github.com/SigmaHQ/sigma) community and by Splunk's
open-source [security_content](https://github.com/splunk/security_content) project, and
Signalith runs on OpenSearch, Fluent Bit, osquery, Zeek, Suricata, Nmap and OpenVAS
([Architecture](architecture.md)).

Signalith is a personal project, made in the maintainer's own time. It is not a product
of his employer or of Anthropic, and neither is responsible for it.

## How changes are checked

Every change arrives as a pull request on
[GitHub](https://github.com/jrsamsanchez/Signalith/pulls), in the open. These checks run
on it, and it cannot be merged while a required one fails:

- **Tests** on Linux and Windows, run again with Go's data race detector.
- **Rule tests.** Every rule in the SigmaHQ and Splunk packs ships with test events that
  prove it fires.
- **Fuzzing** of every parser that reads data from the network, for a short while on
  each change and for longer every night.
- **Static analysis** with CodeQL, and `govulncheck` for known vulnerabilities in
  dependencies.
- **Install tests** that install, upgrade from the previous release and remove the
  packages on Ubuntu, Rocky, Fedora and Windows.
- **A security review** of changes to sign-in, data intake, search, AI features,
  storage and deployment before they are merged.

Besides that, the whole code base is audited from time to time, and the high and medium
findings are fixed and listed with their ids in the
[release notes](https://github.com/jrsamsanchez/Signalith/releases). Releases come with
an SBOM, signatures and build attestations ([check a download](install-packages.md#check-a-download)),
and the project holds the [OpenSSF Best Practices](https://www.bestpractices.dev/projects/15694)
silver badge.

## What has not been checked

- **The security reviews and audits are done with AI too.** They find real problems, but
  they are not independent of the tool that wrote the code.
- **No outside security review yet.** One by people outside the project is planned
  before 1.0 ([roadmap](roadmap.md#next)).
- **No second person approves changes.** The project is looking for a second maintainer.
- **Little use outside the lab.** No install outside the maintainer's lab has run it for
  long.

[Threat model](threat-model.md#how-it-is-reviewed) has the detail on what the reviews
cover.

## What this means for you

Treat Signalith as you would any young open-source security tool: try it next to what
you run today before you rely on it, read the [security checks](security.md) it runs on
itself, and check what matters to you. The code is all in the open, so you can.

If you find something wrong, please say so: bugs as an
[issue](https://github.com/jrsamsanchez/Signalith/issues), and security problems
privately through the
[security policy](https://github.com/jrsamsanchez/Signalith/blob/main/SECURITY.md).
