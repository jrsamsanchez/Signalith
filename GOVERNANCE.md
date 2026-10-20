# Governance

Signalith is a personal open source project led by one maintainer. This page says who
decides what, who holds which role, and how the project continues if that person is
unavailable.

## Roles

| Role | Who | What they do |
| --- | --- | --- |
| Maintainer and project lead | Samuel Sanchez Jr. ([@jrsamsanchez](https://github.com/jrsamsanchez)) | Sets direction and the [roadmap](docs/roadmap.md), reviews and merges pull requests, publishes releases, owns the repository, website and release signing |
| Security contact | The maintainer | Receives private vulnerability reports and runs the process in [SECURITY.md](SECURITY.md) |
| Code of conduct contact | The maintainer | Handles reports under the [Code of Conduct](CODE_OF_CONDUCT.md) |
| Contributor | Anyone | Opens issues and pull requests under [CONTRIBUTING.md](CONTRIBUTING.md) |

Most code is written with the help of an AI coding assistant (Claude Code) and checked
by automated review before merge. The maintainer is responsible for every change that is
merged, whoever or whatever wrote it.

## How decisions are made

- Day-to-day changes are decided in pull requests. A change is merged when CI is green,
  it follows [CONTRIBUTING.md](CONTRIBUTING.md), and the maintainer accepts it.
- Larger changes (a new data store, a breaking change to settings or the API, a change
  to the license) are proposed in a GitHub issue first so anyone can comment. The
  maintainer makes the final call and says why in the issue.
- Only the maintainer pushes release tags.

## Becoming a maintainer

A contributor who has made regular, high-quality contributions over several months can
be invited to become a maintainer. New maintainers are added to this page and get
write access to the repository. The project wants a second maintainer; if you are
interested, say so in an issue.

## Continuity

If the maintainer cannot continue, the project should be able to carry on within a week:

- The maintainer keeps everything needed to run the project in a password manager:
  the GitHub account and its two-factor recovery codes, the signalith.io domain
  registration, and the release signing keys. A trusted person has emergency access
  to it, so they can create and close issues, merge changes, publish releases and
  keep the site running, or hand the project to a new maintainer.
- Everything needed to build, test and release is in this repository: the build and
  test steps in [CONTRIBUTING.md](CONTRIBUTING.md) and the release steps in
  [docs/releasing.md](docs/releasing.md).
- The code is Apache 2.0, so anyone may fork it and continue under a new name.

## Changes to this page

Changes to governance are made by pull request and merged by the maintainer.
