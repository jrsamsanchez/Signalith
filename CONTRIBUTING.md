# Contributing to Signalith

Thanks for wanting to help. Bug reports, detections, docs fixes and code are all
welcome. Signalith is a personal open-source project, so a small, focused change with a
clear reason is the easiest kind to review and merge.

- **Questions and ideas:** open an issue with the
  [feature request](https://github.com/jrsamsanchez/Signalith/issues/new/choose) form.
  For a bigger change, say what you plan before writing much code.
- **Bugs:** use the bug report form, with your version (`signalith version`) and how to
  reproduce it.
- **Security weaknesses:** never in a public issue. Follow [SECURITY.md](SECURITY.md) and
  report it privately through
  [GitHub security advisories](https://github.com/jrsamsanchez/Signalith/security/advisories/new).

## Build

Signalith is one Go program with the web UI embedded (`web/static`, plain JavaScript,
no build step). It needs the Go version in [`go.mod`](go.mod) (currently 1.26.9). With
an older Go installed, the `go` command downloads the right one by itself; if your
setup turns that off, set it for one command:

```sh
GOTOOLCHAIN=go1.26.9 go build -o signalith ./cmd/signalith
```

```sh
go build -o signalith ./cmd/signalith                                  # this system
GOOS=windows GOARCH=amd64 go build -o signalith.exe ./cmd/signalith    # Windows
```

To try a change end to end, run the [Docker quick start](README.md#docker-evaluation)
with the build file added, so it builds Signalith from your working copy instead of
pulling the published image:

```sh
docker compose -f deploy/docker/docker-compose.yml -f deploy/docker/docker-compose.build.yml up -d --build
```

[Sample data](docs/sample-data.md) gives it a week of events to look at:
`docker compose -f deploy/docker/docker-compose.yml exec signalith signalith sample-data load`.

## Test

Every pull request runs [CI](.github/workflows/ci.yml): `go vet`, `go test` on Linux and
Windows, the tests again with the race detector, `govulncheck`, a cross-compile for
Linux and Windows, and end-to-end tests against the Docker quick start. Run the same
checks locally before you push:

```sh
gofmt -l .                         # prints nothing when everything is formatted
go vet ./...
go test ./...
go test -race -timeout 20m ./...   # slower; needs cgo
```

The **end-to-end tests** (`internal/integration`, build tag `integration`) run against a
real OpenSearch. CI starts the Docker quick start with OpenSearch's port published on
`127.0.0.1:9200`, copies Signalith's OpenSearch certificates out of the container, stops
the `signalith` service so it does not work on the test indices, and runs:

```sh
SIGNALITH_TEST_OPENSEARCH=https://localhost:9200 \
SIGNALITH_TEST_OPENSEARCH_CA=/path/to/opensearch-ca.pem \
SIGNALITH_TEST_OPENSEARCH_CERT=/path/to/opensearch-client.pem \
SIGNALITH_TEST_OPENSEARCH_KEY=/path/to/opensearch-client-key.pem \
go test -tags integration -count=1 ./internal/integration/
```

The `integration` job in [ci.yml](.github/workflows/ci.yml) has the exact commands. The
`TestCluster` tests start several `signalith serve` processes that share one OpenSearch
and stop them with `kill -9` and `SIGSTOP`, so they run on Linux only; without
`SIGNALITH_TEST_OPENSEARCH` they use a built-in stand-in for OpenSearch.

Tests must pass on Windows too. Git on Windows may check text files out with CRLF line
endings, so a test that reads a file from the repository (such as a doc) should not
compare it byte for byte. Use `path/filepath` (not `path`) for file paths, and
`filepath.IsAbs`, which knows `C:\`; and don't test exact file modes, which Windows
does not keep.

### Completeness tests

A few tests make sure nothing new slips through without the pieces around it. When one
fails, it says what is missing:

| You add | Also add | Test |
| --- | --- | --- |
| A route under `/api` | A role: register it with `api.viewer`, `api.analyst` or `api.admin` (the router in [`internal/api/access.go`](internal/api/access.go)), and list it under that role in [`docs/users.md`](docs/users.md#roles-of-every-route) | `TestEveryRouteHasARole`, `TestUsersDocListsEveryRoute` |
| A setting in `signalith.yaml` | An entry in the settings registry in [`internal/config/settings.go`](internal/config/settings.go), or in its `Excluded` list with the reason it is not on the Settings page | `TestRegistryCoversEveryConfigSetting` |
| A built-in detection that is on by default | Events in the sample data that make it fire ([`internal/sample`](internal/sample)) | `TestRecipeEveryEnabledDetectionHasData` |
| A security check | A section with the check's title in [`docs/security.md`](docs/security.md) | `TestEveryCheckHasADocsSection` |

## Code style

- Format with `gofmt` and keep `go vet` clean.
- Prefer the standard library; a new dependency needs a good reason and a license that
  fits Apache 2.0.
- Keep messages people read plain and specific: say what happened and what to change.
- Write tests next to the code (`foo_test.go`), including the error paths.
- Update the docs in the same change when behaviour, settings or the API change.

## Detections

Built-in detections are YAML files in
[`internal/detect/builtin`](internal/detect/builtin); the format is in
[docs/detections.md](docs/detections.md). Starting from a [Sigma](https://github.com/SigmaHQ/sigma)
rule is often quickest: import it with **Import Sigma rule** on the Detections page
(or `POST /api/detections/sigma`), check the warnings and the converted query, and
**Test** it against data before copying the result into a file. Each detection should:

- map to MITRE ATT&CK where it can, and say how to triage what it finds;
- name its source and license when it is based on someone else's rule (Sigma rules are
  under the Detection Rule License, which asks for credit);
- come with sample data that makes it fire, if it is on by default (see above).

Rules from other projects ship as **content packs** in
[`internal/detect/packs`](internal/detect/packs) (SigmaHQ and Splunk Security Content),
unchanged and off by default. They are generated, so do not edit them by hand: change
the generator (`internal/detect/packgen`, `internal/detect/splunkgen`) or the parser or
field mappings, and regenerate as
[docs/detections.md](docs/detections.md#content-packs) shows. Every pack rule is tested
against its own events (`TestPackRulesFireOnTheirTests`), so a change that breaks one
fails CI. Files under `internal/detect/packs` are hashed and signed byte for byte, so
keep their line endings as they are.

## Docs

The documentation in [`docs/`](docs) is published at
[signalith.io/docs](https://signalith.io/docs/) with
[MkDocs](https://www.mkdocs.org) and
[Material for MkDocs](https://squidfunk.github.io/mkdocs-material/). To preview it:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r docs/requirements.txt
.venv/bin/mkdocs serve      # http://127.0.0.1:8000/docs/
```

CI builds it with `mkdocs build --strict`, which fails on broken links and missing
anchors. A new page also needs a place in the `nav` of [mkdocs.yml](mkdocs.yml). Link
between docs with relative paths (`https.md#trust-the-certificate`); link to anything
outside `docs/` with a full `https://github.com/jrsamsanchez/Signalith/blob/main/...`
address. Some docs are read by tests (`users.md`, `security.md`, `dashboards.md`), so
keep their headings and lists in shape.

## Commits and pull requests

- Branch from `main` and keep one topic per pull request.
- Write commit messages that say what changed and why, with a short first line.
- Say in the pull request what you changed, why, and how you tested it; include a
  screenshot for UI changes.
- CI must be green before a merge. Pull requests are usually squash-merged.
- In [ci.yml](.github/workflows/ci.yml), add new jobs rather than renaming existing
  ones: `main` requires its checks by name.
- Never commit passwords, tokens, keys or real log data, even in tests; use made-up
  values such as `example.com` addresses and the documentation IP ranges.

## License

Signalith is licensed under the [Apache License 2.0](LICENSE). By contributing, you
agree that your contribution is licensed under the same license (inbound = outbound, as
section 5 of the license says). There is no contributor license agreement to sign. Only
contribute work you have the right to submit, and keep third-party notices in
[NOTICE](NOTICE) up to date when you add data or code from elsewhere.
