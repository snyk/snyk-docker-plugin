# AGENTS.md

Guidance for AI coding agents (Claude Code, Cursor, Copilot, etc.) working in this repo.

## What this is

`snyk-docker-plugin` is a library that extracts dependency metadata from
container images. It is consumed as a library — there is no CLI entry point of
its own. The public surface is exported from `lib/index.ts` (`scan`, `display`,
`extractContent`, `dockerFile`, plus the supporting types).

Known consumers include:

- `snyk/cli` — scan handler
- `snyk/kubernetes-monitor` — scan handler
- `snyk/container-image-collector` — scan handler (with `--exclude-app-vulns`)
- `snyk/docker-registry-agent` — scan handler
- `snyk/docker-deps` — types, Dockerfile/image analysis
- `snyk/kubernetes-upstream`, `snyk/kubernetes-agent`, `snyk/registry` — types only

Treat any change to `PluginResponse`, `ScanResult`, `Fact`, or `FactType` (and
the dockerfile-analysis types) as a public-API change with multiple downstream
consumers, not just the CLI.

## Output model: `PluginResponse` and Facts

`scan()` returns a `PluginResponse` containing one or more `ScanResult`s. Each
`ScanResult` carries a list of typed `Fact` objects — this is the contract with
every downstream consumer (see "What this is" above). All `FactType` values are
enumerated in `lib/types.ts`; concrete shapes live in `lib/facts.ts`. Common ones:

- `depGraph` — a `@snyk/dep-graph` for a package manager or application
- `dockerfileAnalysis` — base image, instructions, layers
- `imageLayers`, `imageId`, `imageNames`, `imageOsReleasePrettyName`,
  `imageSizeBytes`, `imageCreationTime`, `imageLabels`
- `jarFingerprints`, `keyBinariesHashes` — for things not installed by a
  package manager
- `imageManifestFiles` — raw manifest contents (e.g. `requirements.txt`)
- `pluginVersion`, `pluginWarnings`

When adding a new ecosystem or signal, emit a `Fact` with an existing
`FactType` if one fits; introducing a new `FactType` is a contract change
affecting every consumer and should be flagged in the PR.

## Provenance attestations

Provenance attestations are optional supply-chain metadata attached to a
container image that describes where it came from and how it was built. 

Specific provenance fields are parsed from attestation manifests embedded
in the OCI image index. Attestations larger than 2 MB are skipped.
Downstream, the collapsed provenance fields are emitted as a
`provenanceMetadata` fact and persisted in `container-monitor-data`.

## Repo layout

```
lib/
  scan.ts                  Top-level entry: scan(options) -> PluginResponse
  index.ts                 Public exports
  extractor/               Read images: docker-archive, oci-archive, kaniko-archive
  analyzer/                Identify OS, package managers, applications, runtimes
  inputs/                  Per-ecosystem file readers (apk, apt, rpm, node, java, python, php, binaries, ...)
  parser/                  Parse package manager databases into dep graphs
  dependency-tree/         Dep graph construction helpers
  dockerfile/              Dockerfile parsing and base-image analysis
  go-parser/               Go binary parsing
  python-parser/           Python package parsing
test/
  unit/  lib/              Fast tests, no Docker required
  system/                  Integration tests; require a running Docker daemon + auth env vars
  fixtures/                Image archives and sample data
```

## Setup

- Node `>=20.19` (see `.nvmrc`: `20`).
- `npm install` against the public npm registry. The `@snyk/*` runtime
  dependencies are published publicly — no auth needed for local install.
  (CI writes an `NPM_TOKEN` to `.npmrc`; you don't need to replicate that.)
- `npm run build` compiles TypeScript to `dist/`.

## Commands

Use these exact scripts — don't invent new ones.

| Task                 | Command                                             |
| -------------------- | --------------------------------------------------- |
| Build                | `npm run build`                                     |
| Lint (all)           | `npm run lint`                                      |
| Auto-format + fix    | `npm run format`                                    |
| Unit tests (default) | `npm run test:unit`                                 |
| System tests         | `npm run test:system` (requires Docker — see below) |
| All tests            | `npm test`                                          |

For a quick inner loop, `npm run test:unit` is fastest. Run
`npm run test:system` (or full `npm test`) before declaring a change done,
provided Docker and the required env vars are available — see below. If they
aren't, say so explicitly rather than skipping silently.

## Testing rules

- **New tests must be Jest, with the `.spec.ts` suffix.** Files ending in
  `.test.ts` are legacy `tap` tests — do not add new ones, and prefer migrating
  rather than extending them.
- System tests need:
  - A running Docker daemon (with "Use containerd for pulling and storing
    images" **disabled** in Docker Desktop — containerd causes SHA mismatches).
  - Env vars `DOCKER_HUB_PRIVATE_IMAGE`, `DOCKER_HUB_USERNAME`,
    `DOCKER_HUB_PASSWORD` (values in 1Password).
  - At runtime, the plugin itself reads `SNYK_REGISTRY_USERNAME` /
    `SNYK_REGISTRY_PASSWORD` — these are separate from the test creds.
- See `test/README.md` for the authoritative details.

### Snapshots

Some tests use Jest snapshots (`__snapshots__/` directories). Update with
`npx jest -u <pattern>` and **review the diff** — snapshot churn often hides
real behavior changes. Note: `jest.config.js` pins a custom `snapshotFormat`
to keep pre-Jest-29 snapshots readable; don't change it casually.

## Debugging

- The library uses the [`debug`](https://www.npmjs.com/package/debug) package.
  Set `DEBUG=snyk-docker-plugin*` (or a more specific namespace) when running
  tests or a consumer to see internal logs.
- `npm run debug` runs `tsc-watch` with `node --inspect --inspect-brk` for
  step-through debugging in an attached debugger.

## CI

CircleCI (`.circleci/config.yml`) runs build, lint, and tests on:

- Linux (`cimg/node:20.19`) — full Jest suite, including system tests
- Windows (`win/server-2022`) — `test/windows/` suite via `npm run test:windows` (fixture-only) and `npm run test:windows:docker` (requires Docker daemon)

`main`-branch failures notify Slack `#team-container-pipeline-info`. Match the
target Node major (`20`) when validating locally.

## Commit & PR conventions

- **Conventional commits, enforced by commitlint** (`@commitlint/config-conventional`).
  Allowed types: `feat`, `fix`, `docs`, `test`, `chore`, `refactor`, `style`, `perf`.
  Header max length 100. Example: `fix: handle empty layer in OCI archive`.
- For a bug fix, prefer committing a **failing test first**, then the fix in a
  separate commit (see `.github/CONTRIBUTING.md`).
- CODEOWNERS: `@snyk/container_container` reviews everything by default.

## Things not to touch

- `dist/` — generated by `tsc`, gitignored, never hand-edit.
- Test fixtures under `test/fixtures/` are large and load-bearing — don't
  regenerate or "tidy" them without a clear reason.

## Style

- TypeScript, formatted by Prettier (`{ "trailingComma": "all", "arrowParens": "always" }`)
  and linted by tslint. Run `npm run format` before sending changes.
- Prefer editing existing files in `lib/<area>/` over creating new top-level
  modules. Mirror the existing per-ecosystem layout (`inputs/<eco>`,
  `analyzer/applications/<eco>`, `parser/<eco>`).

## When in doubt

- Public API: read `lib/index.ts` and `lib/types.ts`.
- How a scan flows end-to-end: start at `lib/scan.ts`.
- How to add support for a new ecosystem: look at an existing one under
  `lib/inputs/` + `lib/analyzer/applications/` + `lib/parser/` as a template.

## Cursor Cloud specific instructions

These notes are specific to the Cursor Cloud Agent VM. Standard commands live in
the tables above and in `package.json` — only the non-obvious caveats are here.

### Running unit tests — set `FORCE_COLOR`

`npm run test:unit` passes, but you **must** export `FORCE_COLOR=1` (or higher),
e.g. `FORCE_COLOR=3 npm run test:unit`. Without it, the 4 `display` tests in
`test/lib/display.spec.ts` fail: their expected fixtures embed ANSI color
escapes, and `chalk` strips colors when stdout is not a TTY (as in the cloud
shell). This is an environment artifact, not a code bug — do not "fix" the
fixtures.

### Docker is installed but Docker Hub pulls are blocked

- The Docker engine is installed and configured for docker-in-docker
  (`fuse-overlayfs` storage driver in `/etc/docker/daemon.json`). It is **not**
  auto-started: run `sudo dockerd >/tmp/dockerd.log 2>&1 &` once per VM if you
  need it. The socket is left world-readable/writable so `docker` works without
  `sudo`.
- Network egress to Docker Hub **blob storage** (`*.s3...amazonaws.com` /
  `production.cloudflare.docker.com`) is blocked, so `docker pull <docker.io image>`
  fails with TLS/`EOF` errors after the manifest fetch. Pull Docker official
  images from the AWS public mirror instead, e.g.
  `docker pull public.ecr.aws/docker/library/node:18-alpine`.
- Consequently `npm run test:system` (and the sibling `snyk-docker-pull` repo's
  tests) cannot pull their target images here and will fail on network — run
  `npm run test:unit` for the inner loop and rely on CI for system tests, unless
  the user widens network access and provides the `DOCKER_HUB_*` creds.

### Quick end-to-end smoke of the library

`scan()` works fully offline against a saved archive — no daemon or network
needed once the tar exists:

```bash
docker pull public.ecr.aws/docker/library/node:18-alpine
docker save public.ecr.aws/docker/library/node:18-alpine -o /tmp/img.tar
node -e 'require("./dist").scan({path:"docker-archive:/tmp/img.tar"}).then(r=>console.log(r.scanResults[0].facts.map(f=>f.type)))'
```

(`npm run build` first so `dist/` exists.)

### Workspace-wide credential note

This VM contains several sibling Snyk repos under `repos/`. The public libraries
(`snyk-docker-plugin`, `snyk-docker-pull`, `docker-registry-v2-client`) install
from the public npm registry with no auth. The service repos
(`docker-deps`, `container-image-collector`, `docker-registry-agent`, `registry`)
depend on **private `@snyk/*` npm packages** and need an `NPM_TOKEN`; the Go
services (`container-image-service`, `container-importer`, `container-monitor-data`)
depend on **private `github.com/snyk/*` modules** (`GOPRIVATE=github.com/snyk`)
and need a GitHub credential with access to the Snyk org. Without those secrets
their dependency installs fail with 404 / "repository not found".
