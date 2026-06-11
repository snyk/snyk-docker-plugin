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

- Node `>=22` (see `.nvmrc`: `22`).
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
- Jest config: `jest.config.js` (root) and `test/windows/jest.config.js`.
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

- Linux (`cimg/node:22.22`) — full Jest suite, including system tests
- Windows (`win/server-2022`) — `test/windows/` suite via `npm run test-jest-windows`

`main`-branch failures notify Slack `#team-container-pipeline-info`. Match the
target Node major (`22`) when validating locally.

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
