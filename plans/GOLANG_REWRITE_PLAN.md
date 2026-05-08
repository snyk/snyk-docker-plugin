# Go Rewrite Plan: snyk-docker-plugin

> Status: **Draft for review**  
> Scope: Full port of `snyk-docker-plugin` (TypeScript) to Go, with a dual-implementation test harness, equivalence integration tests, 100% unit coverage, and compliance with the Snyk CLI Go extension API (`go-application-framework/pkg/workflow`).

---

## 1. What this is and why the plan matters

`snyk-docker-plugin` is the library that extracts container-image dependency metadata for every Snyk container scan. It has ~7,600 lines of TypeScript across 80+ source files, 217 unit tests and 217 system (integration) tests. The Go rewrite must:

- Produce **identical `PluginResponse` / `ScanResult` / `Fact` JSON** to the TS implementation so all downstream consumers (CLI, kubernetes-monitor, DRA, etc.) are unaffected.
- Expose a **workflow extension entry point** (`func Init(e workflow.Engine) error`) compatible with `github.com/snyk/go-application-framework/pkg/workflow`, the same pattern used by `container-cli`, `cli-extension-dep-graph`, and every other first-party Go extension.
- Ship a **test harness** that runs the same test corpus against both implementations, flags any divergence, and becomes the merge gate.
- Achieve **100% unit test coverage** on the Go side.

---

## 2. Go extension API contract

The Snyk CLI embeds Go extensions via:

```go
// go-application-framework/pkg/workflow/types.go
type ExtensionInit func(engine Engine) error
type Callback      func(invocation InvocationContext, input []Data) ([]Data, error)
```

Every extension implements:

```go
// pkg/dockerplugin/extension.go
func Init(e workflow.Engine) error {
    _, err := e.Register(
        WorkflowID,                          // *url.URL
        configurationOptionsFromFlagSet(),   // workflow.ConfigurationOptions
        entrypoint,                          // workflow.Callback
    )
    return err
}
```

The CLI wires it in as:

```go
engine.AddExtensionInitializer(dockerplugin.Init)
```

### 2.1 Workflow identifier

```go
var WorkflowID = workflow.NewWorkflowIdentifier("container/scan")
```

The type identifier for the output data:

```go
var TypeIDPluginResponse = workflow.NewTypeIdentifier(WorkflowID, "pluginResponse")
```

### 2.2 Input / output

| Direction | Type | Description |
|-----------|------|-------------|
| Input (config) | `configuration.Configuration` | All `PluginOptions` fields read via `config.GetString(…)` / `config.GetBool(…)` |
| Output | `[]workflow.Data` | One `workflow.Data` per `ScanResult`, payload is `[]byte` (JSON-encoded `ScanResult`) |

This mirrors the pattern in `container-cli/internal/workflows/depgraph` where each dep-graph is a separate `workflow.Data` item.

### 2.3 Configuration flags

Every `PluginOptions` field becomes a pflag:

| TS field | Go flag name | Type |
|----------|-------------|------|
| `path` | `path` / `targetDirectory` | string |
| `file` | `file` | string |
| `username` | `username` | string |
| `password` | `password` | string |
| `platform` | `platform` | string |
| `imageSavePath` | `image-save-path` | string |
| `imageNameAndTag` | `image-name-and-tag` | string |
| `exclude-app-vulns` | `exclude-app-vulns` | bool |
| `exclude-node-modules` | `exclude-node-modules` | bool |
| `exclude-base-image-vulns` | `exclude-base-image-vulns` | bool |
| `nested-jars-depth` | `nested-jars-depth` | int |
| `include-system-jars` | `include-system-jars` | bool |
| `collect-application-files` | `collect-application-files` | bool |
| `target-reference` | `target-reference` | string |
| `globsToFind.include` | `globs-include` | []string |
| `globsToFind.exclude` | `globs-exclude` | []string |

Registry credentials fall back to env vars `SNYK_REGISTRY_USERNAME` / `SNYK_REGISTRY_PASSWORD` when flags are empty (same logic as `scan.ts:mergeEnvVarsIntoCredentials`).

---

## 3. Repository layout

The Go code lives in a new top-level `go/` directory inside this repo so it shares fixtures, CI, and the test harness with the TS code.

```
snyk-docker-plugin/
├── lib/                          # existing TypeScript source (unchanged)
├── test/                         # existing TS tests (unchanged)
├── go/
│   ├── go.mod                    # module: github.com/snyk/snyk-docker-plugin
│   ├── go.sum
│   ├── pkg/
│   │   ├── extension/            # workflow.Engine entry point
│   │   │   ├── extension.go      # Init(), WorkflowID, TypeIDPluginResponse
│   │   │   ├── flags.go          # pflag definitions
│   │   │   └── extension_test.go
│   │   ├── types/                # Go equivalents of lib/types.ts & lib/facts.ts
│   │   │   ├── pluginresponse.go
│   │   │   ├── scanresult.go
│   │   │   ├── fact.go
│   │   │   ├── options.go
│   │   │   └── depgraph.go       # mirror of @snyk/dep-graph JSON wire format
│   │   ├── image/                # image type detection, archive path parsing
│   │   │   ├── type.go           # ImageType enum + GetImageType()
│   │   │   ├── name.go           # ImageName (name + digest)
│   │   │   └── savepath.go
│   │   ├── extractor/            # tar archive reading (docker, oci, kaniko)
│   │   │   ├── extractor.go      # ExtractImageContent() – main entry
│   │   │   ├── types.go          # ExtractAction, ExtractedLayers, ImageConfig, …
│   │   │   ├── layer.go          # whiteout handling, layer merging
│   │   │   ├── decompress.go     # zstd / gz / uncompressed detection
│   │   │   ├── docker/
│   │   │   │   ├── archive.go    # docker-archive extractor
│   │   │   │   └── archive_test.go
│   │   │   ├── oci/
│   │   │   │   ├── archive.go    # oci-archive extractor
│   │   │   │   └── archive_test.go
│   │   │   └── kaniko/
│   │   │       ├── archive.go
│   │   │       └── archive_test.go
│   │   ├── inputs/               # per-ecosystem file readers
│   │   │   ├── apk/
│   │   │   │   ├── static.go     # ExtractAction + content getter
│   │   │   │   └── static_test.go
│   │   │   ├── apt/
│   │   │   │   ├── static.go
│   │   │   │   └── static_test.go
│   │   │   ├── rpm/
│   │   │   │   ├── static.go
│   │   │   │   └── static_test.go
│   │   │   ├── chisel/
│   │   │   ├── osrelease/
│   │   │   ├── node/
│   │   │   ├── java/
│   │   │   ├── python/
│   │   │   ├── php/
│   │   │   ├── binaries/
│   │   │   ├── baseruntimes/
│   │   │   ├── distroless/
│   │   │   ├── redhat/
│   │   │   └── filepattern/
│   │   ├── analyzer/             # per-ecosystem analysis logic
│   │   │   ├── static.go         # top-level analyzeStatically()
│   │   │   ├── osrelease/
│   │   │   │   ├── detector.go
│   │   │   │   ├── release.go    # tryOSRelease, tryLsbRelease, …
│   │   │   │   └── release_test.go
│   │   │   ├── packages/
│   │   │   │   ├── apk.go        # APK parser
│   │   │   │   ├── apk_test.go
│   │   │   │   ├── apt.go        # dpkg parser + purl
│   │   │   │   ├── apt_test.go
│   │   │   │   ├── rpm.go        # BDB/NDB/SQLite RPM parser
│   │   │   │   ├── rpm_test.go
│   │   │   │   └── chisel.go
│   │   │   ├── applications/
│   │   │   │   ├── node.go
│   │   │   │   ├── java.go       # JAR fingerprinting
│   │   │   │   ├── python/
│   │   │   │   │   ├── pip.go
│   │   │   │   │   └── poetry.go
│   │   │   │   ├── php.go
│   │   │   │   └── types.go
│   │   │   └── baseruntimes/
│   │   │       └── java.go       # Java runtime release detection
│   │   ├── parser/               # pkg analysis → dep-graph
│   │   │   ├── parser.go         # parseAnalysisResults()
│   │   │   └── parser_test.go
│   │   ├── deptree/              # DepTree builder (kept for legacy compat)
│   │   │   ├── tree.go           # buildTree() → DepTree → DepGraph
│   │   │   └── tree_test.go
│   │   ├── depgraph/             # @snyk/dep-graph JSON wire format
│   │   │   ├── depgraph.go       # DepGraph struct + JSON marshaling
│   │   │   ├── builder.go        # depTreeToGraph() equivalent
│   │   │   └── depgraph_test.go
│   │   ├── dockerfile/           # Dockerfile parsing & analysis
│   │   │   ├── parse.go          # readDockerfileAndAnalyse()
│   │   │   ├── instructions.go   # instruction parser (install regex)
│   │   │   ├── updater.go
│   │   │   ├── types.go
│   │   │   └── parse_test.go
│   │   ├── gobinary/             # Go binary / pclntab analysis
│   │   │   ├── gobinary.go
│   │   │   ├── pclntab.go
│   │   │   └── gobinary_test.go
│   │   ├── pythonparser/
│   │   │   ├── requirements.go
│   │   │   ├── metadata.go
│   │   │   └── parser_test.go
│   │   ├── registry/             # image pull / docker daemon inspect
│   │   │   ├── inspector.go      # getImageArchive() equivalent
│   │   │   ├── docker.go         # Docker daemon client
│   │   │   └── inspector_test.go
│   │   ├── response/             # buildResponse() equivalent
│   │   │   ├── builder.go
│   │   │   └── builder_test.go
│   │   └── scan/                 # top-level scan() entry (non-workflow path)
│   │       ├── scan.go
│   │       └── scan_test.go
│   └── internal/
│       └── testutil/             # shared test helpers
│           ├── fixtures.go       # loads test/fixtures/ from TS repo
│           └── assert.go         # deep-equal helpers for ScanResult
├── test-harness/                 # dual-implementation test harness
│   ├── harness.go                # Scanner interface + factory
│   ├── ts_adapter/
│   │   ├── adapter.go            # runs TS via `node` subprocess, parses JSON
│   │   └── adapter_test.go
│   ├── go_adapter/
│   │   ├── adapter.go            # calls go/pkg/scan directly
│   │   └── adapter_test.go
│   └── equivalence/
│       ├── equivalence_test.go   # parameterised over both impls
│       └── cases_test.go         # all integration test cases ported here
└── GOLANG_REWRITE_PLAN.md        # this file
```

---

## 4. Data model

All Go structs are direct transliterations of `lib/types.ts` and `lib/facts.ts`. JSON tags must match the TS serialization exactly because the CLI sends the wire format to Snyk's API.

```go
// go/pkg/types/pluginresponse.go
type PluginResponse struct {
    ScanResults []ScanResult      `json:"scanResults"`
    Analytics   []PluginAnalytics `json:"analytics,omitempty"`
}

type ScanResult struct {
    Name            string          `json:"name,omitempty"`
    Policy          string          `json:"policy,omitempty"`
    Target          ContainerTarget `json:"target"`
    Identity        Identity        `json:"identity"`
    Facts           []Fact          `json:"facts"`
    TargetReference string          `json:"targetReference,omitempty"`
}

type ContainerTarget struct { Image string `json:"image"` }
type Identity struct {
    Type       string            `json:"type"`
    TargetFile string            `json:"targetFile,omitempty"`
    Args       map[string]string `json:"args,omitempty"`
}

type Fact struct {
    Type FactType    `json:"type"`
    Data interface{} `json:"data"`
}
```

### 4.1 DepGraph wire format

The `@snyk/dep-graph` library serialises to a well-defined JSON schema. The Go implementation must produce the same schema so the CLI can pass it to the API unmodified.

```go
// go/pkg/depgraph/depgraph.go
type DepGraphData struct {
    SchemaVersion string       `json:"schemaVersion"`  // "1.2.0"
    PkgManager    PkgManager   `json:"pkgManager"`
    Pkgs          []Pkg        `json:"pkgs"`
    Graph         Graph        `json:"graph"`
}
type PkgManager struct {
    Name         string       `json:"name"`
    Repositories []Repository `json:"repositories,omitempty"`
}
type Graph struct {
    RootNodeID string  `json:"rootNodeId"`
    Nodes      []Node  `json:"nodes"`
}
type Node struct {
    NodeID string     `json:"nodeId"`
    PkgID  string     `json:"pkgId"`
    Deps   []DepRef   `json:"deps"`
}
type DepRef struct { NodeID string `json:"nodeId"` }
type Pkg struct {
    ID   string  `json:"id"`
    Info PkgInfo `json:"info"`
}
type PkgInfo struct {
    Name    string `json:"name"`
    Version string `json:"version,omitempty"`
}
```

Schema version `"1.2.0"` matches what `@snyk/dep-graph` currently emits. Pin this and add a test that compares the Go and TS outputs byte-for-byte on the same fixture.

---

## 5. Implementation phases

Each phase is independently reviewable and mergeable. Phases build on each other but each is testable in isolation.

### Phase 0 — Scaffolding & test harness (Week 1)

**Goal:** Get the dual-implementation harness green before writing any real Go logic.

1. Create `go/go.mod` with module `github.com/snyk/snyk-docker-plugin` (same GitHub org, same repo, Go sub-module).
2. Add key dependencies:
   ```
   github.com/snyk/go-application-framework
   github.com/spf13/pflag
   github.com/rs/zerolog
   github.com/stretchr/testify
   github.com/klauspost/compress        # zstd / gzip
   github.com/opencontainers/image-spec # OCI manifest types
   ```
3. Define `go/pkg/types/` – all Go struct mirrors of the TS data model.
4. Define `test-harness/harness.go`:
   ```go
   type Scanner interface {
       Scan(ctx context.Context, opts ScanOptions) (*types.PluginResponse, error)
   }
   ```
5. Implement `test-harness/ts_adapter/adapter.go`:
   - Compiles a small TS runner (`scripts/run-scan.ts`) that calls `plugin.scan(opts)` and writes JSON to stdout.
   - `adapter.Scan()` execs `node scripts/run-scan.ts '<<opts-json>>'`, reads stdout, unmarshals into `*types.PluginResponse`.
   - Depends on `npm run build` having run first; skip gracefully if `node` not found.
6. Implement `test-harness/go_adapter/adapter.go` – stub that returns `nil, errors.New("not implemented")`.
7. Write `test-harness/equivalence/equivalence_test.go` with one skipped test case (alpine fixture) to prove the harness compiles and the TS adapter path works.
8. CI job: `go test ./test-harness/... -run TestEquivalence -v`.

**Exit criteria:** `TestEquivalence/ts_alpine` passes. Go adapter skips. CI green.

---

### Phase 1 — Archive extraction (Weeks 2–3)

**Modules:** `go/pkg/extractor/`, `go/pkg/image/`

**What the TS does:**
- Detects archive type (docker-archive prefix, oci-archive prefix, kaniko-archive, bare identifier).
- Opens the tar, reads `manifest.json` (docker) or `index.json` + per-manifest `manifest.json` (OCI).
- Walks layers in order, applies whiteout logic, produces `ExtractedLayers` (flat map: path → action-name → content).
- Reads `ImageConfig` (JSON): architecture, os, rootfs, config, created, history.
- Supports zstd and gzip layer compression.

**Go implementation:**

```go
// go/pkg/extractor/extractor.go
func ExtractImageContent(
    ctx context.Context,
    imageType image.ImageType,
    archivePath string,
    actions []ExtractAction,
    opts types.PluginOptions,
) (*ExtractionResult, error)
```

`ExtractAction` mirrors the TS:
```go
type ExtractAction struct {
    ActionName      string
    FilePathMatches func(path string) bool
    Callback        func(r io.Reader, size int64) (interface{}, error) // nil = raw []byte
}
```

Layer merging uses the same whiteout algorithm: `.wh.` prefix files delete later-shadowed files; `wh..opq` wipes the directory.

**Key Go libraries:**
- `archive/tar` (stdlib)
- `compress/gzip` (stdlib)
- `github.com/klauspost/compress/zstd`
- `github.com/opencontainers/image-spec/specs-go/v1` for OCI types

**Unit tests** (all using fixtures in `test/fixtures/`):
- Docker archive: `test/fixtures/docker-archives/`
- OCI archive: `test/fixtures/oci-archives/`
- Kaniko archive: `test/fixtures/kaniko-archives/`
- Layer whiteout handling: `test/fixtures/extracted-layers/`
- Zstd-compressed layer: `test/fixtures/containerd-archives/`
- `getImageIdFromManifest` – mirror of `test/lib/extractor/docker-archive/index.spec.ts`
- `getRootFsLayersFromConfig`, `getPlatformFromConfig`, `getDetectedLayersInfoFromConfig`
- `layersWithLatestFileModifications` (whiteout, opaque whiteout, directory removal)

**100% coverage target:** Every branch in whiteout logic, every archive format, every compression codec, every error path (manifest missing, config missing, invalid archive).

---

### Phase 2 — OS release detection (Week 3)

**Modules:** `go/pkg/inputs/osrelease/`, `go/pkg/analyzer/osrelease/`

Direct port of `lib/analyzer/os-release/release-analyzer.ts` and `lib/inputs/os-release/static.ts`.

Files parsed (in priority order):
1. `/etc/os-release` → `tryOSRelease`
2. `/usr/lib/os-release` → `tryOSRelease`
3. `/etc/lsb-release` → `tryLsbRelease`
4. `/etc/debian_version` → `tryDebianVersion`
5. `/etc/alpine-release` → `tryAlpineRelease`
6. `/etc/redhat-release`, `/etc/oracle-release`, `/etc/centos-release` → `tryRedHatRelease`

All fixture data in `test/fixtures/os/*/fs/` is reused unchanged.

**Unit tests** mirror `test/lib/analyzer/os-release-detector.spec.ts` exactly — same directory names, same expected `{name, version, prettyName}` triples for every OS in the fixture set.

---

### Phase 3 — Package manager parsers (Weeks 4–5)

**Module:** `go/pkg/analyzer/packages/`

#### 3a. APK
Port of `lib/analyzer/package-managers/apk.ts`.
- Key–value text format (`P:`, `V:`, `p:`, `r:`, `D:`, `o:`).
- Unit tests mirror `test/lib/analyzer/package-managers/` plus fixtures from `test/fixtures/`.

#### 3b. APT / DEB
Port of `lib/analyzer/package-managers/apt.ts`.
- dpkg `status` file parser.
- `/var/lib/dpkg/info/*.list` extended status.
- purl generation for deb packages (with Debian codename map).
- Distroless variant (multiple dpkg status files).
- Unit tests mirror `test/lib/analyzer/package-managers/apt.spec.ts`.

#### 3c. RPM
Port of `lib/analyzer/package-managers/rpm.ts` + `@snyk/rpm-parser`.
- Three storage formats: BDB (`/var/lib/rpm/Packages`), NDB (`/var/lib/rpm/Packages.db`), SQLite (`/var/lib/rpm/rpmdb.sqlite`).
- The TS delegates BDB/NDB to `@snyk/rpm-parser` (a native C binding). In Go, use `github.com/sassoftware/go-rpmutils` for BDB and implement NDB/SQLite readers natively (the NDB format is documented in the RPM source and the TS has the logic in `lib/analyzer/package-managers/rpm.ts`).
- Unit tests mirror `test/lib/analyzer/package-managers/rpm.spec.ts` and `test/fixtures/rpm/`.

#### 3d. Chisel
Port of `lib/analyzer/package-managers/chisel.ts`.
- Parses `/var/lib/chisel/manifests.wall` (JSON array of chisel package objects).
- Unit tests mirror `test/lib/analyzer/package-managers/chisel.spec.ts`.

**Coverage requirement:** Every parser function, every edge case (empty file, corrupt file, missing optional fields, auto-installed flag).

---

### Phase 4 — Dep-tree / dep-graph construction (Week 5)

**Modules:** `go/pkg/deptree/`, `go/pkg/depgraph/`, `go/pkg/parser/`

This phase is purely algorithmic — no I/O — and must be bit-for-bit equivalent to the TS output.

1. `parser.ParseAnalysisResults()` – select the winning package manager result, map `AnalysisType` → `packageFormat` string.
2. `deptree.BuildTree()` – port of `lib/dependency-tree/index.ts`:
   - `countDepsRecursive` for high-frequency node pruning (threshold = 100).
   - `buildTreeRecursive` for the actual tree walk.
   - Virtual provides map (`p:` APK / `Provides:` deb / RPM `PROVIDES`).
3. `depgraph.DepTreeToGraph()` – port of `@snyk/dep-graph`'s `legacy.depTreeToGraph()`:
   - Deduplicates packages by `name@version`.
   - Handles `|N` suffix for duplicates at the same package.
   - Produces `DepGraphData` with `schemaVersion: "1.2.0"`.

**Unit tests** mirror `test/lib/dependency-tree/index.spec.ts` and `test/fixtures/analysis-results/deps.json`.

**Critical:** The node-deduplication and `|N` suffix logic in `@snyk/dep-graph` is subtle. The Go port of `depTreeToGraph` must pass the existing snapshot tests (loaded as golden files).

---

### Phase 5 — Registry / image pull (Week 6)

**Module:** `go/pkg/registry/`

Port of `lib/docker.ts` + `lib/analyzer/image-inspector.ts`.

Two code paths:
1. **Docker socket** (`docker inspect` + `docker save`) – exec `docker` binary via `os/exec`, same as TS.
2. **Registry pull without Docker** – the TS uses `@snyk/snyk-docker-pull`. The Go equivalent is a direct OCI registry client:
   - Use `github.com/google/go-containerregistry` (already used widely in the Go container ecosystem) for:
     - Auth (anonymous + username/password + env-var credentials)
     - Multi-platform image index resolution (platform flag)
     - Pulling the manifest + config + layer blobs
     - Writing a docker-archive tar to a temp file
   - Platform resolution: same default `linux/amd64`, same `os/arch[/variant]` parsing.

The temp archive is cleaned up after analysis (same as TS `removeArchive()` callback).

**Unit tests:**
- `getImageType()` for every prefix/format.
- `appendLatestTagIfMissing()`.
- `isValidDockerImageReference()`.
- Auth merge from env vars.
- Mock registry server tests for pull path.

---

### Phase 6 — Application dependency scanning (Weeks 7–9)

This is the largest phase. Each ecosystem is independently mergeable.

#### 6a. Node.js (npm / yarn / pnpm)
Port of `lib/analyzer/applications/node.ts` + `lib/analyzer/applications/node-modules-utils.ts`.
- Detect `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`.
- Parse lockfiles to produce dep-graphs.
- The TS uses `snyk-nodejs-lockfile-parser`. Go alternative: port the relevant parts or shell out to `node` (acceptable for MVP; replace in follow-up).
- **MVP approach:** embed a small Node.js runner script; call via subprocess. Flag as technical debt. Parallels how `container-cli` currently shells out to legacy CLI for dep-graphs.
- Unit tests mirror `test/lib/analyzer/applications/node-modules-utils.spec.ts` and `test/fixtures/npm/`, `test/fixtures/yarn/`, `test/fixtures/pnpm/`.

#### 6b. Java (JAR fingerprinting)
Port of `lib/analyzer/applications/java.ts`.
- Walk extracted layers for `*.jar`, `*.war`, `*.ear`.
- Compute SHA-1 of each JAR (and nested JARs up to `nested-jars-depth` levels).
- Produce `JarFingerprintsFact` matching the TS structure exactly.
- The TS uses a custom JAR-walking algorithm; port it directly.
- Unit tests mirror `test/lib/analyzer/java.spec.ts` and `test/fixtures/maven/`, `test/fixtures/pom-properties/`.

#### 6c. Python (pip / poetry)
Port of `lib/analyzer/applications/python/pip.ts` and `poetry.ts` + `lib/python-parser/`.
- pip: parse `requirements.txt` variants.
- poetry: parse `poetry.lock`.
- Unit tests mirror `test/lib/analyzer/python-pip-analyzer.spec.ts` and `test/fixtures/python/`.

#### 6d. PHP (Composer)
Port of `lib/analyzer/applications/php.ts`.
- Parse `composer.lock` JSON.
- The TS uses `@snyk/composer-lockfile-parser`. Port the relevant subset.
- Unit tests mirror `test/lib/analyzer/php.spec.ts` and `test/fixtures/php/`.

#### 6e. Go binaries
Port of `lib/go-parser/`.
- ELF file detection in the archive.
- pclntab parsing (Go 1.2 / 1.16 / 1.18 / 1.20 formats) – this is already Go code reimplemented in TS; porting back to Go is the natural direction. Use `debug/elf` (stdlib) + `runtime/debug` build info format.
- Actually: Go's stdlib `debug/buildinfo.ReadFile()` reads the build info section directly (available since Go 1.18). Use it instead of reimplementing pclntab.
- Unit tests mirror `test/fixtures/go-binaries/`.

#### 6f. Ruby
Detection only (manifest files: `Gemfile.lock`). No dep-graph generation in the TS plugin either – it just collects the file as `imageManifestFiles`. Port accordingly.

---

### Phase 7 — Response builder (Week 9)

**Module:** `go/pkg/response/`

Port of `lib/response-builder.ts`. This assembles all facts into `PluginResponse`. Most of the logic is:
1. `getUserInstructionDeps()` – expand dockerfile packages to transitive deps.
2. `excludeBaseImageDeps()` – filter by dockerfile packages when `--exclude-base-image-vulns`.
3. `annotateLayerIds()` – stamp `dockerLayerId` label on packages.
4. Assemble each `Fact` type into `ScanResult.Facts` in the same order as TS.
5. `truncateAdditionalFacts()` – port of `lib/utils.ts:truncateAdditionalFacts`.
6. `computeScanPayloadMetrics()` – port of `lib/scan-payload-metrics.ts`.

**Unit tests** mirror `test/lib/response-builder.spec.ts` and `test/lib/scan-payload-metrics.spec.ts`.

---

### Phase 8 — Dockerfile analysis (Week 10)

**Module:** `go/pkg/dockerfile/`

Port of `lib/dockerfile/`.
- `parseDockerfile()` – the TS uses `dockerfile-ast`. Go: use `github.com/moby/buildkit/frontend/dockerfile/parser` (stdlib-equivalent for Docker).
- `getPackagesFromDockerfile()` – install-command regex extraction.
- `getLayersFromPackages()` – layer-to-package mapping.
- `instructionDigest()` – SHA of instruction text.
- `analyseDockerfile()` – base image extraction.
- `updateDockerfileBaseImageName()`.

Unit tests mirror `test/lib/dockerfile/index.spec.ts`, `test/lib/instructions-parser.spec.ts`, and all `test/fixtures/dockerfiles/`.

---

### Phase 9 — Top-level scan & extension wiring (Week 10)

**Module:** `go/pkg/scan/`, `go/pkg/extension/`

Ports `lib/scan.ts` and `lib/static.ts`.

```go
// go/pkg/scan/scan.go
func Scan(ctx context.Context, opts types.PluginOptions) (*types.PluginResponse, error)
func ExtractContent(ctx context.Context, actions []extractor.ExtractAction, opts types.PluginOptions) (*extractor.ExtractionResult, error)
```

Then the extension wrapper:

```go
// go/pkg/extension/extension.go
func Init(e workflow.Engine) error {
    _, err := e.Register(WorkflowID, flags(), entrypoint)
    return err
}

func entrypoint(ictx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
    opts := optsFromConfig(ictx.GetConfiguration())
    resp, err := scan.Scan(ictx.Context(), opts)
    if err != nil { return nil, err }
    output := make([]workflow.Data, len(resp.ScanResults))
    for i, sr := range resp.ScanResults {
        b, _ := json.Marshal(sr)
        output[i] = workflow.NewData(TypeIDPluginResponse, "application/json", b)
    }
    return output, nil
}
```

---

### Phase 10 — Equivalence integration tests (Weeks 11–12)

**Module:** `test-harness/equivalence/`

This is the regression gate. Every system test case from `test/system/` is ported as a Go equivalence test parameterised over both adapters. A test fails if:
- The TS adapter returns an error and Go does not (or vice versa).
- The `ScanResult.identity.type` differs.
- The dep-graph node/edge counts differ by more than a small tolerance (to allow for determinism differences in ordering).
- Any `Fact.type` present in TS output is absent from Go output.

```go
// test-harness/equivalence/equivalence_test.go
var cases = []EquivalenceCase{
    {Name: "alpine-3.12-apk",   Opts: ScanOptions{Path: "alpine:3.12.0", Platform: "linux/amd64"}},
    {Name: "debian9-deb",       Opts: ScanOptions{Path: "debian@sha256:89ff...", Platform: "linux/amd64"}},
    {Name: "centos7-rpm",       Opts: ScanOptions{Path: "centos@sha256:50b9...", Platform: "linux/amd64"}},
    {Name: "ubi8-rpm",          Opts: ScanOptions{Path: "redhat/ubi8:8.0", Platform: "linux/amd64"}},
    {Name: "sles15",            Opts: ScanOptions{Path: "registry.suse.com/suse/sle15:15.0"}},
    {Name: "distroless",        Opts: ScanOptions{Path: "gcr.io/distroless/base-debian11"}},
    {Name: "scratch",           Opts: ScanOptions{Path: "docker-archive:test/fixtures/docker-archives/…"}},
    {Name: "chisel-ubuntu",     Opts: ScanOptions{Path: "ubuntu/ubuntu:chisel"}},
    {Name: "node-app",          Opts: ScanOptions{Path: "node:6.14.2"}},
    {Name: "java-app",          Opts: ScanOptions{Path: "openjdk:8"}},
    {Name: "python-pip",        Opts: ScanOptions{Path: "python:3.9"}},
    {Name: "go-binary",         Opts: ScanOptions{Path: "docker-archive:test/fixtures/…"}},
    {Name: "oci-archive",       Opts: ScanOptions{Path: "oci-archive:test/fixtures/oci-archives/…"}},
    {Name: "kaniko-archive",    Opts: ScanOptions{Path: "kaniko-archive:test/fixtures/kaniko-archives/…"}},
    {Name: "arm64-platform",    Opts: ScanOptions{Path: "alpine:3.12.0", Platform: "linux/arm64"}},
    // … all other system test images
}

func TestEquivalence(t *testing.T) {
    ts  := tsadapter.New()
    goa := goadapter.New()
    for _, c := range cases {
        c := c
        t.Run(c.Name+"/ts",  func(t *testing.T) { runAndStore(t, ts,  c) })
        t.Run(c.Name+"/go",  func(t *testing.T) { runAndStore(t, goa, c) })
        t.Run(c.Name+"/cmp", func(t *testing.T) { compare(t, c) })
    }
}
```

Comparison rules (codified in `test-harness/equivalence/compare.go`):

| Field | Comparison |
|-------|------------|
| `scanResults[0].identity.type` | exact |
| `facts` by type: presence | TS set ⊆ Go set (Go may add new facts) |
| `depGraph.pkgManager.name` | exact |
| `depGraph.pkgs` length | exact |
| `depGraph.graph.nodes` count | exact |
| `imageLayers` | exact (order matters) |
| `imageId` | exact |
| `rootFs` | exact |
| `platform` | exact |
| `imageCreationTime` | exact |
| `imageLabels` | exact |
| `containerConfig` | exact |
| `history` | exact |
| `imageOsReleasePrettyName` | exact |
| `pluginVersion` | ignored (different values expected) |
| `analytics` | ignored |

---

## 6. Test coverage strategy

### 6.1 Unit test rule

Every exported function in `go/pkg/` must have a corresponding `_test.go` file. Coverage is enforced with:

```makefile
go test -coverprofile=coverage.out ./go/pkg/...
go tool cover -func=coverage.out | grep -v "100.0%" | grep -v "^total" && exit 1 || exit 0
```

This runs in CI and blocks merge if any package drops below 100%.

### 6.2 Unit test sources

| Go package | Primary TS test to mirror | Fixtures |
|------------|--------------------------|----------|
| `extractor/docker` | `test/lib/extractor/docker-archive/index.spec.ts` | `test/fixtures/docker-archives/` |
| `extractor/oci` | `test/lib/extractor/oci-archive/layer.spec.ts` | `test/fixtures/oci-archives/` |
| `extractor/layer` | `test/lib/extractor/layer.spec.ts` | `test/fixtures/extracted-layers/` |
| `extractor` (top) | `test/lib/extractor/extractor.spec.ts` | various |
| `image` | `test/lib/image-type.spec.ts`, `image-save-path.spec.ts` | — |
| `analyzer/osrelease` | `test/lib/analyzer/os-release-detector.spec.ts` | `test/fixtures/os/` |
| `analyzer/packages/apk` | `test/system/package-managers/apk.spec.ts` (unit portions) | — |
| `analyzer/packages/apt` | `test/lib/analyzer/package-managers/apt.spec.ts` | — |
| `analyzer/packages/rpm` | `test/lib/analyzer/package-managers/rpm.spec.ts` | `test/fixtures/rpm/` |
| `analyzer/packages/chisel` | `test/lib/analyzer/package-managers/chisel.spec.ts` | — |
| `deptree` | `test/lib/dependency-tree/index.spec.ts` | `test/fixtures/analysis-results/` |
| `depgraph` | snapshot files in `test/system/operating-systems/__snapshots__/` | — |
| `parser` | (inline with deptree) | — |
| `dockerfile` | `test/lib/dockerfile/index.spec.ts`, `instructions-parser.spec.ts` | `test/fixtures/dockerfiles/` |
| `gobinary` | `test/fixtures/go-binaries/` | — |
| `pythonparser` | `test/lib/analyzer/python-pip-analyzer.spec.ts` | `test/fixtures/python/` |
| `response` | `test/lib/response-builder.spec.ts` | `test/fixtures/analysis-results/` |
| `scan` | `test/lib/scan.spec.ts` | — |
| `extension` | `test/lib/facts.spec.ts` | — |

### 6.3 Table-driven tests

All Go unit tests use `testify/require` and table-driven patterns:

```go
func TestTryOSRelease(t *testing.T) {
    cases := []struct{
        name   string
        input  string
        want   OSRelease
        wantErr bool
    }{ … }
    for _, c := range cases {
        t.Run(c.name, func(t *testing.T) {
            got, err := TryOSRelease(c.input)
            if c.wantErr { require.Error(t, err); return }
            require.NoError(t, err)
            require.Equal(t, c.want, got)
        })
    }
}
```

### 6.4 Error path coverage

Every function that returns `error` must have at least one test exercising the error path. Use interfaces + fakes (not mocks) where possible to keep tests self-contained.

---

## 7. CI integration

Add a new CI job to `.circleci/config.yml` (or equivalent) that runs after the existing TS jobs:

```yaml
go-unit-tests:
  executor: cimg/go:1.24
  steps:
    - checkout
    - run: cd go && go test -race -coverprofile=cov.out ./pkg/...
    - run: go tool cover -func=go/cov.out | awk '/^total/{print $3}' | grep -E '^100\.'

go-equivalence-tests:
  executor: cimg/go:1.24  # with Docker daemon
  steps:
    - checkout
    - run: npm ci && npm run build   # build TS adapter runner
    - run: cd go && go test -v -timeout 30m ./test-harness/equivalence/...
```

The equivalence tests are gated behind the same `DOCKER_HUB_*` env vars as the TS system tests and are skipped in PR builds without those vars set.

---

## 8. Key technical decisions and risks

### 8.1 RPM parsing

The TS delegates to `@snyk/rpm-parser` which is a native C binding to `librpm`. Options for Go:

| Option | Pros | Cons |
|--------|------|------|
| `cgo` + `librpm` | Exact parity | CGO complexity, cross-compilation issues |
| `github.com/sassoftware/go-rpmutils` | Pure Go BDB support | NDB and SQLite still needed |
| Port NDB reader from TS | Already documented in TS source | Medium effort |
| Shell out to `rpm --dbpath` | Simple | Requires rpm binary on scanner host |

**Recommended:** Use `go-rpmutils` for BDB format (most common). Port the NDB reader from the TS `rpm.ts` directly (it's ~60 lines). For SQLite, use `github.com/mattn/go-sqlite3` (CGO) or `modernc.org/sqlite` (pure Go – preferred). This covers all three formats with no external binary dependency.

### 8.2 Node.js application scanning (MVP)

Parsing `package-lock.json` v1/v2/v3, `yarn.lock` (v1/v2), and `pnpm-lock.yaml` is non-trivial. The TS uses `snyk-nodejs-lockfile-parser`. For MVP:
- Shell out to a bundled Node.js script (acceptable since the extension runs inside the Snyk CLI which already has Node.js available for CLIv1).
- Track as `//TODO(go-rewrite): replace with native Go lockfile parser`.
- Full native port is a follow-up: `npm-lockfile-parser` is well-understood and can be ported package by package.

### 8.3 Dep-graph schema version pinning

The `@snyk/dep-graph` TS library is at schema `1.2.0`. The Go struct must emit the same version. Add a golden-file test that compares the byte-for-byte JSON output of both implementations on the `test/fixtures/analysis-results/deps.json` fixture.

### 8.4 purl generation for DEB packages

The purl format for DEB packages includes the Debian codename. The TS has a hardcoded `debianCodenames` map. Port this map exactly and add a test for every entry.

### 8.5 Determinism

The dep-graph node ordering in the TS is insertion-order (JavaScript Maps). Go maps are non-deterministic. **All Go dep-graph construction must sort nodes and edges** before serialisation to produce stable output. Add a fuzz test that runs `buildTree` twice on the same input and asserts identical JSON.

### 8.6 Event loop spinner

The TS uses `event-loop-spinner` to yield the JS event loop during CPU-intensive operations. In Go, use goroutines with bounded parallelism (`golang.org/x/sync/errgroup`) for per-file processing. This is strictly better.

---

## 9. Milestones

| Week | Milestone | Deliverable | Go adapter status |
|------|-----------|-------------|------------------|
| 1 | — | Phase 0: harness + TS adapter | stub |
| 2–3 | — | Phase 1: archive extraction | partial (archive only) |
| 3 | — | Phase 2: OS release | OS detection works |
| 4–5 | — | Phase 3: package parsers | OS + packages |
| 5 | — | Phase 4: dep-tree / dep-graph | full OS scan works |
| 6 | — | Phase 5: registry pull | live image pull works |
| 7–9 | — | Phase 6: app scanning | all ecosystems |
| 9 | — | Phase 7: response builder | full PluginResponse |
| 10 | — | Phase 8: Dockerfile analysis | Dockerfile facts |
| 10 | — | Phase 9: extension wiring | `workflow.Engine` integrated |
| 11–12 | — | Phase 10: equivalence tests | all cases green |
| 13 | — | Coverage audit, documentation, release | 100% unit coverage |
| 14 | **14** | Phase 11: `display()` port + golden-file tests | display works |
| 15 | **15** | Phase 12: performance benchmarks + regression gate | benchmarks baseline committed |

---

### Phase 11 — Display / human-readable output (Milestone 14)

**Module:** `go/pkg/display/`

Port of `lib/display.ts`. The `display()` function takes `[]ScanResult`, `[]TestResult`, and an `Options` object and returns a formatted, ANSI-coloured string suitable for terminal output. It is part of the library's public API (`lib/index.ts` exports it) and must be ported with the same fidelity as the rest.

#### What it renders

| Section | Condition |
|---------|-----------|
| Per-issue block (severity, description, info URL, introduced-through, from chains, fixed-in) | one per `issue` in each `TestResult` |
| Metadata block (org, package manager, project name, docker image, base image, licenses, platform) | always |
| Summary line (dep count, vuln count or ‘no vulnerable paths’) | always |
| Remediations block (base image advice) | when `testResult.docker.baseImageRemediation` present |
| Suggestions block (pro-tip for `--file` or `--exclude-base-image-vulns`) | when `!options.isDockerUser && config.disableSuggestions !== "true"` |
| User CTA (Docker Hub sign-up link) | when `options.isDockerUser` |

All colouring uses raw ANSI escape codes — the existing fixture files (`test/fixtures/display/output/*.txt`) contain the literal escape sequences, so the golden-file tests work without a terminal.

#### Go implementation

```go
// go/pkg/display/display.go
func Display(
    scanResults []types.ScanResult,
    testResults []types.TestResult,
    errors      []string,
    opts        types.Options,
) (string, error)
```

Use `github.com/fatih/color` (already a transitive dependency via `go-application-framework`) for ANSI colouring. Map TS `chalk` calls:

| TypeScript | Go (`fatih/color`) |
|------------|-------------------|
| `chalk.green(s)` | `color.GreenString(s)` |
| `chalk.bold.red(s)` | `color.New(color.FgRed, color.Bold).Sprint(s)` |
| `chalk.bold.blue(s)` | `color.New(color.FgBlue, color.Bold).Sprint(s)` |
| `chalk.bold.yellow(s)` | `color.New(color.FgYellow, color.Bold).Sprint(s)` |
| `chalk.bold.green(s)` | `color.New(color.FgGreen, color.Bold).Sprint(s)` |
| `chalk.bold.white(s)` | `color.New(color.FgWhite, color.Bold).Sprint(s)` |
| `chalk.whiteBright(s)` | `color.New(color.FgHiWhite).Sprint(s)` |

Force colour output on in tests (`color.NoColor = false`) to match the fixture files.

`padding()` is a straightforward `strings.Repeat(" ", n)` with the same column width constant (`SECTION_PADDING_TO_FORMAT_METADATA = 19`).

Line separator is `os.LineEnding` (matches TS `os.EOL`). Tests run on Linux/macOS where this is `\n`; if Windows support is added later, golden files will need a platform variant.

#### Sub-functions to port

| TS function | Go function |
|-------------|-------------|
| `formatIssue()` | `formatIssue()` |
| `formatIntroduced()` | `formatIntroduced()` |
| `formatFrom()` (max 3 chains) | `formatFrom()` |
| `formatFixedIn()` | `formatFixedIn()` |
| `formatMetadataSection()` | `formatMetadataSection()` |
| `formatMetadataLine()` + `padding()` | `formatMetadataLine()` |
| `formatSummary()` (dep-graph pkg count) | `formatSummary()` |
| `formatVulnSummaryText()` | `formatVulnSummaryText()` |
| `formatRemediations()` | `formatRemediations()` |
| `formatString()` (color+bold combinator) | `formatStyle()` |
| `formatSuggestions()` | `formatSuggestions()` |
| `formatUserCTA()` | `formatUserCTA()` |
| `getColor()` severity switch | `severityColor()` |
| `capitalize()` | `capitalize()` |

`formatSummary()` requires reconstructing a dep-graph from `TestResult.DepGraphData` to call `getDepPkgs()`. Implement `depgraph.PkgCount(data DepGraphData) int` that counts unique non-root packages — a simple walk of `graph.nodes` excluding the root node.

#### Additional types needed

```go
// go/pkg/types/testresult.go
type TestResult struct {
    Org            string             `json:"org"`
    LicensesPolicy interface{}        `json:"licensesPolicy"`
    Docker         DockerTestInfo     `json:"docker"`
    Issues         []Issue            `json:"issues"`
    IssuesData     map[string]IssueData `json:"issuesData"`
    DepGraphData   depgraph.DepGraphData `json:"depGraphData"`
}
type DockerTestInfo struct {
    BaseImage            string                `json:"baseImage,omitempty"`
    BaseImageRemediation *BaseImageRemediation `json:"baseImageRemediation,omitempty"`
}
type BaseImageRemediation struct {
    Code   string                    `json:"code"`
    Advice []BaseImageRemediationAdvice `json:"advice"`
    Message string                   `json:"message,omitempty"`
}
type BaseImageRemediationAdvice struct {
    Message string `json:"message"`
    Bold    bool   `json:"bold,omitempty"`
    Color   string `json:"color,omitempty"`
}
type Issue struct {
    PkgName    string   `json:"pkgName"`
    PkgVersion string   `json:"pkgVersion,omitempty"`
    IssueID    string   `json:"issueId"`
    FixInfo    FixInfo  `json:"fixInfo"`
}
type FixInfo struct {
    NearestFixedInVersion string `json:"nearestFixedInVersion,omitempty"`
}
type IssueData struct {
    ID       string     `json:"id"`
    Severity string     `json:"severity"`
    From     [][]string `json:"from"`
    Title    string     `json:"title"`
}
```

#### Unit tests

All four TS test cases from `test/lib/display.spec.ts` are ported as golden-file tests reading the same fixtures:

| Test case | Fixture output file |
|-----------|--------------------|
| No issues, `path` set | `test/fixtures/display/output/no-issues.txt` |
| No issues, `file` option set | `test/fixtures/display/output/no-issues-with-file-options.txt` |
| Three issues, mixed severities | `test/fixtures/display/output/a-few-issues.txt` |
| Base image remediation only | `test/fixtures/display/output/only-base-image-remediations.txt` |

All four tests compare `Display()` output byte-for-byte against the fixture files, ANSI codes included. No snapshot regeneration is needed — the TS fixtures are the ground truth.

Additional unit tests (100% coverage):
- `formatFrom()`: exactly 3 chains (no truncation), 4 chains (truncation to 3 + "and 1 more..."), 1 chain.
- `formatFixedIn()`: with version, without version.
- `formatSummary()`: zero deps, non-zero deps, zero issues, non-zero issues.
- `formatRemediations()`: nil remediation, advice list, fallback message, empty (returns `""`).
- `formatSuggestions()`: Docker user (returns `""`), `disableSuggestions=true` (returns `""`), no file, with file, with `--exclude-base-image-vulns`.
- `severityColor()`: all four severity levels including unknown.
- `padding()`: exact fit (padLength ≤ 0), normal pad.

#### Milestone 14 exit criteria

- `go test -cover ./go/pkg/display/...` reports 100%.
- All four golden-file tests pass byte-for-byte.
- `go vet` and linter clean.

---

### Phase 12 — Performance benchmarking (Milestone 15)

**Module:** `go/benchmarks/`

Once the Go implementation is functionally complete and all equivalence tests are green, a dedicated benchmark suite measures end-to-end scan latency and memory pressure. Benchmarks run in CI on a fixed executor (no flakiness from variable network) using pre-pulled, locally cached images.

#### 12.1 Benchmark corpus

##### Integration test images (reuse equivalence corpus)

Every image already used in Phase 10 equivalence tests is also a benchmark target, giving baseline numbers across all supported OS/package-manager combinations:

| Image | PM | Notes |
|-------|----|-------|
| `alpine:3.12.0` (linux/amd64) | APK | small, fast baseline |
| `debian@sha256:89ff…` | DEB | medium Debian |
| `centos@sha256:50b9…` | RPM/BDB | legacy BDB format |
| `registry.access.redhat.com/ubi8:8.0` | RPM/NDB | NDB format |
| `registry.suse.com/suse/sle15:15.0` | RPM | SUSE variant |
| `gcr.io/distroless/base-debian11` | DEB (distroless) | no shell |
| `ubuntu/ubuntu:chisel` | Chisel | chisel slim |
| `busybox:1.32.0` | none | scratch-like |
| OCI archive fixture | OCI | local, no pull |
| Kaniko archive fixture | kaniko | local, no pull |

##### Large real-world images (stress benchmarks)

Five large public images chosen to stress memory and parse time. Pulled once and cached on the benchmark executor.

| Image | Approx size | Why |
|-------|-------------|-----|
| `node:20-bookworm` | ~1.1 GB | large DEB image + Node.js app layer |
| `openjdk:21-jdk-bookworm` | ~800 MB | large DEB + JAR scan |
| `python:3.12-bookworm` | ~900 MB | large DEB + pip |
| `gradle:8-jdk21-jammy` | ~1.0 GB | DEB + deeply nested JARs |
| `registry.access.redhat.com/ubi9:latest` | ~250 MB | RPM/NDB at realistic enterprise size |

These are pinned by digest in the benchmark config to guarantee reproducibility across runs.

#### 12.2 Benchmark structure

```
go/benchmarks/
├── bench_test.go        # Go testing.B benchmarks
├── corpus.go            # image list + pull/cache helpers
├── compare_test.go      # TS vs Go head-to-head timing
└── README.md
```

```go
// go/benchmarks/bench_test.go
func BenchmarkScan_Alpine(b *testing.B)         { benchmarkImage(b, "alpine:3.12.0") }
func BenchmarkScan_Debian(b *testing.B)         { benchmarkImage(b, "debian@sha256:…") }
func BenchmarkScan_CentOS_RPM_BDB(b *testing.B) { benchmarkImage(b, "centos@sha256:…") }
func BenchmarkScan_UBI8_RPM_NDB(b *testing.B)  { benchmarkImage(b, "registry.access.redhat.com/ubi8:8.0") }
func BenchmarkScan_Distroless(b *testing.B)    { benchmarkImage(b, "gcr.io/distroless/base-debian11") }
func BenchmarkScan_Node20(b *testing.B)         { benchmarkLargeImage(b, "node:20-bookworm@sha256:…") }
func BenchmarkScan_OpenJDK21(b *testing.B)      { benchmarkLargeImage(b, "openjdk:21-jdk-bookworm@sha256:…") }
func BenchmarkScan_Python312(b *testing.B)      { benchmarkLargeImage(b, "python:3.12-bookworm@sha256:…") }
func BenchmarkScan_Gradle8(b *testing.B)        { benchmarkLargeImage(b, "gradle:8-jdk21-jammy@sha256:…") }
func BenchmarkScan_UBI9(b *testing.B)           { benchmarkLargeImage(b, "registry.access.redhat.com/ubi9:latest@sha256:…") }

func BenchmarkExtract_DockerArchive(b *testing.B) { benchmarkArchive(b, imageType.DockerArchive, "test/fixtures/docker-archives/…") }
func BenchmarkExtract_OciArchive(b *testing.B)    { benchmarkArchive(b, imageType.OciArchive, "test/fixtures/oci-archives/…") }

func benchmarkImage(b *testing.B, image string) {
    b.Helper()
    archivePath := pullAndCache(b, image)  // pulls once, reuses across iterations
    opts := types.PluginOptions{Path: "docker-archive:" + archivePath, Platform: "linux/amd64"}
    b.ResetTimer()
    b.ReportAllocs()
    for i := 0; i < b.N; i++ {
        _, err := scan.Scan(context.Background(), opts)
        if err != nil { b.Fatal(err) }
    }
}
```

Images are pulled to a temp directory via the registry client before `b.ResetTimer()`, so network latency is excluded from the timed region. Subsequent iterations read from the local tar, matching real-world usage where images are pre-pulled.

#### 12.3 TS vs Go head-to-head comparison

```go
// go/benchmarks/compare_test.go
func TestComparePerformance(t *testing.T) {
    if testing.Short() { t.Skip("skipping perf comparison in short mode") }
    for _, img := range benchCorpus {
        img := img
        t.Run(img.Name, func(t *testing.T) {
            tsMs  := timeTS(t, img)
            goMs  := timeGo(t, img)
            ratio := float64(tsMs) / float64(goMs)
            t.Logf("TS: %dms  Go: %dms  ratio: %.2fx", tsMs, goMs, ratio)
            // soft assertion: Go must not be more than 2× slower than TS
            require.Greater(t, ratio, 0.5, "Go is more than 2× slower than TS for %s", img.Name)
        })
    }
}
```

This is intentionally a soft lower bound (Go must not regress more than 2× behind TS) rather than a hard upper bound, because the primary goal is correctness. The ratio is logged for every run so trends are visible in CI artifacts.

#### 12.4 Metrics reported

For each benchmark the following are captured and persisted as CI artifacts:

| Metric | How |
|--------|-----|
| Wall-clock time per op (`ns/op`) | `testing.B` built-in |
| Allocations per op (`allocs/op`) | `b.ReportAllocs()` |
| Bytes allocated per op (`B/op`) | `testing.B` built-in |
| Peak RSS | `runtime.ReadMemStats` before/after |
| TS wall-clock (for ratio) | `time.Now()` around TS subprocess call |

Results are written as JSON to `go/benchmarks/results/latest.json` and compared against `baseline.json` (committed after initial run). CI fails if any benchmark regresses by more than **20%** wall-clock or **50%** allocations relative to baseline.

```json
// go/benchmarks/results/baseline.json (example)
{
  "alpine": {"ns_per_op": 420000000, "allocs_per_op": 142300, "bytes_per_op": 18200000},
  "node20":  {"ns_per_op": 9800000000, "allocs_per_op": 3100000, "bytes_per_op": 840000000}
}
```

#### 12.5 Profiling targets

For each large image, CPU and memory profiles are captured once (not every CI run) and stored as release artifacts:

```bash
go test -bench BenchmarkScan_Node20 -cpuprofile cpu.prof -memprofile mem.prof -benchtime 3x ./go/benchmarks/
go tool pprof -pdf cpu.prof > node20-cpu.pdf
```

This enables hotspot identification after the initial release.

#### 12.6 CI job

```yaml
benchmarks:
  executor: cimg/go:1.24   # dedicated executor with Docker daemon, >=4 vCPU, >=8 GB RAM
  environment:
    BENCHMARK_TIMEOUT: 60m
  steps:
    - checkout
    - run: docker pull alpine:3.12.0 node:20-bookworm …   # pre-pull large images
    - run: |
        cd go && go test -bench . -benchtime 5x -timeout $BENCHMARK_TIMEOUT \
          -benchmem ./benchmarks/ \
          | tee benchmarks/results/latest.txt
    - run: go run ./benchmarks/cmd/compare -baseline benchmarks/results/baseline.json \
             -latest benchmarks/results/latest.txt --fail-on-regression
    - store_artifacts:
        path: go/benchmarks/results/
```

The benchmark job is **not** a merge gate for normal PRs — it runs on `main` after merge and on release branches. It becomes a gate only when a PR is tagged `perf-sensitive`.

#### Milestone 15 exit criteria

- All benchmarks run to completion without error on the CI executor.
- `baseline.json` is committed and the regression check script passes against it.
- At least one CPU profile is committed per large image as a release artifact.
- TS vs Go ratio is logged and no image shows Go taking more than 2× TS wall-clock time.
- `go test -bench . -benchmem` output is human-readable in CI logs (image name, ns/op, B/op, allocs/op).

---

## 10. Out of scope for this plan

- Windows container images – the TS does not fully support these either.
- Replacing the TS implementation in the existing CLI wiring – that is a separate CLI PR after the Go extension is validated.

---

## 11. Open questions (need answers before Phase 0 merge)

6. **Display ANSI portability**: The golden-file fixtures use raw ANSI escape codes that match `chalk`'s output on Linux. Confirm CI executors do not strip ANSI codes before the comparison (or add a `--no-color` path and update fixtures).
7. **Benchmark executor**: Confirm the dedicated benchmark CI executor spec (CPU count, RAM, disk) and whether large images (up to ~1.1 GB) can be pre-pulled and cached between CI runs to avoid repeated egress costs.
8. **Benchmark regression threshold**: Confirm the proposed 20% wall-clock / 50% allocation regression thresholds are acceptable, or adjust before committing `baseline.json`.

Original questions:

1. **Module path**: Should the Go module be `github.com/snyk/snyk-docker-plugin` (same repo, sub-module at `go/`) or a new repo `github.com/snyk/snyk-docker-plugin-go`? Recommend same repo to share fixtures.
2. **RPM**: Confirm the SQLite driver preference (`modernc.org/sqlite` pure-Go vs `mattn/go-sqlite3` CGO). CGO complicates cross-compilation for the CLI release pipeline.
3. **Node.js MVP shim**: Is shelling out to `node` acceptable for the MVP of the Go extension, or must the first release be fully self-contained?
4. **Schema version**: Confirm `@snyk/dep-graph` is still at `1.2.0` and there is no pending bump.
5. **`pluginVersion` fact**: Should the Go implementation use the same version string as the TS, or a separate versioning scheme? Recommend a separate `go-<semver>` prefix to distinguish implementations in analytics.
