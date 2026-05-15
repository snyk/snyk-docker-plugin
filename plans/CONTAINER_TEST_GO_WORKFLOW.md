# Container Test — Native Go Workflow

> Status: **Plan, accepted; implementation in progress**
> Scope: Add a native `snyk container test` Go workflow so the command no longer falls back to the embedded TypeScript CLI.

---

## 1. Problem

Today's CLI flow:

1. `snyk container test <image>` → cobra has no registered workflow for `container test` → `unknownCommandMessage` error.
2. `handleErrorFallbackToLegacyCLI` shells out to the embedded TS CLI.
3. TS CLI calls the Node.js `snyk-docker-plugin` in-process.

Result: the Go plugin we wired up via `go-extension-adapter` (which registers `container depgraph`) is reached by `container sbom` but never by `container test`.

To make `container test` use the Go plugin end-to-end, the CLI needs a native Go workflow that:

- Claims the `container test` workflow identifier (so cobra dispatches to it).
- Invokes the already-registered `container depgraph` workflow for the dep graph + image facts.
- Sends each dep graph to the Snyk Test API.
- Renders the results.

---

## 2. Location & module shape

A new top-level module inside `snyk-docker-plugin`:

```
snyk-docker-plugin/
  go/                              # plugin (unchanged)
  go-extension-adapter/            # registers "container depgraph" (unchanged)
  go-cli-extension-container/      # NEW — registers "container test"
    go.mod                         # module: github.com/snyk/snyk-docker-plugin/cli-extension-container
    extension.go                   # Init(e) + entrypoint
    flags.go                       # pflag definitions
    testflow.go                    # depgraph → Test API → results
    output.go                      # JSON + human rendering
    README.md
```

Rationale: matches the pattern already proven by `go-extension-adapter`, uses a single `replace` directive in `cliv2/go.mod`, and avoids spinning up a new GitHub repo. Promotion to its own `snyk/cli-extension-container` repo later is a rename + version pin — no architectural change.

---

## 3. Workflow internals

### Registration (`extension.go`)

```go
const WorkflowName = "container test"

func Init(e workflow.Engine) error {
    _, err := e.Register(
        workflow.NewWorkflowIdentifier(WorkflowName),
        workflow.ConfigurationOptionsFromFlagset(flags()),
        entrypoint,
    )
    return err
}
```

### Entrypoint (`testflow.go`)

Mirrors `container-cli/internal/workflows/sbom/sbom.go` — invoke `container depgraph` via the engine, then transform each result:

```
entrypoint(ictx, _)
  cfg := ictx.GetConfiguration()
  depGraphID := workflow.NewWorkflowIdentifier("container depgraph")
  depData, err := ictx.GetEngine().InvokeWithConfig(depGraphID, cfg.Clone())
  for d in depData:
      scanResult := decode(d.GetPayload().([]byte))           # plugin's ScanResult JSON
      depGraph   := extractDepGraphFact(scanResult)
      target     := scanResult.Target.Image
      result     := runSnykTest(ctx, ictx, depGraph, target, cfg)
      out = append(out, renderedData(result))
  return out
```

### Test API call

Mirror `cli-extension-os-flows/internal/commands/ostest/`:

- Build client: `testapi.NewTestClient(snykClient.GetAPIBaseURL(), WithPollInterval, WithCustomHTTPClient)`.
- Build subject: `testapi.NewStartTestParamsFromSubject(orgID, &subject, &testConfig)`.
- `subject` carries the dep graph (exact `TestSubjectCreate` variant to confirm at implementation time).
- Reuse `ostest.RunTestWithSubject` if exported, else inline the ~30 lines of `runTestInternal`.

### Output (`output.go`)

- Default human: per-image vuln summary (counts by severity, base image, top vulns). Minimal in first cut.
- `--json`: emit `LegacyVulnerabilityResponse` shape returned by `RunTestWithSubject`.
- `--sarif`: defer — the gaf `output` workflow already maps `application/json+vuln` data to SARIF. Hook up later.

---

## 4. Flags

Combine `container-cli`'s `CommonFlags` with the ostest standard set:

| Flag | Source |
|---|---|
| `--platform`, `--username`, `--password`, `--exclude-app-vulns`, `--exclude-node-modules`, `--nested-jars-depth` | container-cli `CommonFlags` |
| `--file` (Dockerfile path) | container-cli |
| `--exclude-base-image-vulns` | new (read at render time) |
| `--org`, `--project-name`, `--target-reference`, `--severity-threshold`, `--json`, `--sarif` | gaf / ostest standard |

Declared once in `flags.go` and passed through `workflow.ConfigurationOptionsFromFlagset(fs)`.

---

## 5. cliv2 integration

Delta on top of the existing `dockerplugin.Init` change in `cli/cliv2/cmd/cliv2/main.go`:

`cliv2/go.mod`:

```
require github.com/snyk/snyk-docker-plugin/cli-extension-container v0.0.0
replace github.com/snyk/snyk-docker-plugin/cli-extension-container => ../../snyk-docker-plugin/go-cli-extension-container
```

`cliv2/cmd/cliv2/main.go`:

```
import containertest "github.com/snyk/snyk-docker-plugin/cli-extension-container"
...
engine.AddExtensionInitializer(containertest.Init)   # immediately after dockerplugin.Init
```

Order matters: `dockerplugin.Init` must register `container depgraph` before `containertest.Init` runs, because the new entrypoint looks it up.

---

## 6. Implementation order

1. Module scaffold (`go.mod`, `extension.go`, `flags.go`) — verify cliv2 still builds.
2. Stub entrypoint invokes `container depgraph` and echoes its JSON output. Validates the depgraph→workflow.Data plumbing without Test-API risk.
3. Test API call against a single dep graph + minimal human output.
4. Multi-dep-graph fan-out + `--json`.
5. Severity threshold, exit codes, base-image-vuln exclusion.
6. SARIF + remaining flag parity.

Each step is independently testable against
`oci-archive:./test/fixtures/oci-archives/busybox-1.31.1.tar`
since the depgraph half is already proven.

---

## 7. Open questions (to resolve at implementation time)

- **Subject variant**: confirm whether `testapi.TestSubjectCreate` has a container-specific variant or if we reuse the dep-graph variant ostest uses (tagging `imageId`/`imageLayers` via scan-result metadata).
- **Fan-out**: an image with both OS and app deps yields multiple dep graphs. Mirror the TS CLI behaviour — one Test-API call per ecosystem.
- **Org input**: resolve via `cfg.GetString(configuration.ORGANIZATION)`; verify it's the slug or UUID the ostest path uses.

---

## 8. References

- `container-cli/internal/workflows/sbom/sbom.go:65` — workflow-invokes-workflow pattern.
- `container-cli/internal/workflows/depgraph/depgraph.go:39` — depgraph workflow ID definition.
- `cli-extension-os-flows/internal/commands/ostest/test_execution.go:41` — `RunTestWithSubject`.
- `cli-extension-os-flows/internal/commands/ostest/workflow.go:92` — `TestClient` construction.
- `go-application-framework/pkg/workflow/types.go:99` — `Engine.Invoke*` signatures.
- `go-application-framework/pkg/apiclients/testapi/testapi.go:177` — `TestClient` interface.
- `go-extension-adapter/extension.go:65` — existing `container depgraph` registration.
