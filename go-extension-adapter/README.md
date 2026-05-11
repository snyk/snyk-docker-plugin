# snyk-docker-plugin extension adapter

This Go module wires `github.com/snyk/snyk-docker-plugin` into the
Snyk CLI v2 (`go-application-framework`) as a native Go workflow extension.

It is a **separate module** so the main `snyk-docker-plugin` module stays
free of the framework's dependency tree.

---

## What it does

Registers the `"container depgraph"` workflow — the same identifier used by
`github.com/snyk/container-cli` — but backed by the Go scanner instead of
shelling out to the TypeScript legacy CLI.

The rest of the container pipeline (SBOM, output, analytics) works unchanged.

---

## Integration into cliv2

### 1. Add to `cliv2/go.mod`

```
require (
    github.com/snyk/snyk-docker-plugin/extension-adapter v0.0.0
)

replace (
    github.com/snyk/snyk-docker-plugin => ../../snyk-docker-plugin/go
    github.com/snyk/snyk-docker-plugin/extension-adapter => ../../snyk-docker-plugin/go-extension-adapter
)
```

### 2. Import the adapter in `cliv2/cmd/cliv2/main.go`

```go
import (
    // ... existing imports ...
    dockerplugin "github.com/snyk/snyk-docker-plugin/extension-adapter"
)
```

### 3. Register the extension in `initExtensions`

```go
func initExtensions(engine workflow.Engine, config configuration.Configuration) {
    // ... existing lines ...

    // Replace the container-cli depgraph shell-out with the native Go implementation.
    // Remove the container.Init line below once this is validated.
    engine.AddExtensionInitializer(dockerplugin.Init)

    // Keep SBOM and other container workflows:
    engine.AddExtensionInitializer(container.Init) // can remove depgraph-only parts
}
```

> **Note:** `container.Init` currently registers both the SBOM workflow and the
> depgraph workflow. The depgraph registration will be superseded by
> `dockerplugin.Init` (last write wins for the same workflow ID).
> Once validated, remove `depgraph.Workflow.InitWorkflow(e)` from `container-cli`
> or replace `container.Init` with a version that only initialises SBOM.

---

## Configuration keys read

| Config key | Source | Description |
|---|---|---|
| `targetDirectory` | `configuration.INPUT_DIRECTORY` | Image path or archive path (first positional arg) |
| `platform` | `--platform` flag | e.g. `linux/amd64` |
| `username` | `--username` flag | Registry auth |
| `password` | `--password` flag | Registry auth |
| `exclude-app-vulns` | `--exclude-app-vulns` flag | Disable app scanning |
| `exclude-node-modules` | `--exclude-node-modules` flag | Skip node_modules |
| `nested-jars-depth` | `--nested-jars-depth` flag | Java nested JAR depth |
| `file` | `--file` flag | Dockerfile path |

---

## Data contract

Each returned `workflow.Data` item:

| Field | Value |
|---|---|
| `ContentType` | `"application/json"` |
| `Payload` | JSON-encoded `types.ScanResult` |
| `MetaData["Content-Location"]` | Target image name |

This matches the contract defined by `github.com/snyk/container-cli` so
downstream consumers (test, monitor, SBOM) work without modification.
