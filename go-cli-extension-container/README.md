# cli-extension-container

A `go-application-framework` extension that registers the native
`snyk container test` workflow.

It's a separate Go module
(`github.com/snyk/snyk-docker-plugin/cli-extension-container`) so that the
main `snyk-docker-plugin` module does not need to carry the
go-application-framework dependency tree.

## What it does

1. Invokes the `container depgraph` workflow (registered by the sibling
   `go-extension-adapter` module) to obtain Snyk dependency graphs plus
   image facts via the native Go plugin.
2. Sends each dependency graph to the Snyk Test API.
3. Emits per-image findings + summary `workflow.Data` items that the
   gaf output workflow renders to JSON, human text, or SARIF.

## Wiring into cliv2

In `cliv2/go.mod`:

```
require github.com/snyk/snyk-docker-plugin/cli-extension-container v0.0.0
replace github.com/snyk/snyk-docker-plugin/cli-extension-container => ../../snyk-docker-plugin/go-cli-extension-container
```

In `cliv2/cmd/cliv2/main.go`:

```go
import containertest "github.com/snyk/snyk-docker-plugin/cli-extension-container"
...
engine.AddExtensionInitializer(containertest.Init)
```

Place `containertest.Init` **after** `dockerplugin.Init` — the depgraph
workflow it calls into must already be registered when this entrypoint
runs.

## Status

Experimental. See `plans/CONTAINER_TEST_GO_WORKFLOW.md` for the full
design and open questions.
