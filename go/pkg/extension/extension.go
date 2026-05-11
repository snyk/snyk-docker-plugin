// Package extension provides a minimal interface for integrating
// snyk-docker-plugin as a CLI workflow extension.
//
// # Architecture
//
// The main snyk-docker-plugin Go module intentionally does not import
// github.com/snyk/go-application-framework, keeping the dependency tree
// small and cross-compilation straightforward.
//
// Integration with the Snyk CLI v2 (go-application-framework) is handled
// by the companion module at go-extension-adapter/, which imports both this
// module and the framework, and exposes Init(workflow.Engine) error.
//
// See go-extension-adapter/extension.go for the wiring code and
// go-extension-adapter/README.md for step-by-step cliv2 integration.
package extension

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/snyk/snyk-docker-plugin/pkg/scan"
	"github.com/snyk/snyk-docker-plugin/pkg/types"
)

// WorkflowName is the workflow identifier this plugin registers.
// It matches the name used by github.com/snyk/container-cli so this
// implementation is a drop-in replacement for the legacy shell-out.
const WorkflowName = "container depgraph"

// ScanFunc is the core scanning function exposed for testing and embedding.
// It accepts a JSON-encoded PluginOptions and returns a JSON-encoded PluginResponse.
func ScanJSON(ctx context.Context, optionsJSON []byte) ([]byte, error) {
	var opts types.PluginOptions
	if len(optionsJSON) > 0 {
		if err := json.Unmarshal(optionsJSON, &opts); err != nil {
			return nil, fmt.Errorf("decoding options: %w", err)
		}
	}

	resp, err := scan.Scan(ctx, opts)
	if err != nil {
		return nil, err
	}

	b, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("encoding response: %w", err)
	}
	return b, nil
}
