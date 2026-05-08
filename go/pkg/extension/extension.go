// Package extension implements the Snyk CLI workflow extension entry point.
// It registers the container scan workflow with the go-application-framework engine.
//
// NOTE: The go-application-framework dependency is intentionally omitted from
// go.mod in this MVP to keep the build self-contained. Add it back when
// integrating with the Snyk CLI.
package extension

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/snyk/snyk-docker-plugin/pkg/scan"
	"github.com/snyk/snyk-docker-plugin/pkg/types"
)

// WorkflowID string for the container scan workflow.
const WorkflowID = "container/scan"

// Engine is a minimal interface mirroring workflow.Engine from
// go-application-framework. Kept here to avoid the large dependency tree
// in the MVP build.
type Engine interface {
	Register(id string, opts interface{}, callback Callback) error
	AddExtensionInitializer(init func(Engine) error)
}

// Callback is a workflow callback.
type Callback func(ctx context.Context, input []byte) ([]byte, error)

// Init registers the container scan extension with the workflow engine.
// This is the entry point for the Snyk CLI extension system.
func Init(e Engine) error {
	return e.Register(WorkflowID, nil, entrypoint)
}

func entrypoint(ctx context.Context, input []byte) ([]byte, error) {
	var opts types.PluginOptions
	if len(input) > 0 {
		if err := json.Unmarshal(input, &opts); err != nil {
			return nil, fmt.Errorf("unmarshaling input: %w", err)
		}
	}

	resp, err := scan.Scan(ctx, opts)
	if err != nil {
		return nil, err
	}

	b, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("marshaling response: %w", err)
	}
	return b, nil
}
