// Package extensionadapter wires github.com/snyk/snyk-docker-plugin into the
// Snyk CLI v2 (go-application-framework) as a native Go workflow extension.
//
// It is a separate Go module (github.com/snyk/snyk-docker-plugin/extension-adapter)
// so that the main snyk-docker-plugin module does not need to carry the
// go-application-framework dependency tree.
//
// # Usage in cliv2
//
// In cliv2/go.mod:
//
//	require github.com/snyk/snyk-docker-plugin/extension-adapter v0.0.0
//	replace github.com/snyk/snyk-docker-plugin => ../../snyk-docker-plugin/go
//	replace github.com/snyk/snyk-docker-plugin/extension-adapter => ../../snyk-docker-plugin/go-extension-adapter
//
// In cliv2/cmd/cliv2/main.go, inside initExtensions, add:
//
//	engine.AddExtensionInitializer(dockerplugin.Init)
//
// and at the top of the file:
//
//	dockerplugin "github.com/snyk/snyk-docker-plugin/extension-adapter"
//
// # Workflow contract
//
// Registers the "container depgraph" workflow identifier — the same one used by
// github.com/snyk/container-cli — so the rest of the container pipeline works
// unchanged. Each returned workflow.Data item carries:
//
//	ContentType:              "application/json"
//	Payload:                  JSON-encoded types.ScanResult
//	MetaData[Content-Location]: target image name
package extensionadapter

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-docker-plugin/pkg/scan"
	"github.com/snyk/snyk-docker-plugin/pkg/types"
)

const (
	// WorkflowName matches the workflow registered by container-cli's depgraph
	// workflow so this is a drop-in replacement.
	WorkflowName = "container depgraph"

	contentTypeJSON        = "application/json"
	headerContentLocation  = "Content-Location"
	dataTypeName           = "depgraph"
)

var (
	workflowID = workflow.NewWorkflowIdentifier(WorkflowName)
	typeID     = workflow.NewTypeIdentifier(workflowID, dataTypeName)
)

// Init registers the "container depgraph" workflow with the engine.
// Its signature satisfies workflow.ExtensionInit so it can be passed directly
// to engine.AddExtensionInitializer.
func Init(e workflow.Engine) error {
	_, err := e.Register(workflowID, workflow.ConfigurationOptionsFromFlagset(flags()), entrypoint)
	if err != nil {
		return fmt.Errorf("registering container depgraph workflow: %w", err)
	}
	return nil
}

// entrypoint is the workflow.Callback invoked by the engine for every
// "container depgraph" invocation.
func entrypoint(ictx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	opts := optsFromConfig(ictx.GetConfiguration())

	// Use the context from the invocation when the framework version provides one.
	ctx := context.Background()
	if c, ok := any(ictx).(interface{ Context() context.Context }); ok {
		ctx = c.Context()
	}

	resp, err := scan.Scan(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("snyk-docker-plugin: %w", err)
	}

	return resultsToData(resp.ScanResults)
}

// optsFromConfig reads PluginOptions from the engine configuration.
func optsFromConfig(cfg configuration.Configuration) types.PluginOptions {
	target := ""
	if dirs := cfg.GetStringSlice(configuration.INPUT_DIRECTORY); len(dirs) > 0 {
		target = dirs[0]
	}
	if target == "" {
		target = cfg.GetString(configuration.INPUT_DIRECTORY)
	}

	return types.PluginOptions{
		Path:               target,
		Platform:           cfg.GetString("platform"),
		Username:           cfg.GetString("username"),
		Password:           cfg.GetString("password"),
		ExcludeAppVulns:    cfg.GetBool("exclude-app-vulns"),
		ExcludeNodeModules: cfg.GetBool("exclude-node-modules"),
		NestedJarsDepth:    cfg.GetString("nested-jars-depth"),
	}
}

// resultsToData converts ScanResults into workflow.Data items.
func resultsToData(results []types.ScanResult) ([]workflow.Data, error) {
	out := make([]workflow.Data, 0, len(results))
	for _, sr := range results {
		b, err := json.Marshal(sr)
		if err != nil {
			return nil, fmt.Errorf("marshaling scan result: %w", err)
		}
		d := workflow.NewData(typeID, contentTypeJSON, b)
		d.SetMetaData(headerContentLocation, sr.Target.Image)
		out = append(out, d)
	}
	return out, nil
}
