// Package containertest registers the native Go "container test" workflow
// with the Snyk CLI's go-application-framework engine.
//
// The workflow:
//   1. Invokes the "container depgraph" workflow (registered by
//      github.com/snyk/snyk-docker-plugin/extension-adapter) to obtain
//      one or more Snyk dependency graphs plus image facts.
//   2. For each dependency graph, calls the Snyk Test API to evaluate
//      the graph against the vulnerability database.
//   3. Emits the per-image test results as workflow.Data items so the
//      gaf output workflow can render them.
//
// Wiring in cliv2:
//
//	import containertest "github.com/snyk/snyk-docker-plugin/cli-extension-container"
//	...
//	engine.AddExtensionInitializer(containertest.Init)
//
// Ordering matters: the depgraph workflow must be registered (via the
// extension-adapter package) before this workflow's entrypoint runs.
package containertest

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

// WorkflowName is the cobra command path: `snyk container test`.
const WorkflowName = "container test"

const (
	// DepGraphWorkflowName is the workflow registered by the extension-adapter.
	DepGraphWorkflowName = "container depgraph"

	contentTypeJSON      = "application/json"
	contentTypeTestJSON  = "application/json+vuln"
	contentTypeSummary   = "application/json; schema=local-unified-summary"
	headerContentLocation = "Content-Location"

	dataTypeTestResult = "container-test-result"
	dataTypeSummary    = "container-test-summary"
)

var (
	workflowID = workflow.NewWorkflowIdentifier(WorkflowName)
	typeID     = workflow.NewTypeIdentifier(workflowID, dataTypeTestResult)
	summaryID  = workflow.NewTypeIdentifier(workflowID, dataTypeSummary)
)

// Init registers the "container test" workflow with the engine.
// Its signature satisfies workflow.ExtensionInit so it can be passed
// directly to engine.AddExtensionInitializer.
func Init(e workflow.Engine) error {
	_, err := e.Register(
		workflowID,
		workflow.ConfigurationOptionsFromFlagset(flags()),
		entrypoint,
	)
	if err != nil {
		return fmt.Errorf("registering %q workflow: %w", WorkflowName, err)
	}
	return nil
}
