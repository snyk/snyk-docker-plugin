package containertest

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-docker-plugin/pkg/types"
)

// entrypoint is the workflow.Callback invoked by the engine for every
// "container test" invocation. It invokes the "container depgraph"
// workflow to obtain dep graphs + image facts, then sends each dep graph
// to the Snyk Test API and aggregates the results.
func entrypoint(ictx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	ctx := contextFrom(ictx)
	logger := ictx.GetEnhancedLogger()
	cfg := ictx.GetConfiguration()

	orgID := cfg.GetString(configuration.ORGANIZATION)
	if orgID == "" {
		return nil, fmt.Errorf("no organization configured — set SNYK_CFG_ORG or pass --org")
	}

	logger.Info().Str("workflow", WorkflowName).Msg("starting container test workflow")

	depGraphData, err := ictx.GetEngine().InvokeWithConfig(
		workflow.NewWorkflowIdentifier(DepGraphWorkflowName),
		cfg.Clone(),
	)
	if err != nil {
		return nil, fmt.Errorf("invoking %q workflow: %w", DepGraphWorkflowName, err)
	}

	testClient, err := newTestClient(ictx)
	if err != nil {
		return nil, err
	}

	imageResults := make([]imageTestResult, 0, len(depGraphData))
	for _, d := range depGraphData {
		if d.GetPayload() == nil {
			continue
		}
		raw, ok := d.GetPayload().([]byte)
		if !ok {
			return nil, fmt.Errorf("unexpected depgraph payload type %T (want []byte)", d.GetPayload())
		}

		var sr types.ScanResult
		if err := json.Unmarshal(raw, &sr); err != nil {
			return nil, fmt.Errorf("decoding ScanResult JSON from depgraph workflow: %w", err)
		}

		res, runErr := runSingleTest(ctx, ictx, testClient, orgID, sr)
		if runErr != nil {
			return nil, fmt.Errorf("testing image %q: %w", sr.Target.Image, runErr)
		}
		imageResults = append(imageResults, res)
	}

	return renderResults(cfg, imageResults)
}

// imageTestResult captures the bits we need to render output for one
// (image, ecosystem) pair.
type imageTestResult struct {
	Image          string
	TargetFile     string
	PackageManager string
	Result         testapi.TestResult
	Findings       []testapi.FindingData
}

func runSingleTest(
	ctx context.Context,
	ictx workflow.InvocationContext,
	testClient testapi.TestClient,
	orgID string,
	sr types.ScanResult,
) (imageTestResult, error) {
	logger := ictx.GetEnhancedLogger()

	depGraphPayload, err := extractDepGraph(sr)
	if err != nil {
		return imageTestResult{}, err
	}

	subject, err := buildTestSubject(depGraphPayload, sr)
	if err != nil {
		return imageTestResult{}, err
	}

	startParams := testapi.NewStartTestParamsFromSubject(orgID, &subject, &testapi.TestConfiguration{})

	logger.Debug().Str("image", sr.Target.Image).Msg("starting Snyk Test API call")
	handle, err := testClient.StartTest(ctx, startParams)
	if err != nil {
		return imageTestResult{}, fmt.Errorf("StartTest: %w", err)
	}
	if waitErr := handle.Wait(ctx); waitErr != nil {
		return imageTestResult{}, fmt.Errorf("waiting for test completion: %w", waitErr)
	}

	result := handle.Result()
	if result == nil {
		return imageTestResult{}, fmt.Errorf("test completed but no result was returned")
	}
	if result.GetExecutionState() == testapi.TestExecutionStatesErrored {
		if apiErrs := result.GetErrors(); apiErrs != nil && len(*apiErrs) > 0 {
			return imageTestResult{}, fmt.Errorf("test errored: %s", (*apiErrs)[0].Detail)
		}
		return imageTestResult{}, fmt.Errorf("test errored: unknown reason")
	}

	findings, complete, err := result.Findings(ctx)
	if err != nil {
		return imageTestResult{}, fmt.Errorf("fetching findings: %w", err)
	}
	if !complete {
		logger.Warn().Int("count", len(findings)).Msg("findings retrieval incomplete; rendering partial result")
	}

	return imageTestResult{
		Image:          sr.Target.Image,
		TargetFile:     sr.Identity.TargetFile,
		PackageManager: sr.Identity.Type,
		Result:         result,
		Findings:       findings,
	}, nil
}

// extractDepGraph returns the depGraph fact payload as a testapi DepGraph
// request body. It tolerates the fact data being either a typed value
// (already a *DepGraph) or a raw map decoded from JSON.
func extractDepGraph(sr types.ScanResult) (testapi.IoSnykApiV1testdepgraphRequestDepGraph, error) {
	var out testapi.IoSnykApiV1testdepgraphRequestDepGraph
	for _, f := range sr.Facts {
		if f.Type != types.FactDepGraph {
			continue
		}
		raw, err := json.Marshal(f.Data)
		if err != nil {
			return out, fmt.Errorf("marshaling depGraph fact data: %w", err)
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			return out, fmt.Errorf("decoding depGraph into testapi shape: %w", err)
		}
		return out, nil
	}
	return out, fmt.Errorf("no depGraph fact found on scan result for image %q", sr.Target.Image)
}

// buildTestSubject wraps a DepGraph payload in a TestSubjectCreate, attaching
// the image name as the locator path.
func buildTestSubject(
	dg testapi.IoSnykApiV1testdepgraphRequestDepGraph,
	sr types.ScanResult,
) (testapi.TestSubjectCreate, error) {
	dgSubject := testapi.DepGraphSubjectCreate{
		Type:     testapi.DepGraph,
		DepGraph: dg,
		Locator: testapi.LocalPathLocator{
			Paths: []string{sr.Target.Image},
			Type:  testapi.LocalPath,
		},
	}

	var subject testapi.TestSubjectCreate
	if err := subject.FromDepGraphSubjectCreate(dgSubject); err != nil {
		return subject, fmt.Errorf("building TestSubjectCreate: %w", err)
	}
	return subject, nil
}

// newTestClient constructs a testapi.TestClient using the gaf-provided
// HTTP client and the configured Snyk API URL.
func newTestClient(ictx workflow.InvocationContext) (testapi.TestClient, error) {
	cfg := ictx.GetConfiguration()
	httpClient := ictx.GetNetworkAccess().GetHttpClient()
	apiURL := cfg.GetString(configuration.API_URL)

	client, err := testapi.NewTestClient(
		apiURL,
		testapi.WithCustomHTTPClient(httpClient),
	)
	if err != nil {
		return nil, fmt.Errorf("creating Snyk Test API client: %w", err)
	}
	return client, nil
}

// contextFrom returns the InvocationContext's context if it exposes one,
// otherwise falls back to context.Background. The interface check keeps the
// adapter compatible with older gaf versions that don't expose Context().
func contextFrom(ictx workflow.InvocationContext) context.Context {
	if c, ok := any(ictx).(interface{ Context() context.Context }); ok {
		if ctx := c.Context(); ctx != nil {
			return ctx
		}
	}
	return context.Background()
}
