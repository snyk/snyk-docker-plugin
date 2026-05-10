package response_test

import (
	"strings"
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/response"
	"github.com/snyk/snyk-docker-plugin/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// ComputeScanPayloadMetrics
// ---------------------------------------------------------------------------

func TestComputeScanPayloadMetrics_empty(t *testing.T) {
	m := response.ComputeScanPayloadMetrics(nil)
	assert.Equal(t, 0, m.ScanResultCount)
	assert.Equal(t, 0, m.ApplicationScanResultCount)
	assert.Empty(t, m.ScanResultPayloadBytes)
	assert.Greater(t, m.TotalScanResultsPayloadBytes, 0) // JSON of empty slice is "[]"
}

func TestComputeScanPayloadMetrics_oneResult(t *testing.T) {
	srs := []types.ScanResult{
		{Target: types.ContainerTarget{Image: "alpine:3"}},
	}
	m := response.ComputeScanPayloadMetrics(srs)
	assert.Equal(t, 1, m.ScanResultCount)
	assert.Equal(t, 0, m.ApplicationScanResultCount) // max(0, 1-1)
	require.Len(t, m.ScanResultPayloadBytes, 1)
	assert.Greater(t, m.ScanResultPayloadBytes[0], 0)
	assert.Greater(t, m.TotalScanResultsPayloadBytes, 0)
}

func TestComputeScanPayloadMetrics_multipleResults(t *testing.T) {
	srs := []types.ScanResult{
		{Target: types.ContainerTarget{Image: "alpine:3"}},
		{Target: types.ContainerTarget{Image: "alpine:3"}},
		{Target: types.ContainerTarget{Image: "alpine:3"}},
	}
	m := response.ComputeScanPayloadMetrics(srs)
	assert.Equal(t, 3, m.ScanResultCount)
	assert.Equal(t, 2, m.ApplicationScanResultCount)
	assert.Len(t, m.ScanResultPayloadBytes, 3)
}

// ---------------------------------------------------------------------------
// TruncateAdditionalFacts — no truncation needed
// ---------------------------------------------------------------------------

func TestTruncate_noopOnSmallFacts(t *testing.T) {
	facts := []types.Fact{
		{Type: types.FactImageID, Data: "sha256:abc"},
		{Type: types.FactPlatform, Data: "linux/amd64"},
	}
	out := response.TruncateAdditionalFacts(facts)
	// Should be returned unchanged (no pluginWarnings added).
	assert.Len(t, out, 2)
	for _, f := range out {
		assert.NotEqual(t, types.FactPluginWarnings, f.Type)
	}
}

func TestTruncate_depGraphPassthrough(t *testing.T) {
	// depGraph facts must pass through untouched.
	dg := types.DepGraphData{SchemaVersion: "1.2.0"}
	facts := []types.Fact{
		{Type: types.FactDepGraph, Data: dg},
	}
	out := response.TruncateAdditionalFacts(facts)
	assert.Len(t, out, 1)
	assert.Equal(t, types.FactDepGraph, out[0].Type)
}

// ---------------------------------------------------------------------------
// TruncateAdditionalFacts — string truncation
// ---------------------------------------------------------------------------

func TestTruncate_user_overLimit(t *testing.T) {
	// containerConfig.data.user limit = 1024
	bigUser := strings.Repeat("u", 2000)
	facts := []types.Fact{
		{
			Type: types.FactContainerConfig,
			Data: map[string]interface{}{"user": bigUser},
		},
	}
	out := response.TruncateAdditionalFacts(facts)
	// A pluginWarnings fact should be appended.
	require.Len(t, out, 2)
	assert.Equal(t, types.FactPluginWarnings, out[1].Type)
	// The containerConfig data should have the user truncated to 1024 chars.
	cc, ok := out[0].Data.(map[string]interface{})
	require.True(t, ok)
	user, ok := cc["user"].(string)
	require.True(t, ok)
	assert.Equal(t, 1024, len(user))
}

func TestTruncate_user_atLimit_noWarning(t *testing.T) {
	// Exactly at limit — no truncation.
	exactUser := strings.Repeat("u", 1024)
	facts := []types.Fact{
		{
			Type: types.FactContainerConfig,
			Data: map[string]interface{}{"user": exactUser},
		},
	}
	out := response.TruncateAdditionalFacts(facts)
	assert.Len(t, out, 1, "no pluginWarnings expected when exactly at limit")
}

// ---------------------------------------------------------------------------
// TruncateAdditionalFacts — array truncation
// ---------------------------------------------------------------------------

func TestTruncate_history_overLimit(t *testing.T) {
	// history.data limit = 1000
	history := make([]interface{}, 1500)
	for i := range history {
		history[i] = map[string]interface{}{"createdBy": "RUN echo hello"}
	}
	facts := []types.Fact{
		{Type: types.FactHistory, Data: history},
	}
	out := response.TruncateAdditionalFacts(facts)
	require.Len(t, out, 2) // original + pluginWarnings
	histOut, ok := out[0].Data.([]interface{})
	require.True(t, ok)
	assert.Len(t, histOut, 1000)
}

func TestTruncate_env_perElementLimit(t *testing.T) {
	// containerConfig.data.env[*] limit = 1024
	bigEnv := strings.Repeat("E", 2000)
	facts := []types.Fact{
		{
			Type: types.FactContainerConfig,
			Data: map[string]interface{}{
				"env": []interface{}{bigEnv, "SHORT=val"},
			},
		},
	}
	out := response.TruncateAdditionalFacts(facts)
	require.Len(t, out, 2) // + pluginWarnings
	cc := out[0].Data.(map[string]interface{})
	envOut := cc["env"].([]interface{})
	assert.Equal(t, 1024, len(envOut[0].(string)))
	assert.Equal(t, "SHORT=val", envOut[1].(string))
}

// ---------------------------------------------------------------------------
// TruncateAdditionalFacts — existing pluginWarnings is updated
// ---------------------------------------------------------------------------

func TestTruncate_existingWarningsUpdated(t *testing.T) {
	bigUser := strings.Repeat("u", 2000)
	facts := []types.Fact{
		{
			Type: types.FactContainerConfig,
			Data: map[string]interface{}{"user": bigUser},
		},
		{
			Type: types.FactPluginWarnings,
			Data: map[string]interface{}{"parameterChecks": []string{"some-warning"}},
		},
	}
	out := response.TruncateAdditionalFacts(facts)
	// Should NOT add a new pluginWarnings — should augment the existing one.
	warningCount := 0
	for _, f := range out {
		if f.Type == types.FactPluginWarnings {
			warningCount++
		}
	}
	assert.Equal(t, 1, warningCount)
}

// ---------------------------------------------------------------------------
// Assemble
// ---------------------------------------------------------------------------

func TestAssemble_returnsAnalytics(t *testing.T) {
	srs := []types.ScanResult{
		{Target: types.ContainerTarget{Image: "alpine:3"}},
	}
	resp := response.Assemble(srs)
	require.NotNil(t, resp)
	require.Len(t, resp.Analytics, 1)
	assert.Equal(t, "containerScanPayloadMetrics", resp.Analytics[0].Name)
}

func TestAssemble_truncatesAndAddsAnalytics(t *testing.T) {
	bigUser := strings.Repeat("u", 2000)
	srs := []types.ScanResult{
		{
			Target: types.ContainerTarget{Image: "alpine:3"},
			Facts: []types.Fact{
				{Type: types.FactContainerConfig, Data: map[string]interface{}{"user": bigUser}},
			},
		},
	}
	resp := response.Assemble(srs)
	// Truncation must have happened: pluginWarnings appended to first result.
	hasWarnings := false
	for _, f := range resp.ScanResults[0].Facts {
		if f.Type == types.FactPluginWarnings {
			hasWarnings = true
		}
	}
	assert.True(t, hasWarnings, "expected pluginWarnings after truncation")
	// Analytics must be present.
	assert.Len(t, resp.Analytics, 1)
}

func TestAssemble_empty(t *testing.T) {
	resp := response.Assemble(nil)
	require.NotNil(t, resp)
	assert.Empty(t, resp.ScanResults)
	assert.Len(t, resp.Analytics, 1)
}

// ---------------------------------------------------------------------------
// BuildResponse (passthrough)
// ---------------------------------------------------------------------------

func TestBuildResponse_basic(t *testing.T) {
	facts := []types.Fact{{Type: types.FactImageID, Data: "sha256:abc"}}
	target := types.ContainerTarget{Image: "alpine:3"}
	id := types.Identity{Type: "apk"}
	resp := response.BuildResponse(facts, target, id)
	require.NotNil(t, resp)
	require.Len(t, resp.ScanResults, 1)
	assert.Equal(t, target, resp.ScanResults[0].Target)
	assert.Equal(t, id, resp.ScanResults[0].Identity)
	assert.Equal(t, facts, resp.ScanResults[0].Facts)
}
