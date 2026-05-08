package display_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/fatih/color"
	"github.com/snyk/snyk-docker-plugin/pkg/display"
	"github.com/snyk/snyk-docker-plugin/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	// Force ANSI codes on so golden-file comparisons match the fixtures.
	color.NoColor = false
}

// repoRoot returns the path to the repo root (../../.. relative to this file).
func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	// go/pkg/display/display_test.go → ../../..
	return filepath.Join(filepath.Dir(file), "..", "..", "..")
}

func fixtureDir() string {
	return filepath.Join(repoRoot(), "test", "fixtures", "display")
}

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join(fixtureDir(), "output", name)
	data, err := os.ReadFile(path)
	require.NoError(t, err, "reading fixture %s", name)
	return data
}

func loadJSON[T any](t *testing.T, name string) T {
	t.Helper()
	path := filepath.Join(fixtureDir(), name)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var v T
	require.NoError(t, json.Unmarshal(data, &v))
	return v
}

// --- Unit tests for individual helpers ---

func TestFormatRemediations_nil(t *testing.T) {
	result := display.FormatRemediations(types.TestResult{})
	assert.Equal(t, "", result)
}

func TestFormatRemediations_advice(t *testing.T) {
	res := types.TestResult{
		Docker: types.DockerTestInfo{
			BaseImageRemediation: &types.BaseImageRemediation{
				Code: "REMEDIATION_AVAILABLE",
				Advice: []types.BaseImageRemediationAdvice{
					{Message: "hello"},
					{Message: "world", Bold: true},
				},
			},
		},
	}
	out := display.FormatRemediations(res)
	assert.Contains(t, out, "hello")
	assert.Contains(t, out, "world")
}

func TestFormatRemediations_message_only(t *testing.T) {
	res := types.TestResult{
		Docker: types.DockerTestInfo{
			BaseImageRemediation: &types.BaseImageRemediation{
				Code:    "NO_DATA",
				Message: "No remediation data available",
			},
		},
	}
	out := display.FormatRemediations(res)
	assert.Equal(t, "No remediation data available", out)
}

func TestFormatRemediations_empty_advice(t *testing.T) {
	res := types.TestResult{
		Docker: types.DockerTestInfo{
			BaseImageRemediation: &types.BaseImageRemediation{
				Code: "NO_DATA",
			},
		},
	}
	out := display.FormatRemediations(res)
	assert.Equal(t, "", out)
}

// -- Display() smoke test (no issues) --

func TestDisplay_noIssues(t *testing.T) {
	scanResult := types.ScanResult{
		Target:   types.ContainerTarget{Image: "docker-image|example"},
		Identity: types.Identity{Type: "deb"},
	}
	testResult := types.TestResult{
		Org:    "my-org",
		Issues: []types.Issue{},
		IssuesData: map[string]types.IssueData{},
		DepGraphData: types.DepGraphData{
			SchemaVersion: "1.2.0",
			PkgManager:    types.PkgManager{Name: "deb"},
			Pkgs:          []types.Pkg{{ID: "root", Info: types.PkgInfo{Name: "root"}}},
			Graph: types.Graph{
				RootNodeID: "root-node",
				Nodes:      []types.Node{{NodeID: "root-node", PkgID: "root", Deps: []types.DepRef{}}},
			},
		},
	}
	out, err := display.Display(
		[]types.ScanResult{scanResult},
		[]types.TestResult{testResult},
		nil,
		types.Options{Path: "example"},
	)
	require.NoError(t, err)
	assert.Contains(t, out, "Organization:")
	assert.Contains(t, out, "no vulnerable paths found")
}
