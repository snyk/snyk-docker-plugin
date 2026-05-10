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

// --- Unit tests for chalk helpers and edge cases ---

func TestDisplay_SeverityColors(t *testing.T) {
	// Exercise low/medium/high severity code paths.
	for _, severity := range []string{"low", "medium", "high", "critical"} {
		tr := types.TestResult{
			Org: "org",
			Issues: []types.Issue{{PkgName: "foo", IssueID: "CVE-X"}},
			IssuesData: map[string]types.IssueData{
				"CVE-X": {ID: "CVE-X", Severity: severity, Title: "t", From: [][]string{{"foo@1"}}},
			},
			DepGraphData: types.DepGraphData{
				SchemaVersion: "1.2.0",
				PkgManager:    types.PkgManager{Name: "deb"},
				Pkgs:          []types.Pkg{{ID: "r", Info: types.PkgInfo{Name: "r"}}},
				Graph:         types.Graph{RootNodeID: "root-node", Nodes: []types.Node{{NodeID: "root-node", PkgID: "r", Deps: []types.DepRef{}}}},
			},
		}
		out, err := display.Display(
			[]types.ScanResult{{Target: types.ContainerTarget{Image: "img"}, Identity: types.Identity{Type: "deb"}}},
			[]types.TestResult{tr}, nil, types.Options{Config: &types.OptionsConfig{DisableSuggestions: "true"}},
		)
		require.NoError(t, err)
		assert.Contains(t, out, "foo", "severity=%s", severity)
	}
}

func TestDisplay_RemediationColors(t *testing.T) {
	// Exercise advice colour branches: red, yellow, blue, white, plain.
	advices := []types.BaseImageRemediationAdvice{
		{Message: "red msg", Color: "red"},
		{Message: "yellow msg", Color: "yellow"},
		{Message: "blue msg", Color: "blue"},
		{Message: "white msg", Color: "white"},
		{Message: "bold msg", Bold: true},
		{Message: "plain msg"},
	}
	tr := types.TestResult{
		Org: "org",
		Issues: []types.Issue{},
		IssuesData: map[string]types.IssueData{},
		Docker: types.DockerTestInfo{
			BaseImageRemediation: &types.BaseImageRemediation{Advice: advices},
		},
		DepGraphData: types.DepGraphData{
			SchemaVersion: "1.2.0",
			PkgManager:    types.PkgManager{Name: "deb"},
			Pkgs:          []types.Pkg{{ID: "r", Info: types.PkgInfo{Name: "r"}}},
			Graph:         types.Graph{RootNodeID: "rn", Nodes: []types.Node{{NodeID: "rn", PkgID: "r", Deps: []types.DepRef{}}}},
		},
	}
	out, err := display.Display(
		[]types.ScanResult{{Target: types.ContainerTarget{Image: "img"}, Identity: types.Identity{Type: "deb"}}},
		[]types.TestResult{tr}, nil, types.Options{Config: &types.OptionsConfig{DisableSuggestions: "true"}},
	)
	require.NoError(t, err)
	for _, adv := range advices {
		assert.Contains(t, out, adv.Message)
	}
}

func TestFormatRemediations_nil(t *testing.T) {
	result := display.FormatRemediations(types.TestResult{})
	assert.Equal(t, "", result)
}

func TestDisplay_emptyIssues_noOrphanSummary(t *testing.T) {
	// Exercises the capitalize("") empty-string guard via zero-issues summary path.
	// Also exercises padding() when the header fits exactly.
	tr := types.TestResult{
		Org:        "",
		Issues:     []types.Issue{},
		IssuesData: map[string]types.IssueData{},
		DepGraphData: types.DepGraphData{
			SchemaVersion: "1.2.0",
			PkgManager:    types.PkgManager{Name: "deb"},
			Pkgs:          []types.Pkg{{ID: "r", Info: types.PkgInfo{Name: "r"}}},
			Graph:         types.Graph{RootNodeID: "rn", Nodes: []types.Node{{NodeID: "rn", PkgID: "r", Deps: []types.DepRef{}}}},
		},
	}
	// Package manager label is 19 chars — exactly sectionPaddingWidth, exercises padding no-op branch.
	sr := types.ScanResult{
		Target:   types.ContainerTarget{Image: "img"},
		Identity: types.Identity{Type: "Package manager:"},
	}
	out, err := display.Display(
		[]types.ScanResult{sr},
		[]types.TestResult{tr},
		nil,
		types.Options{IsDockerUser: true},
	)
	require.NoError(t, err)
	assert.Contains(t, out, "no vulnerable paths found")
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

// --- Golden-file tests (mirror display.spec.ts exactly) ---

func loadDisplayFixtures(t *testing.T) (debDG types.DepGraphData, rpmScan types.ScanResult) {
	t.Helper()
	debDG = loadJSON[types.DepGraphData](t, "deb-dep-graph.json")
	rpmRaw, err := os.ReadFile(filepath.Join(fixtureDir(), "scan-results", "rpm.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(rpmRaw, &rpmScan))
	return
}

func TestDisplay_Golden_noIssues(t *testing.T) {
	want := string(loadFixture(t, "no-issues.txt"))
	debDG, rpmScan := loadDisplayFixtures(t)
	tr := types.TestResult{
		Org:        "org-test",
		Issues:     []types.Issue{},
		IssuesData: map[string]types.IssueData{},
		DepGraphData: debDG,
	}
	got, err := display.Display(
		[]types.ScanResult{rpmScan},
		[]types.TestResult{tr},
		nil,
		types.Options{Path: "snyk/kubernetes-monitor", Config: &types.OptionsConfig{}},
	)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestDisplay_Golden_noIssuesWithFile(t *testing.T) {
	want := string(loadFixture(t, "no-issues-with-file-options.txt"))
	debDG, rpmScan := loadDisplayFixtures(t)
	tr := types.TestResult{
		Org:        "org-test",
		Issues:     []types.Issue{},
		IssuesData: map[string]types.IssueData{},
		DepGraphData: debDG,
	}
	got, err := display.Display(
		[]types.ScanResult{rpmScan},
		[]types.TestResult{tr},
		nil,
		types.Options{File: "Dockerfile", Config: &types.OptionsConfig{}},
	)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestDisplay_Golden_aFewIssues(t *testing.T) {
	want := string(loadFixture(t, "a-few-issues.txt"))
	debDG, rpmScan := loadDisplayFixtures(t)
	trPath := filepath.Join(fixtureDir(), "test-results", "with-few-issues.txt")
	trRaw, err := os.ReadFile(trPath)
	require.NoError(t, err)
	var tr types.TestResult
	require.NoError(t, json.Unmarshal(trRaw, &tr))
	tr.DepGraphData = debDG
	got, err := display.Display(
		[]types.ScanResult{rpmScan},
		[]types.TestResult{tr},
		nil,
		types.Options{Path: "ubuntu", Config: &types.OptionsConfig{DisableSuggestions: "true"}},
	)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestDisplay_Golden_onlyBaseImageRemediations(t *testing.T) {
	want := string(loadFixture(t, "only-base-image-remediations.txt"))
	debDG, rpmScan := loadDisplayFixtures(t)
	trPath := filepath.Join(fixtureDir(), "test-results", "only-base-image-remediation.txt")
	trRaw, err := os.ReadFile(trPath)
	require.NoError(t, err)
	var tr types.TestResult
	require.NoError(t, json.Unmarshal(trRaw, &tr))
	tr.DepGraphData = debDG
	got, err := display.Display(
		[]types.ScanResult{rpmScan},
		[]types.TestResult{tr},
		nil,
		types.Options{Path: "ubuntu", IsDockerUser: true, Config: &types.OptionsConfig{DisableSuggestions: "true"}},
	)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

// -- Display() smoke test (no issues, inline data) --

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
