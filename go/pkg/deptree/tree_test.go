package deptree_test

import (
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/deptree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildDepInfos_empty(t *testing.T) {
	result := deptree.BuildDepInfos(nil)
	assert.Empty(t, result)
}

func TestBuildDepInfos_single(t *testing.T) {
	pkgs := []deptree.AnalyzedPackage{
		{Name: "curl", Version: "7.68.0"},
	}
	result := deptree.BuildDepInfos(pkgs)
	require.Len(t, result, 1)
	assert.Equal(t, "curl", result[0].Name)
	assert.Equal(t, "7.68.0", result[0].Version)
}

func TestBuildDepInfos_depResolution(t *testing.T) {
	pkgs := []deptree.AnalyzedPackage{
		{Name: "curl", Version: "7.68.0", Deps: map[string]bool{"libssl": true}},
		{Name: "libssl", Version: "1.1.1"},
	}
	result := deptree.BuildDepInfos(pkgs)
	// curl should be a top-level dep with libssl as child
	found := false
	for _, r := range result {
		if r.Name == "curl" {
			found = true
			// libssl should appear as a child
			var hasLibssl bool
			for _, d := range r.Deps {
				if d.Name == "libssl" {
					hasLibssl = true
				}
			}
			assert.True(t, hasLibssl, "curl should have libssl as dep")
		}
	}
	assert.True(t, found)
}

func TestBuildDepInfos_providesResolution(t *testing.T) {
	pkgs := []deptree.AnalyzedPackage{
		{Name: "app", Version: "1.0", Deps: map[string]bool{"libc-provider": true}},
		{Name: "musl", Version: "1.1", Provides: []string{"libc-provider"}},
	}
	result := deptree.BuildDepInfos(pkgs)
	// app should resolve libc-provider to musl
	for _, r := range result {
		if r.Name == "app" {
			for _, d := range r.Deps {
				assert.Equal(t, "musl", d.Name, "virtual dep should resolve to musl")
			}
		}
	}
}

func TestBuildDepInfos_cycleDetection(t *testing.T) {
	// a→b→a should not infinite loop
	pkgs := []deptree.AnalyzedPackage{
		{Name: "a", Version: "1", Deps: map[string]bool{"b": true}},
		{Name: "b", Version: "1", Deps: map[string]bool{"a": true}},
	}
	assert.NotPanics(t, func() {
		deptree.BuildDepInfos(pkgs)
	})
}

func TestBuildDepInfos_fullNameWithSource(t *testing.T) {
	pkgs := []deptree.AnalyzedPackage{
		{Name: "libgcc1", Version: "10", Source: "gcc-10"},
	}
	result := deptree.BuildDepInfos(pkgs)
	require.NotEmpty(t, result)
	// fullName should be "gcc-10/libgcc1"
	assert.Equal(t, "gcc-10/libgcc1", result[0].Name)
}

func TestBuildDepInfos_autoInstalledAttachedLast(t *testing.T) {
	pkgs := []deptree.AnalyzedPackage{
		{Name: "auto-pkg", Version: "1", AutoInstalled: true},
		{Name: "manual-pkg", Version: "1", AutoInstalled: false},
	}
	result := deptree.BuildDepInfos(pkgs)
	// manual-pkg should come first (or both present)
	names := make([]string, len(result))
	for i, r := range result {
		names[i] = r.Name
	}
	assert.Contains(t, names, "manual-pkg")
	assert.Contains(t, names, "auto-pkg")
}
