package python_test

import (
	"testing"

	python "github.com/snyk/snyk-docker-plugin/pkg/analyzer/applications/python"
	"github.com/snyk/snyk-docker-plugin/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const basicPyproject = `
[tool.poetry]
name = "myapp"
version = "0.1.0"
description = "A test app"

[tool.poetry.dependencies]
python = "^3.9"
requests = "^2.31.0"
`

const basicPoetryLock = `
[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."
optional = false
python-versions = ">=3.7"

[[package]]
name = "certifi"
version = "2024.2.2"
description = "Python package for SSL certs"
optional = false
python-versions = ">=3.6"
`

func TestScanPoetry_BasicCase(t *testing.T) {
	pathToContent := map[string][]byte{
		"/app/pyproject.toml": []byte(basicPyproject),
		"/app/poetry.lock":    []byte(basicPoetryLock),
	}
	results := python.ScanPoetry(pathToContent)
	require.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, "poetry", r.Identity.Type)
	assert.Equal(t, "/app/poetry.lock", r.Identity.TargetFile)

	require.Len(t, r.Facts, 2)
	assert.Equal(t, types.FactDepGraph, r.Facts[0].Type)
	assert.Equal(t, types.FactTestedFiles, r.Facts[1].Type)
}

func TestScanPoetry_DepGraphContents(t *testing.T) {
	pathToContent := map[string][]byte{
		"/app/pyproject.toml": []byte(basicPyproject),
		"/app/poetry.lock":    []byte(basicPoetryLock),
	}
	results := python.ScanPoetry(pathToContent)
	require.Len(t, results, 1)

	dgData, ok := results[0].Facts[0].Data.(types.DepGraphData)
	require.True(t, ok, "Facts[0].Data should be types.DepGraphData")

	assert.Equal(t, "poetry", dgData.PkgManager.Name)
	assert.Equal(t, "1.2.0", dgData.SchemaVersion)
	assert.Equal(t, "root-node", dgData.Graph.RootNodeID)

	// Root pkg + 2 deps = at least 3 packages.
	assert.GreaterOrEqual(t, len(dgData.Pkgs), 3)

	pkgNames := map[string]bool{}
	for _, p := range dgData.Pkgs {
		pkgNames[p.Info.Name] = true
	}
	assert.True(t, pkgNames["myapp"], "root package myapp should be present")
	assert.True(t, pkgNames["requests"], "requests should be present")
	assert.True(t, pkgNames["certifi"], "certifi should be present")
}

func TestScanPoetry_RootNameAndVersion(t *testing.T) {
	pathToContent := map[string][]byte{
		"/app/pyproject.toml": []byte(basicPyproject),
		"/app/poetry.lock":    []byte(basicPoetryLock),
	}
	results := python.ScanPoetry(pathToContent)
	require.Len(t, results, 1)

	dgData := results[0].Facts[0].Data.(types.DepGraphData)

	// Find the root package.
	var rootPkg *types.Pkg
	for i, p := range dgData.Pkgs {
		if p.Info.Name == "myapp" {
			rootPkg = &dgData.Pkgs[i]
			break
		}
	}
	require.NotNil(t, rootPkg, "root package myapp must be in Pkgs")
	assert.Equal(t, "0.1.0", rootPkg.Info.Version)
}

func TestScanPoetry_TestedFiles(t *testing.T) {
	pathToContent := map[string][]byte{
		"/app/pyproject.toml": []byte(basicPyproject),
		"/app/poetry.lock":    []byte(basicPoetryLock),
	}
	results := python.ScanPoetry(pathToContent)
	require.Len(t, results, 1)

	testedFiles, ok := results[0].Facts[1].Data.([]string)
	require.True(t, ok)
	assert.Contains(t, testedFiles, "pyproject.toml")
	assert.Contains(t, testedFiles, "poetry.lock")
}

func TestScanPoetry_EmptyMap(t *testing.T) {
	results := python.ScanPoetry(map[string][]byte{})
	assert.Nil(t, results)
}

func TestScanPoetry_MissingPoetryLock(t *testing.T) {
	pathToContent := map[string][]byte{
		"/app/pyproject.toml": []byte(basicPyproject),
	}
	results := python.ScanPoetry(pathToContent)
	assert.Nil(t, results)
}

func TestScanPoetry_MissingPyproject(t *testing.T) {
	pathToContent := map[string][]byte{
		"/app/poetry.lock": []byte(basicPoetryLock),
	}
	results := python.ScanPoetry(pathToContent)
	assert.Nil(t, results)
}

func TestScanPoetry_PyprojectWithoutToolPoetry(t *testing.T) {
	// pyproject.toml that has no [tool.poetry] section → skip.
	noPoetry := `
[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"
`
	pathToContent := map[string][]byte{
		"/app/pyproject.toml": []byte(noPoetry),
		"/app/poetry.lock":    []byte(basicPoetryLock),
	}
	results := python.ScanPoetry(pathToContent)
	assert.Nil(t, results)
}

func TestScanPoetry_EmptyLockfile(t *testing.T) {
	// poetry.lock with no [[package]] stanzas → no deps → nil result.
	emptyLock := `
[metadata]
content-hash = "abc123"
`
	pathToContent := map[string][]byte{
		"/app/pyproject.toml": []byte(basicPyproject),
		"/app/poetry.lock":    []byte(emptyLock),
	}
	results := python.ScanPoetry(pathToContent)
	assert.Nil(t, results)
}

func TestScanPoetry_MultipleProjects(t *testing.T) {
	pathToContent := map[string][]byte{
		"/app/pyproject.toml":     []byte(basicPyproject),
		"/app/poetry.lock":        []byte(basicPoetryLock),
		"/service/pyproject.toml": []byte("[tool.poetry]\nname = \"service\"\nversion = \"1.0.0\"\n"),
		"/service/poetry.lock":    []byte("[[package]]\nname = \"flask\"\nversion = \"3.0.0\"\n"),
	}
	results := python.ScanPoetry(pathToContent)
	assert.Len(t, results, 2)
}

func TestScanPoetry_SinglePackage(t *testing.T) {
	pathToContent := map[string][]byte{
		"/app/pyproject.toml": []byte("[tool.poetry]\nname = \"app\"\nversion = \"2.0\"\n"),
		"/app/poetry.lock":    []byte("[[package]]\nname = \"flask\"\nversion = \"3.0.0\"\n"),
	}
	results := python.ScanPoetry(pathToContent)
	require.Len(t, results, 1)
	dgData := results[0].Facts[0].Data.(types.DepGraphData)
	assert.Equal(t, "poetry", dgData.PkgManager.Name)
	// root + 1 dep = 2 packages
	assert.Equal(t, 2, len(dgData.Pkgs))
}
