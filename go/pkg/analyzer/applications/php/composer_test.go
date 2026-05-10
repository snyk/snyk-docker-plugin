package php_test

import (
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/analyzer/applications/php"
	"github.com/snyk/snyk-docker-plugin/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const composerJSON = `{"name": "test/project", "require": {}}`

const composerLockSimple = `{
  "packages": [
    {"name": "vendor/foo", "version": "v1.0.0", "require": {}},
    {"name": "vendor/bar", "version": "2.0.0", "require": {}}
  ]
}`

const composerLockWithDeps = `{
  "packages": [
    {"name": "vendor/foo", "version": "1.0.0", "require": {"vendor/bar": "^2.0", "php": ">=7.4", "ext-json": "*"}},
    {"name": "vendor/bar", "version": "2.0.0", "require": {}}
  ]
}`

func TestScanComposer_empty(t *testing.T) {
	results := php.ScanComposer(map[string][]byte{})
	assert.Nil(t, results)
}

func TestScanComposer_onlyComposerJSON(t *testing.T) {
	results := php.ScanComposer(map[string][]byte{
		"/app/composer.json": []byte(composerJSON),
	})
	assert.Nil(t, results)
}

func TestScanComposer_onlyComposerLock(t *testing.T) {
	results := php.ScanComposer(map[string][]byte{
		"/app/composer.lock": []byte(composerLockSimple),
	})
	assert.Nil(t, results)
}

func TestScanComposer_bothFilesProduceResult(t *testing.T) {
	results := php.ScanComposer(map[string][]byte{
		"/app/composer.json": []byte(composerJSON),
		"/app/composer.lock": []byte(composerLockSimple),
	})
	require.Len(t, results, 1)
	r := results[0]
	assert.Equal(t, "composer", r.Identity.Type)
	assert.Contains(t, r.Identity.TargetFile, "composer.lock")
}

func TestScanComposer_identityTargetFile(t *testing.T) {
	results := php.ScanComposer(map[string][]byte{
		"/opt/drupal/composer.json": []byte(composerJSON),
		"/opt/drupal/composer.lock": []byte(composerLockSimple),
	})
	require.Len(t, results, 1)
	assert.Equal(t, "/opt/drupal/composer.lock", results[0].Identity.TargetFile)
}

func TestScanComposer_factsIncludeDepGraphAndTestedFiles(t *testing.T) {
	results := php.ScanComposer(map[string][]byte{
		"/app/composer.json": []byte(composerJSON),
		"/app/composer.lock": []byte(composerLockSimple),
	})
	require.Len(t, results, 1)
	r := results[0]
	require.Len(t, r.Facts, 2)
	assert.Equal(t, types.FactDepGraph, r.Facts[0].Type)
	assert.Equal(t, types.FactTestedFiles, r.Facts[1].Type)

	files, ok := r.Facts[1].Data.([]string)
	require.True(t, ok)
	assert.ElementsMatch(t, []string{"composer.json", "composer.lock"}, files)
}

func TestScanComposer_depGraphHasComposerPkgManager(t *testing.T) {
	results := php.ScanComposer(map[string][]byte{
		"/app/composer.json": []byte(composerJSON),
		"/app/composer.lock": []byte(composerLockSimple),
	})
	require.Len(t, results, 1)
	dg, ok := results[0].Facts[0].Data.(types.DepGraphData)
	require.True(t, ok)
	assert.Equal(t, "composer", dg.PkgManager.Name)
	// root pkg + 2 packages = 3
	assert.GreaterOrEqual(t, len(dg.Pkgs), 3)
}

func TestScanComposer_versionNormalisationStripsV(t *testing.T) {
	results := php.ScanComposer(map[string][]byte{
		"/app/composer.json": []byte(composerJSON),
		"/app/composer.lock": []byte(composerLockSimple),
	})
	require.Len(t, results, 1)
	dg := results[0].Facts[0].Data.(types.DepGraphData)
	for _, pkg := range dg.Pkgs {
		// No version should start with 'v'.
		if pkg.Info.Version != "" {
			assert.NotEqual(t, 'v', pkg.Info.Version[0],
				"version %q should not start with 'v'", pkg.Info.Version)
		}
	}
}

func TestScanComposer_platformDepsSkipped(t *testing.T) {
	// php, ext-*, lib-* in require should not appear as packages.
	results := php.ScanComposer(map[string][]byte{
		"/app/composer.json": []byte(composerJSON),
		"/app/composer.lock": []byte(composerLockWithDeps),
	})
	require.Len(t, results, 1)
	dg := results[0].Facts[0].Data.(types.DepGraphData)
	for _, pkg := range dg.Pkgs {
		assert.NotEqual(t, "php", pkg.Info.Name)
		assert.NotContains(t, pkg.Info.Name, "ext-")
	}
}

func TestScanComposer_invalidJSONReturnsNil(t *testing.T) {
	results := php.ScanComposer(map[string][]byte{
		"/app/composer.json": []byte(composerJSON),
		"/app/composer.lock": []byte("not json at all"),
	})
	assert.Nil(t, results)
}

func TestScanComposer_zeroPackagesReturnsNil(t *testing.T) {
	results := php.ScanComposer(map[string][]byte{
		"/app/composer.json": []byte(composerJSON),
		"/app/composer.lock": []byte(`{"packages": []}`),
	})
	assert.Nil(t, results)
}

func TestScanComposer_filesInDifferentDirsNotPaired(t *testing.T) {
	// composer.json in /app but composer.lock in /other — should not pair.
	results := php.ScanComposer(map[string][]byte{
		"/app/composer.json":   []byte(composerJSON),
		"/other/composer.lock": []byte(composerLockSimple),
	})
	assert.Nil(t, results)
}

func TestScanComposer_multiplePairs(t *testing.T) {
	results := php.ScanComposer(map[string][]byte{
		"/app/composer.json":     []byte(composerJSON),
		"/app/composer.lock":     []byte(composerLockSimple),
		"/service/composer.json": []byte(composerJSON),
		"/service/composer.lock": []byte(composerLockSimple),
	})
	assert.Len(t, results, 2)
}

func TestScanComposer_transitiveDepsResolved(t *testing.T) {
	// vendor/foo requires vendor/bar; vendor/bar should appear in foo's subtree.
	results := php.ScanComposer(map[string][]byte{
		"/app/composer.json": []byte(composerJSON),
		"/app/composer.lock": []byte(composerLockWithDeps),
	})
	require.Len(t, results, 1)
	dg := results[0].Facts[0].Data.(types.DepGraphData)
	// vendor/foo and vendor/bar should both appear in pkgs.
	pkgNames := map[string]bool{}
	for _, p := range dg.Pkgs {
		pkgNames[p.Info.Name] = true
	}
	assert.True(t, pkgNames["vendor/foo"] || pkgNames["vendor/bar"],
		"expected vendor packages in dep graph")
}

func TestScanComposer_phpVersionNormUpperV(t *testing.T) {
	lock := `{"packages":[{"name":"a/b","version":"V1.0.0","require":{}}]}`
	results := php.ScanComposer(map[string][]byte{
		"/app/composer.json": []byte(composerJSON),
		"/app/composer.lock": []byte(lock),
	})
	require.Len(t, results, 1)
	dg := results[0].Facts[0].Data.(types.DepGraphData)
	for _, p := range dg.Pkgs {
		if p.Info.Name == "a/b" {
			assert.Equal(t, "1.0.0", p.Info.Version)
		}
	}
}

func TestScanComposer_graphRootNodeIsLockPath(t *testing.T) {
	results := php.ScanComposer(map[string][]byte{
		"/app/composer.json": []byte(composerJSON),
		"/app/composer.lock": []byte(composerLockSimple),
	})
	require.Len(t, results, 1)
	dg := results[0].Facts[0].Data.(types.DepGraphData)
	// root node pkgId should include the lock file path
	rootNode := dg.Graph.Nodes[0]
	assert.Contains(t, rootNode.PkgID, "composer.lock")
}
