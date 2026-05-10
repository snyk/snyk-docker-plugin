package node_test

import (
	"os"
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/analyzer/applications/node"
	"github.com/snyk/snyk-docker-plugin/pkg/depgraph"
	"github.com/snyk/snyk-docker-plugin/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err, "reading fixture %s", path)
	return data
}

func findResult(results []node.AppScanResult, identityType string) *node.AppScanResult {
	for i := range results {
		if results[i].Identity.Type == identityType {
			return &results[i]
		}
	}
	return nil
}

func getDepGraph(t *testing.T, result *node.AppScanResult) *types.DepGraphData {
	t.Helper()
	for _, f := range result.Facts {
		if f.Type == types.FactDepGraph {
			dg, ok := f.Data.(types.DepGraphData)
			require.True(t, ok, "FactDepGraph data is not DepGraphData")
			return &dg
		}
	}
	t.Fatal("no DepGraphFact found")
	return nil
}

// ---------------------------------------------------------------------------
// npm lockfile v2
// ---------------------------------------------------------------------------

func TestNpmLockV2_packageCount(t *testing.T) {
	if _, err := os.Stat("/tmp/npm-layer/app/package-lock.json"); os.IsNotExist(err) {
		t.Skip("npm fixture not available")
	}
	// package.json may not be present; npm lockfile v2 embeds name/version.
	pathToContent := map[string][]byte{
		"/tmp/npm-layer/app/package-lock.json": readFixture(t, "/tmp/npm-layer/app/package-lock.json"),
	}
	results := node.ScanNode(pathToContent)
	require.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, "npm", r.Identity.Type)

	dg := getDepGraph(t, &r)
	assert.Equal(t, "npm", dg.PkgManager.Name)

	// Verify root node exists.
	rootPkg := dg.Graph.Nodes[0]
	assert.Equal(t, "root-node", rootPkg.NodeID)

	// 321 non-root entries in packages map; deduplicated by name@version = 291 unique.
	// (The lockfile has nested node_modules/ entries that share the same name@version.)
	assert.Equal(t, 291, depgraph.PkgCount(*dg))
}

func TestNpmLockV2_rootIdentity(t *testing.T) {
	if _, err := os.Stat("/tmp/npm-layer/app/package-lock.json"); os.IsNotExist(err) {
		t.Skip("npm fixture not available")
	}
	pathToContent := map[string][]byte{
		"/tmp/npm-layer/app/package-lock.json": readFixture(t, "/tmp/npm-layer/app/package-lock.json"),
	}
	results := node.ScanNode(pathToContent)
	require.Len(t, results, 1)
	dg := getDepGraph(t, &results[0])

	// Find root pkg.
	rootNodeID := dg.Graph.RootNodeID
	var rootPkgID string
	for _, n := range dg.Graph.Nodes {
		if n.NodeID == rootNodeID {
			rootPkgID = n.PkgID
			break
		}
	}
	assert.NotEmpty(t, rootPkgID)
	var rootPkg *types.PkgInfo
	for _, p := range dg.Pkgs {
		if p.ID == rootPkgID {
			rootPkg = &p.Info
			break
		}
	}
	require.NotNil(t, rootPkg)
	assert.Equal(t, "packlockv2test", rootPkg.Name)
	assert.Equal(t, "1.0.0", rootPkg.Version)
}

func TestNpmLockV2_testedFiles(t *testing.T) {
	if _, err := os.Stat("/tmp/npm-layer/app/package-lock.json"); os.IsNotExist(err) {
		t.Skip("npm fixture not available")
	}
	pathToContent := map[string][]byte{
		"/tmp/npm-layer/app/package-lock.json": readFixture(t, "/tmp/npm-layer/app/package-lock.json"),
	}
	results := node.ScanNode(pathToContent)
	require.Len(t, results, 1)
	var testedFiles []string
	for _, f := range results[0].Facts {
		if f.Type == types.FactTestedFiles {
			testedFiles, _ = f.Data.([]string)
			break
		}
	}
	assert.Contains(t, testedFiles, "package-lock.json")
}

// ---------------------------------------------------------------------------
// yarn lockfile v1
// ---------------------------------------------------------------------------

func TestYarnLockV1_basic(t *testing.T) {
	if _, err := os.Stat("/tmp/yarn-extracted/app/yarn.lock"); os.IsNotExist(err) {
		t.Skip("yarn fixture not available")
	}
	pathToContent := map[string][]byte{
		"/tmp/yarn-extracted/app/package.json": readFixture(t, "/tmp/yarn-extracted/app/package.json"),
		"/tmp/yarn-extracted/app/yarn.lock":    readFixture(t, "/tmp/yarn-extracted/app/yarn.lock"),
	}
	results := node.ScanNode(pathToContent)
	require.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, "yarn", r.Identity.Type)

	dg := getDepGraph(t, &r)
	assert.Equal(t, "yarn", dg.PkgManager.Name)

	// Root should be yarnlockv1test@1.0.0.
	var rootPkg *types.PkgInfo
	rootNodeID := dg.Graph.RootNodeID
	var rootPkgID string
	for _, n := range dg.Graph.Nodes {
		if n.NodeID == rootNodeID {
			rootPkgID = n.PkgID
			break
		}
	}
	for _, p := range dg.Pkgs {
		if p.ID == rootPkgID {
			rootPkg = &p.Info
			break
		}
	}
	require.NotNil(t, rootPkg)
	assert.Equal(t, "yarnlockv1test", rootPkg.Name)
	assert.Equal(t, "1.0.0", rootPkg.Version)

	// Should have packages.
	assert.Greater(t, depgraph.PkgCount(*dg), 0)
}

// ---------------------------------------------------------------------------
// pnpm lockfile v6
// ---------------------------------------------------------------------------

func TestPnpmLockV6_basic(t *testing.T) {
	if _, err := os.Stat("/tmp/pnpm-sample/app/pnpm-lock.yaml"); os.IsNotExist(err) {
		t.Skip("pnpm v6 fixture not available")
	}
	pathToContent := map[string][]byte{
		"/tmp/pnpm-sample/app/package.json":   readFixture(t, "/tmp/pnpm-sample/app/package.json"),
		"/tmp/pnpm-sample/app/pnpm-lock.yaml": readFixture(t, "/tmp/pnpm-sample/app/pnpm-lock.yaml"),
	}
	results := node.ScanNode(pathToContent)
	require.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, "pnpm", r.Identity.Type)

	dg := getDepGraph(t, &r)
	assert.Equal(t, "pnpm", dg.PkgManager.Name)

	// Root package name from package.json.
	var rootPkg *types.PkgInfo
	rootNodeID := dg.Graph.RootNodeID
	var rootPkgID string
	for _, n := range dg.Graph.Nodes {
		if n.NodeID == rootNodeID {
			rootPkgID = n.PkgID
			break
		}
	}
	for _, p := range dg.Pkgs {
		if p.ID == rootPkgID {
			rootPkg = &p.Info
			break
		}
	}
	require.NotNil(t, rootPkg)
	assert.Equal(t, "pnpm-test-project", rootPkg.Name)

	assert.Greater(t, depgraph.PkgCount(*dg), 0)
}

// ---------------------------------------------------------------------------
// pnpm lockfile v9
// ---------------------------------------------------------------------------

func TestPnpmLockV9_basic(t *testing.T) {
	if _, err := os.Stat("/tmp/pnpm9-sample/app/pnpm-lock.yaml"); os.IsNotExist(err) {
		t.Skip("pnpm v9 fixture not available")
	}
	pathToContent := map[string][]byte{
		"/tmp/pnpm9-sample/app/package.json":   readFixture(t, "/tmp/pnpm9-sample/app/package.json"),
		"/tmp/pnpm9-sample/app/pnpm-lock.yaml": readFixture(t, "/tmp/pnpm9-sample/app/pnpm-lock.yaml"),
	}
	results := node.ScanNode(pathToContent)
	require.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, "pnpm", r.Identity.Type)

	dg := getDepGraph(t, &r)
	assert.Equal(t, "pnpm", dg.PkgManager.Name)
	assert.Greater(t, depgraph.PkgCount(*dg), 0)
}

// ---------------------------------------------------------------------------
// ScanNode: no lockfile → no results
// ---------------------------------------------------------------------------

func TestScanNode_noLockfile(t *testing.T) {
	pathToContent := map[string][]byte{
		"/app/package.json": []byte(`{"name":"myapp","version":"1.0.0"}`),
	}
	results := node.ScanNode(pathToContent)
	assert.Empty(t, results)
}

func TestScanNode_noManifestYarn(t *testing.T) {
	// yarn.lock without package.json should produce no results.
	pathToContent := map[string][]byte{
		"/app/yarn.lock": []byte("# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\nyallist@^4:\n  version \"4.0.0\"\n"),
	}
	results := node.ScanNode(pathToContent)
	assert.Empty(t, results)
}

func TestScanNode_noManifestPnpm(t *testing.T) {
	// pnpm-lock.yaml without package.json should produce no results.
	pathToContent := map[string][]byte{
		"/app/pnpm-lock.yaml": []byte("lockfileVersion: '6.0'\n\npackages:\n  /lodash@4.17.21:\n    resolution: {integrity: sha512-abc}\n"),
	}
	results := node.ScanNode(pathToContent)
	assert.Empty(t, results)
}

// ---------------------------------------------------------------------------
// Unit tests for internal parsers via ScanNode
// ---------------------------------------------------------------------------

func TestNpmLockV2_syntheticSmall(t *testing.T) {
	manifest := []byte(`{"name":"myapp","version":"2.0.0"}`)
	lockfile := []byte(`{
  "name": "myapp",
  "version": "2.0.0",
  "lockfileVersion": 2,
  "packages": {
    "": {"name": "myapp", "version": "2.0.0"},
    "node_modules/lodash": {"version": "4.17.21"},
    "node_modules/express": {"version": "4.18.2"}
  }
}`)
	results := node.ScanNode(map[string][]byte{
		"/app/package.json":      manifest,
		"/app/package-lock.json": lockfile,
	})
	require.Len(t, results, 1)
	dg := getDepGraph(t, &results[0])
	assert.Equal(t, "npm", dg.PkgManager.Name)
	assert.Equal(t, 2, depgraph.PkgCount(*dg))
}

func TestYarnV1_syntheticSmall(t *testing.T) {
	manifest := []byte(`{"name":"myapp","version":"1.0.0"}`)
	lockfile := []byte(`# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1

lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
  integrity sha512-abc

express@^4.18.0:
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"
  integrity sha512-def
`)
	results := node.ScanNode(map[string][]byte{
		"/app/package.json": manifest,
		"/app/yarn.lock":    lockfile,
	})
	require.Len(t, results, 1)
	dg := getDepGraph(t, &results[0])
	assert.Equal(t, "yarn", dg.PkgManager.Name)
	assert.Equal(t, 2, depgraph.PkgCount(*dg))
}

func TestPnpmV6_syntheticSmall(t *testing.T) {
	manifest := []byte(`{"name":"myapp","version":"1.0.0"}`)
	lockfile := []byte(`lockfileVersion: '6.0'

packages:

  /lodash@4.17.21:
    resolution: {integrity: sha512-abc}

  /express@4.18.2:
    resolution: {integrity: sha512-def}
`)
	results := node.ScanNode(map[string][]byte{
		"/app/package.json":   manifest,
		"/app/pnpm-lock.yaml": lockfile,
	})
	require.Len(t, results, 1)
	dg := getDepGraph(t, &results[0])
	assert.Equal(t, "pnpm", dg.PkgManager.Name)
	assert.Equal(t, 2, depgraph.PkgCount(*dg))
}

func TestPnpmV9_syntheticSmall(t *testing.T) {
	manifest := []byte(`{"name":"myapp","version":"1.0.0"}`)
	lockfile := []byte(`lockfileVersion: '9.0'

packages:

  lodash@4.17.21:
    resolution: {integrity: sha512-abc}

  express@4.18.2:
    resolution: {integrity: sha512-def}

snapshots:

  lodash@4.17.21: {}

  express@4.18.2: {}
`)
	results := node.ScanNode(map[string][]byte{
		"/app/package.json":   manifest,
		"/app/pnpm-lock.yaml": lockfile,
	})
	require.Len(t, results, 1)
	dg := getDepGraph(t, &results[0])
	assert.Equal(t, "pnpm", dg.PkgManager.Name)
	assert.Equal(t, 2, depgraph.PkgCount(*dg))
}

func TestYarnV2_syntheticSmall(t *testing.T) {
	manifest := []byte(`{"name":"yarnv2app","version":"2.0.0"}`)
	// yarn v2 (Berry) lockfile: no "yarn lockfile v1" header, has __metadata block
	lockfile := []byte(`__metadata:
  version: 6
  cacheKey: 8

"lodash@npm:^4.17.0":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  checksum: abc123
  languageName: node
  linkType: hard

"express@npm:^4.18.0":
  version: 4.18.2
  resolution: "express@npm:4.18.2"
  checksum: def456
  languageName: node
  linkType: hard
`)
	results := node.ScanNode(map[string][]byte{
		"/app/package.json": manifest,
		"/app/yarn.lock":    lockfile,
	})
	require.Len(t, results, 1)
	dg := getDepGraph(t, &results[0])
	assert.Equal(t, "yarn", dg.PkgManager.Name)
	assert.Equal(t, 2, depgraph.PkgCount(*dg))
}
