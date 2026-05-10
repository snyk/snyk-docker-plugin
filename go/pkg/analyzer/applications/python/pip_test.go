package python_test

import (
	"testing"

	python "github.com/snyk/snyk-docker-plugin/pkg/analyzer/applications/python"
	"github.com/snyk/snyk-docker-plugin/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// shared test data
// ---------------------------------------------------------------------------

const flaskMetadata = `Metadata-Version: 2.1
Name: Flask
Version: 2.2.1
Summary: A simple framework for building complex web applications.
Requires-Python: >=3.7
Requires-Dist: Werkzeug (>=2.2.0)
Requires-Dist: Jinja2 (>=3.0)
Requires-Dist: itsdangerous (>=2.0)
Requires-Dist: click (>=8.0)
`

const werkzeugMetadata = `Metadata-Version: 2.1
Name: Werkzeug
Version: 2.2.0
`

const clickMetadata = `Metadata-Version: 2.1
Name: click
Version: 8.1.3
`

// ---------------------------------------------------------------------------
// ScanPip
// ---------------------------------------------------------------------------

func TestScanPip_EmptyMap(t *testing.T) {
	results := python.ScanPip(map[string][]byte{})
	assert.Nil(t, results)
}

func TestScanPip_OnlyRequirementsNoMetadata(t *testing.T) {
	// No dist-info METADATA files → metadata map empty → nil result (TS behaviour).
	pathToContent := map[string][]byte{
		"/app/requirements.txt": []byte("flask==2.2.1\n"),
	}
	results := python.ScanPip(pathToContent)
	assert.Nil(t, results)
}

func TestScanPip_RequirementsAndMetadata_ReturnsScanResult(t *testing.T) {
	pathToContent := map[string][]byte{
		"/app/requirements.txt": []byte("flask==2.2.1\n"),
		"/usr/lib/python3/site-packages/Flask-2.2.1.dist-info/METADATA": []byte(flaskMetadata),
	}

	results := python.ScanPip(pathToContent)
	require.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, "pip", r.Identity.Type)
	assert.Equal(t, "/app/requirements.txt", r.Identity.TargetFile)

	require.Len(t, r.Facts, 1)
	assert.Equal(t, types.FactDepGraph, r.Facts[0].Type)

	dgData, ok := r.Facts[0].Data.(types.DepGraphData)
	require.True(t, ok, "Facts[0].Data should be types.DepGraphData")
	assert.Equal(t, "pip", dgData.PkgManager.Name)
}

func TestScanPip_EmptyRequirements_NoResult(t *testing.T) {
	// requirements.txt that contains only comments → no packages → no result.
	pathToContent := map[string][]byte{
		"/app/requirements.txt": []byte("# just a comment\n\n"),
		"/usr/lib/python3/site-packages/Flask-2.2.1.dist-info/METADATA": []byte(flaskMetadata),
	}
	results := python.ScanPip(pathToContent)
	assert.Nil(t, results)
}

func TestScanPip_PackagesNotInMetadata_NoResult(t *testing.T) {
	// requirements.txt lists packages that have no corresponding METADATA →
	// dep resolution produces 0 deps → no result for that file.
	pathToContent := map[string][]byte{
		"/app/requirements.txt": []byte("unknown-package==1.0.0\n"),
		"/usr/lib/python3/site-packages/Flask-2.2.1.dist-info/METADATA": []byte(flaskMetadata),
	}
	results := python.ScanPip(pathToContent)
	assert.Nil(t, results)
}

func TestScanPip_MultipleRequirementsFiles(t *testing.T) {
	pathToContent := map[string][]byte{
		"/app/requirements.txt":     []byte("flask==2.2.1\n"),
		"/service/requirements.txt": []byte("werkzeug==2.2.0\n"),
		"/usr/lib/python3/site-packages/Flask-2.2.1.dist-info/METADATA":    []byte(flaskMetadata),
		"/usr/lib/python3/site-packages/Werkzeug-2.2.0.dist-info/METADATA": []byte(werkzeugMetadata),
	}

	results := python.ScanPip(pathToContent)
	require.Len(t, results, 2)

	// Results are returned in sorted path order.
	assert.Equal(t, "/app/requirements.txt", results[0].Identity.TargetFile)
	assert.Equal(t, "/service/requirements.txt", results[1].Identity.TargetFile)

	for _, r := range results {
		assert.Equal(t, "pip", r.Identity.Type)
		require.Len(t, r.Facts, 1)
		assert.Equal(t, types.FactDepGraph, r.Facts[0].Type)
	}
}

func TestScanPip_NonRequirementsFilesIgnored(t *testing.T) {
	// Files that are not named requirements.txt must be ignored as requirement
	// inputs (they may still be METADATA files).
	pathToContent := map[string][]byte{
		"/app/setup.cfg":  []byte("flask>=2.0\n"),
		"/app/Pipfile":    []byte("flask = \"*\"\n"),
		"/usr/lib/python3/site-packages/Flask-2.2.1.dist-info/METADATA": []byte(flaskMetadata),
	}
	results := python.ScanPip(pathToContent)
	assert.Nil(t, results)
}

func TestScanPip_DepGraphDataFields(t *testing.T) {
	// Verify the DepGraphData structure returned inside the fact.
	pathToContent := map[string][]byte{
		"/app/requirements.txt": []byte("flask==2.2.1\n"),
		"/usr/lib/python3/site-packages/Flask-2.2.1.dist-info/METADATA": []byte(flaskMetadata),
	}

	results := python.ScanPip(pathToContent)
	require.Len(t, results, 1)

	dgData, ok := results[0].Facts[0].Data.(types.DepGraphData)
	require.True(t, ok)

	assert.Equal(t, "1.2.0", dgData.SchemaVersion)
	assert.Equal(t, "pip", dgData.PkgManager.Name)
	assert.Equal(t, "root-node", dgData.Graph.RootNodeID)
	// At least the root package and flask itself must appear in Pkgs.
	assert.GreaterOrEqual(t, len(dgData.Pkgs), 1)
	// Graph must have at least the root node.
	assert.GreaterOrEqual(t, len(dgData.Graph.Nodes), 1)
}

func TestScanPip_TransitiveDeps(t *testing.T) {
	// Flask depends on Werkzeug (after paren-strip regex handles spacing).
	// Both have METADATA. The dep-graph must include Werkzeug as a transitive node.
	pathToContent := map[string][]byte{
		"/app/requirements.txt": []byte("flask==2.2.1\n"),
		"/usr/lib/python3/site-packages/Flask-2.2.1.dist-info/METADATA":    []byte(flaskMetadata),
		"/usr/lib/python3/site-packages/Werkzeug-2.2.0.dist-info/METADATA": []byte(werkzeugMetadata),
	}

	results := python.ScanPip(pathToContent)
	require.Len(t, results, 1)

	dgData, ok := results[0].Facts[0].Data.(types.DepGraphData)
	require.True(t, ok)

	pkgNames := make(map[string]bool)
	for _, p := range dgData.Pkgs {
		pkgNames[p.Info.Name] = true
	}
	assert.True(t, pkgNames["flask"], "flask should be in pkgs")
	assert.True(t, pkgNames["werkzeug"], "werkzeug should be in pkgs (transitive)")
}

func TestScanPip_WithExtras(t *testing.T) {
	// flask[async]==2.2.1 requests the async extra; the scan should still succeed.
	extraFlaskMetadata := `Metadata-Version: 2.1
Name: Flask
Version: 2.2.1
Requires-Dist: Werkzeug (>=2.2.0)
Requires-Dist: asgiref (>=3.2) ; extra == 'async'
`
	pathToContent := map[string][]byte{
		"/app/requirements.txt": []byte("flask[async]==2.2.1\n"),
		"/usr/lib/python3/site-packages/Flask-2.2.1.dist-info/METADATA":    []byte(extraFlaskMetadata),
		"/usr/lib/python3/site-packages/Werkzeug-2.2.0.dist-info/METADATA": []byte(werkzeugMetadata),
	}

	results := python.ScanPip(pathToContent)
	require.Len(t, results, 1)
	assert.Equal(t, "pip", results[0].Identity.Type)
}

func TestScanPip_MultipleVersionsPackage_VersionMatch(t *testing.T) {
	// Two versions of the same package in metadata; requirements.txt pins a
	// specific version with ==. ScanPip should select the matching one.
	v1 := "Name: requests\nVersion: 2.27.0\n"
	v2 := "Name: requests\nVersion: 2.28.0\n"
	pathToContent := map[string][]byte{
		"/app/requirements.txt":                                        []byte("requests==2.28.0\n"),
		"/layer1/site-packages/requests-2.27.0.dist-info/METADATA":    []byte(v1),
		"/layer2/site-packages/requests-2.28.0.dist-info/METADATA":    []byte(v2),
	}

	results := python.ScanPip(pathToContent)
	require.Len(t, results, 1)

	dgData, ok := results[0].Facts[0].Data.(types.DepGraphData)
	require.True(t, ok)

	found := false
	for _, p := range dgData.Pkgs {
		if p.Info.Name == "requests" {
			assert.Equal(t, "2.28.0", p.Info.Version)
			found = true
		}
	}
	assert.True(t, found, "requests package should be in dep graph")
}

func TestScanPip_NoVersionRequirement_MultipleMetadata(t *testing.T) {
	// When requirements.txt has no version pinned and multiple metadata versions
	// exist, ScanPip should still produce a result (uses first match).
	v1 := "Name: requests\nVersion: 2.27.0\n"
	v2 := "Name: requests\nVersion: 2.28.0\n"
	pathToContent := map[string][]byte{
		"/app/requirements.txt":                                        []byte("requests\n"),
		"/layer1/site-packages/requests-2.27.0.dist-info/METADATA":    []byte(v1),
		"/layer2/site-packages/requests-2.28.0.dist-info/METADATA":    []byte(v2),
	}

	results := python.ScanPip(pathToContent)
	require.Len(t, results, 1)
	assert.Equal(t, types.FactDepGraph, results[0].Facts[0].Type)
}

func TestScanPip_CyclicDepsNoInfiniteLoop(t *testing.T) {
	// a requires b, b requires a — must not hang (visited map prevents recursion).
	a := "Name: a\nVersion: 1.0\nRequires-Dist: b (==1.0)\n"
	b := "Name: b\nVersion: 1.0\nRequires-Dist: a (==1.0)\n"
	results := python.ScanPip(map[string][]byte{
		"/app/requirements.txt":                                              []byte("a==1.0\n"),
		"/usr/lib/python3/site-packages/a-1.0.dist-info/METADATA":           []byte(a),
		"/usr/lib/python3/site-packages/b-1.0.dist-info/METADATA":           []byte(b),
	})
	// Just verify it terminates (test runner timeout would catch infinite loops).
	_ = results
}

func TestScanPip_GteVersionSpecifier(t *testing.T) {
	// requirements.txt uses >= — the version satisfier should handle it.
	v1 := "Name: requests\nVersion: 2.27.0\n"
	v2 := "Name: requests\nVersion: 2.28.0\n"
	pathToContent := map[string][]byte{
		"/app/requirements.txt":                                        []byte("requests>=2.28.0\n"),
		"/layer1/site-packages/requests-2.27.0.dist-info/METADATA":    []byte(v1),
		"/layer2/site-packages/requests-2.28.0.dist-info/METADATA":    []byte(v2),
	}
	results := python.ScanPip(pathToContent)
	require.Len(t, results, 1)
}

func TestScanPip_LteVersionSpecifier(t *testing.T) {
	// requirements.txt uses <= specifier.
	v1 := "Name: requests\nVersion: 2.27.0\n"
	v2 := "Name: requests\nVersion: 2.28.0\n"
	pathToContent := map[string][]byte{
		"/app/requirements.txt":                                        []byte("requests<=2.27.0\n"),
		"/layer1/site-packages/requests-2.27.0.dist-info/METADATA":    []byte(v1),
		"/layer2/site-packages/requests-2.28.0.dist-info/METADATA":    []byte(v2),
	}
	results := python.ScanPip(pathToContent)
	require.Len(t, results, 1)
}

func TestScanPip_CompatibleReleaseSpecifier(t *testing.T) {
	// requirements.txt uses ~= specifier.
	v := "Name: six\nVersion: 1.14.0\n"
	pathToContent := map[string][]byte{
		"/app/requirements.txt":                                     []byte("six~=1.14\n"),
		"/usr/lib/python3/site-packages/six-1.14.0.dist-info/METADATA": []byte(v),
	}
	results := python.ScanPip(pathToContent)
	require.Len(t, results, 1)
}

func TestScanPip_NotEqualSpecifier(t *testing.T) {
	// requirements.txt uses != specifier; version satisfier must handle it.
	v1 := "Name: six\nVersion: 1.13.0\n"
	v2 := "Name: six\nVersion: 1.14.0\n"
	pathToContent := map[string][]byte{
		"/app/requirements.txt": []byte("six!=1.13.0\n"),
		"/layer1/site-packages/six-1.13.0.dist-info/METADATA": []byte(v1),
		"/layer2/site-packages/six-1.14.0.dist-info/METADATA": []byte(v2),
	}
	results := python.ScanPip(pathToContent)
	require.Len(t, results, 1)
}

func TestScanPip_GreaterThanSpecifier(t *testing.T) {
	// requirements.txt uses strict > specifier.
	v1 := "Name: six\nVersion: 1.13.0\n"
	v2 := "Name: six\nVersion: 1.14.0\n"
	pathToContent := map[string][]byte{
		"/app/requirements.txt": []byte("six>1.13.0\n"),
		"/layer1/site-packages/six-1.13.0.dist-info/METADATA": []byte(v1),
		"/layer2/site-packages/six-1.14.0.dist-info/METADATA": []byte(v2),
	}
	results := python.ScanPip(pathToContent)
	require.Len(t, results, 1)
}

func TestScanPip_LessThanSpecifier(t *testing.T) {
	// requirements.txt uses strict < specifier.
	v1 := "Name: six\nVersion: 1.13.0\n"
	v2 := "Name: six\nVersion: 1.14.0\n"
	pathToContent := map[string][]byte{
		"/app/requirements.txt": []byte("six<1.14.0\n"),
		"/layer1/site-packages/six-1.13.0.dist-info/METADATA": []byte(v1),
		"/layer2/site-packages/six-1.14.0.dist-info/METADATA": []byte(v2),
	}
	results := python.ScanPip(pathToContent)
	require.Len(t, results, 1)
}

func TestScanPip_extrasDepsNotTraversed(t *testing.T) {
	// Flask has deps gated on extras: asgiref requires extra=='async'.
	// If we don't request the 'async' extra, asgiref should not appear in the graph.
	flask := `Name: Flask
Version: 2.2.1
Requires-Dist: Werkzeug (>=2.2.0)
Requires-Dist: asgiref[server] (>=3.2) ; extra == 'async'
`
	results := python.ScanPip(map[string][]byte{
		"/app/requirements.txt": []byte("flask==2.2.1\n"),
		"/usr/lib/python3/site-packages/Flask-2.2.1.dist-info/METADATA":   []byte(flask),
		"/usr/lib/python3/site-packages/Werkzeug-2.2.2.dist-info/METADATA": []byte(werkzeugMetadata),
	})
	// Should produce a result for flask.
	require.Len(t, results, 1)
	dg := results[0].Facts[0].Data.(types.DepGraphData)
	pkgNames := map[string]bool{}
	for _, p := range dg.Pkgs {
		pkgNames[p.Info.Name] = true
	}
	// asgiref should NOT be present (extra not requested).
	assert.False(t, pkgNames["asgiref"], "asgiref should not be traversed when extra not requested")
}

func TestScanPip_versionSatisfiesCompatible(t *testing.T) {
	// flask>=2.2.0 with available 2.2.1 should match via ~= fallback (>=).
	results := python.ScanPip(map[string][]byte{
		"/app/requirements.txt": []byte("flask>=2.2.0\n"),
		"/usr/lib/python3/site-packages/Flask-2.2.1.dist-info/METADATA": []byte(flaskMetadata),
		"/usr/lib/python3/site-packages/Werkzeug-2.2.2.dist-info/METADATA": []byte(werkzeugMetadata),
		"/usr/lib/python3/site-packages/click-8.1.3.dist-info/METADATA":    []byte(clickMetadata),
	})
	assert.Len(t, results, 1)
}

func TestScanPip_versionSatisfiesLessThan(t *testing.T) {
	// flask<3.0 with available 2.2.1 should match.
	results := python.ScanPip(map[string][]byte{
		"/app/requirements.txt": []byte("flask<3.0\n"),
		"/usr/lib/python3/site-packages/Flask-2.2.1.dist-info/METADATA": []byte(flaskMetadata),
		"/usr/lib/python3/site-packages/Werkzeug-2.2.2.dist-info/METADATA": []byte(werkzeugMetadata),
		"/usr/lib/python3/site-packages/click-8.1.3.dist-info/METADATA":    []byte(clickMetadata),
	})
	assert.Len(t, results, 1)
}

func TestScanPip_versionSatisfiesNotEqual(t *testing.T) {
	// flask!=3.0 with available 2.2.1 — 2.2.1 != 3.0 so it matches.
	results := python.ScanPip(map[string][]byte{
		"/app/requirements.txt": []byte("flask!=3.0\n"),
		"/usr/lib/python3/site-packages/Flask-2.2.1.dist-info/METADATA": []byte(flaskMetadata),
		"/usr/lib/python3/site-packages/Werkzeug-2.2.2.dist-info/METADATA": []byte(werkzeugMetadata),
		"/usr/lib/python3/site-packages/click-8.1.3.dist-info/METADATA":    []byte(clickMetadata),
	})
	assert.Len(t, results, 1)
}

func TestScanPip_multipleVersionsSelectsMatchingOne(t *testing.T) {
	v1 := "Name: mylib\nVersion: 1.0.0\n"
	v2 := "Name: mylib\nVersion: 2.0.0\n"
	results := python.ScanPip(map[string][]byte{
		"/app/requirements.txt": []byte("mylib==2.0.0\n"),
		"/usr/lib/python3/site-packages/mylib-1.0.0.dist-info/METADATA": []byte(v1),
		"/usr/lib/python3/site-packages/mylib-2.0.0.dist-info/METADATA": []byte(v2),
	})
	require.Len(t, results, 1)
	dg := results[0].Facts[0].Data.(types.DepGraphData)
	found := false
	for _, p := range dg.Pkgs {
		if p.Info.Name == "mylib" && p.Info.Version == "2.0.0" {
			found = true
		}
	}
	assert.True(t, found, "expected mylib@2.0.0 in dep-graph")
}
