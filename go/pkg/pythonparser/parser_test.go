package pythonparser_test

import (
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/pythonparser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// ParseRequirementsTxt
// ---------------------------------------------------------------------------

func TestParseRequirementsTxt_EmptyContent(t *testing.T) {
	reqs, err := pythonparser.ParseRequirementsTxt("")
	require.NoError(t, err)
	assert.Empty(t, reqs)
}

func TestParseRequirementsTxt_CommentLinesSkipped(t *testing.T) {
	content := "# this is a comment\n# another comment\n"
	reqs, err := pythonparser.ParseRequirementsTxt(content)
	require.NoError(t, err)
	assert.Empty(t, reqs)
}

func TestParseRequirementsTxt_BlankLinesSkipped(t *testing.T) {
	content := "\n\n   \n\n"
	reqs, err := pythonparser.ParseRequirementsTxt(content)
	require.NoError(t, err)
	assert.Empty(t, reqs)
}

func TestParseRequirementsTxt_InlineCommentStripped(t *testing.T) {
	content := "flask>=2.2.0 # needed for web\n"
	reqs, err := pythonparser.ParseRequirementsTxt(content)
	require.NoError(t, err)
	require.Len(t, reqs, 1)
	assert.Equal(t, "flask", reqs[0].Name)
	assert.Equal(t, pythonparser.SpecGte, reqs[0].Specifier)
	assert.Equal(t, "2.2.0", reqs[0].Version)
}

func TestParseRequirementsTxt_ExactVersion(t *testing.T) {
	reqs, err := pythonparser.ParseRequirementsTxt("flask==2.2.1\n")
	require.NoError(t, err)
	require.Len(t, reqs, 1)
	assert.Equal(t, "flask", reqs[0].Name)
	assert.Equal(t, pythonparser.SpecEq, reqs[0].Specifier)
	assert.Equal(t, "2.2.1", reqs[0].Version)
}

func TestParseRequirementsTxt_CompatibleRelease(t *testing.T) {
	reqs, err := pythonparser.ParseRequirementsTxt("six~=1.14\n")
	require.NoError(t, err)
	require.Len(t, reqs, 1)
	assert.Equal(t, "six", reqs[0].Name)
	assert.Equal(t, pythonparser.SpecCom, reqs[0].Specifier)
	assert.Equal(t, "1.14", reqs[0].Version)
}

func TestParseRequirementsTxt_DotInName(t *testing.T) {
	reqs, err := pythonparser.ParseRequirementsTxt("rpc.py==0.4.2\n")
	require.NoError(t, err)
	require.Len(t, reqs, 1)
	assert.Equal(t, "rpc.py", reqs[0].Name)
	assert.Equal(t, pythonparser.SpecEq, reqs[0].Specifier)
	assert.Equal(t, "0.4.2", reqs[0].Version)
}

func TestParseRequirementsTxt_GreaterThanOrEqual(t *testing.T) {
	reqs, err := pythonparser.ParseRequirementsTxt("flask>=2.2.0\n")
	require.NoError(t, err)
	require.Len(t, reqs, 1)
	assert.Equal(t, "flask", reqs[0].Name)
	assert.Equal(t, pythonparser.SpecGte, reqs[0].Specifier)
	assert.Equal(t, "2.2.0", reqs[0].Version)
}

func TestParseRequirementsTxt_NoVersion(t *testing.T) {
	reqs, err := pythonparser.ParseRequirementsTxt("requests\n")
	require.NoError(t, err)
	require.Len(t, reqs, 1)
	assert.Equal(t, "requests", reqs[0].Name)
	assert.Equal(t, pythonparser.Specifier(""), reqs[0].Specifier)
	assert.Equal(t, "", reqs[0].Version)
}

func TestParseRequirementsTxt_SingleExtra(t *testing.T) {
	reqs, err := pythonparser.ParseRequirementsTxt("flask[async]==2.2.1\n")
	require.NoError(t, err)
	require.Len(t, reqs, 1)
	assert.Equal(t, "flask", reqs[0].Name)
	assert.Equal(t, pythonparser.SpecEq, reqs[0].Specifier)
	assert.Equal(t, "2.2.1", reqs[0].Version)
	assert.Equal(t, []string{"async"}, reqs[0].Extras)
}

func TestParseRequirementsTxt_MultipleExtras(t *testing.T) {
	reqs, err := pythonparser.ParseRequirementsTxt("flask[async,dotenv]>=2.0\n")
	require.NoError(t, err)
	require.Len(t, reqs, 1)
	assert.Equal(t, "flask", reqs[0].Name)
	assert.Equal(t, []string{"async", "dotenv"}, reqs[0].Extras)
	assert.Equal(t, "2.0", reqs[0].Version)
}

func TestParseRequirementsTxt_MultiplePackages(t *testing.T) {
	content := "requests==2.28.0\nflask==2.2.3\nnumpy\n"
	reqs, err := pythonparser.ParseRequirementsTxt(content)
	require.NoError(t, err)
	require.Len(t, reqs, 3)
	assert.Equal(t, "requests", reqs[0].Name)
	assert.Equal(t, "flask", reqs[1].Name)
	assert.Equal(t, "numpy", reqs[2].Name)
}

func TestParseRequirementsTxt_MixedContent(t *testing.T) {
	// Comments, blanks, and valid entries interleaved; order preserved.
	content := `# top comment
requests==2.28.0

# section comment
flask>=2.0
`
	reqs, err := pythonparser.ParseRequirementsTxt(content)
	require.NoError(t, err)
	require.Len(t, reqs, 2)
	assert.Equal(t, "requests", reqs[0].Name)
	assert.Equal(t, "flask", reqs[1].Name)
}

// ---------------------------------------------------------------------------
// ParseDistInfoMetadata
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
Requires-Dist: importlib-metadata (>=3.6.0) ; python_version < "3.10"
Requires-Dist: asgiref (>=3.2) ; extra == 'async'
Requires-Dist: python-dotenv ; extra == 'dotenv'
`

func TestParseDistInfoMetadata_FullFlask(t *testing.T) {
	pkg, err := pythonparser.ParseDistInfoMetadata(flaskMetadata)
	require.NoError(t, err)
	require.NotNil(t, pkg)

	assert.Equal(t, "flask", pkg.Name)
	assert.Equal(t, "2.2.1", pkg.Version)

	// All Requires-Dist lines produce a dependency entry (including env-marker
	// and extra-marker lines). Names are always lower-cased.
	require.Len(t, pkg.Dependencies, 7)

	// "Werkzeug (>=2.2.0)" → paren stripped → "Werkzeug >=2.2.0"
	// regex with \s* handles the space before >=.
	werkzeug := pkg.Dependencies[0]
	assert.Equal(t, "werkzeug", werkzeug.Name)
	assert.Equal(t, pythonparser.SpecGte, werkzeug.Specifier)
	assert.Equal(t, "2.2.0", werkzeug.Version)

	jinja := pkg.Dependencies[1]
	assert.Equal(t, "jinja2", jinja.Name)
	assert.Equal(t, pythonparser.SpecGte, jinja.Specifier)

	// importlib-metadata: env-marker stripped, name + version parsed correctly.
	importlib := pkg.Dependencies[4]
	assert.Equal(t, "importlib-metadata", importlib.Name)
	assert.Equal(t, pythonparser.SpecGte, importlib.Specifier)
	assert.Equal(t, "3.6.0", importlib.Version)

	// asgiref is extras-gated — still returned by parser (filtering is done
	// upstream by the pip analyser).
	asgiref := pkg.Dependencies[5]
	assert.Equal(t, "asgiref", asgiref.Name)

	// python-dotenv has no version specifier.
	dotenv := pkg.Dependencies[6]
	assert.Equal(t, "python-dotenv", dotenv.Name)
	assert.Equal(t, "", dotenv.Version)
}

func TestParseDistInfoMetadata_EmptyContent(t *testing.T) {
	pkg, err := pythonparser.ParseDistInfoMetadata("")
	require.NoError(t, err)
	assert.Nil(t, pkg)
}

func TestParseDistInfoMetadata_NameOnlyNoVersion(t *testing.T) {
	content := "Name: mypackage\n"
	pkg, err := pythonparser.ParseDistInfoMetadata(content)
	require.NoError(t, err)
	require.NotNil(t, pkg)
	assert.Equal(t, "mypackage", pkg.Name)
	assert.Equal(t, "", pkg.Version)
	assert.Empty(t, pkg.Dependencies)
}

func TestParseDistInfoMetadata_RequiresDistWithParens(t *testing.T) {
	// "Werkzeug (>=2.2.0)" → after paren-stripping → "Werkzeug >=2.2.0"
	// → the regex with \s* allows space before specifier.
	content := "Name: myapp\nVersion: 1.0\nRequires-Dist: Werkzeug (>=2.2.0)\n"
	pkg, err := pythonparser.ParseDistInfoMetadata(content)
	require.NoError(t, err)
	require.NotNil(t, pkg)
	require.Len(t, pkg.Dependencies, 1)
	d := pkg.Dependencies[0]
	assert.Equal(t, "werkzeug", d.Name)
	assert.Equal(t, pythonparser.SpecGte, d.Specifier)
	assert.Equal(t, "2.2.0", d.Version)
}

func TestParseDistInfoMetadata_EnvMarkerStripped(t *testing.T) {
	// "importlib-metadata (>=3.6.0) ; python_version < '3.10'"
	// After semicolon strip: "importlib-metadata (>=3.6.0)"
	// After paren strip: "importlib-metadata >=3.6.0"
	// Regex now handles space before specifier correctly.
	content := "Name: myapp\nVersion: 1.0\nRequires-Dist: importlib-metadata (>=3.6.0) ; python_version < '3.10'\n"
	pkg, err := pythonparser.ParseDistInfoMetadata(content)
	require.NoError(t, err)
	require.NotNil(t, pkg)
	require.Len(t, pkg.Dependencies, 1)
	d := pkg.Dependencies[0]
	assert.Equal(t, "importlib-metadata", d.Name)
	assert.Equal(t, pythonparser.SpecGte, d.Specifier)
	assert.Equal(t, "3.6.0", d.Version)
}

func TestParseDistInfoMetadata_ExtrasMarkerIncluded(t *testing.T) {
	// Deps gated on extra == 'something' are still returned at parse time;
	// caller decides whether to traverse based on requested extras.
	// "asgiref (>=3.2) ; extra == 'async'" → semi stripped →
	// "asgiref (>=3.2)" → paren stripped → "asgiref >=3.2".
	content := "Name: myapp\nVersion: 1.0\nRequires-Dist: asgiref (>=3.2) ; extra == 'async'\n"
	pkg, err := pythonparser.ParseDistInfoMetadata(content)
	require.NoError(t, err)
	require.NotNil(t, pkg)
	require.Len(t, pkg.Dependencies, 1)
	assert.Equal(t, "asgiref", pkg.Dependencies[0].Name)
	assert.Equal(t, pythonparser.SpecGte, pkg.Dependencies[0].Specifier)
	assert.Equal(t, "3.2", pkg.Dependencies[0].Version)
}

// ---------------------------------------------------------------------------
// ParseSitePackagesMetadata
// ---------------------------------------------------------------------------

func TestParseSitePackagesMetadata_NoFiles(t *testing.T) {
	result := pythonparser.ParseSitePackagesMetadata(map[string][]byte{})
	assert.Empty(t, result)
}

func TestParseSitePackagesMetadata_SingleMetadataFile(t *testing.T) {
	pathToContent := map[string][]byte{
		"/usr/lib/python3/site-packages/Flask-2.2.1.dist-info/METADATA": []byte(flaskMetadata),
	}
	result := pythonparser.ParseSitePackagesMetadata(pathToContent)
	require.Len(t, result, 1)
	pkgs, ok := result["flask"]
	require.True(t, ok, "expected key 'flask'")
	require.Len(t, pkgs, 1)
	assert.Equal(t, "flask", pkgs[0].Name)
	assert.Equal(t, "2.2.1", pkgs[0].Version)
}

func TestParseSitePackagesMetadata_FileNotInDistInfoDir(t *testing.T) {
	// METADATA file outside a .dist-info directory must be skipped.
	pathToContent := map[string][]byte{
		"/usr/lib/python3/site-packages/Flask-2.2.1/METADATA": []byte(flaskMetadata),
	}
	result := pythonparser.ParseSitePackagesMetadata(pathToContent)
	assert.Empty(t, result)
}

func TestParseSitePackagesMetadata_RandomFileName(t *testing.T) {
	// A file named something other than "METADATA" in a dist-info dir must be
	// skipped.
	pathToContent := map[string][]byte{
		"/usr/lib/python3/site-packages/Flask-2.2.1.dist-info/WHEEL": []byte(flaskMetadata),
	}
	result := pythonparser.ParseSitePackagesMetadata(pathToContent)
	assert.Empty(t, result)
}

func TestParseSitePackagesMetadata_TwoVersionsSamePackage(t *testing.T) {
	v1 := "Name: requests\nVersion: 2.27.0\n"
	v2 := "Name: requests\nVersion: 2.28.0\n"
	pathToContent := map[string][]byte{
		"/layer1/site-packages/requests-2.27.0.dist-info/METADATA": []byte(v1),
		"/layer2/site-packages/requests-2.28.0.dist-info/METADATA": []byte(v2),
	}
	result := pythonparser.ParseSitePackagesMetadata(pathToContent)
	pkgs, ok := result["requests"]
	require.True(t, ok)
	assert.Len(t, pkgs, 2)
	// Both versions must be present (order unspecified).
	versions := map[string]bool{pkgs[0].Version: true, pkgs[1].Version: true}
	assert.True(t, versions["2.27.0"], "expected version 2.27.0")
	assert.True(t, versions["2.28.0"], "expected version 2.28.0")
}

func TestParseSitePackagesMetadata_RealFlask(t *testing.T) {
	pathToContent := map[string][]byte{
		"/usr/local/lib/python3.10/site-packages/Flask-2.2.1.dist-info/METADATA": []byte(flaskMetadata),
	}
	result := pythonparser.ParseSitePackagesMetadata(pathToContent)
	require.Contains(t, result, "flask")
	flaskPkgs := result["flask"]
	require.Len(t, flaskPkgs, 1)
	assert.Equal(t, "2.2.1", flaskPkgs[0].Version)
}
