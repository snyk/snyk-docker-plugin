package python_test

import (
	"strings"
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/inputs/python"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Poetry actions tests
// ---------------------------------------------------------------------------

func TestPoetryActions_count(t *testing.T) {
	assert.Len(t, python.PoetryActions(), 1)
}

func TestPoetryActions_actionName(t *testing.T) {
	assert.Equal(t, python.PoetryActionName, python.PoetryActions()[0].ActionName)
}

func TestPoetryActions_matchesPyprojectToml(t *testing.T) {
	m := python.PoetryActions()[0].FilePathMatches
	assert.True(t, m("/app/pyproject.toml"))
	assert.True(t, m("/service/deep/pyproject.toml"))
}

func TestPoetryActions_matchesPoetryLock(t *testing.T) {
	m := python.PoetryActions()[0].FilePathMatches
	assert.True(t, m("/app/poetry.lock"))
	assert.True(t, m("/service/poetry.lock"))
}

func TestPoetryActions_matchesWhiteoutVariants(t *testing.T) {
	m := python.PoetryActions()[0].FilePathMatches
	assert.True(t, m("/app/.wh.pyproject.toml"))
	assert.True(t, m("/app/.wh.poetry.lock"))
}

func TestPoetryActions_doesNotMatchOtherFiles(t *testing.T) {
	m := python.PoetryActions()[0].FilePathMatches
	assert.False(t, m("/app/requirements.txt"))
	assert.False(t, m("/app/setup.py"))
	assert.False(t, m("/app/Pipfile"))
	assert.False(t, m("/app/pyproject.toml.bak"))
}

func TestPoetryActions_callbackReadsBytes(t *testing.T) {
	cb := python.PoetryActions()[0].Callback
	r := strings.NewReader("[tool.poetry]\nname = \"myapp\"")
	res, err := cb(r, int64(len("[tool.poetry]\nname = \"myapp\"")))
	require.NoError(t, err)
	data, ok := res.([]byte)
	require.True(t, ok)
	assert.Contains(t, string(data), "tool.poetry")
}

func TestPythonActions_count(t *testing.T) {
	assert.Len(t, python.Actions(), 1)
}

func TestPythonActions_actionName(t *testing.T) {
	assert.Equal(t, python.ActionName, python.Actions()[0].ActionName)
}

func TestPythonActions_matchesRequirements(t *testing.T) {
	m := python.Actions()[0].FilePathMatches
	assert.True(t, m("/app/requirements.txt"))
	assert.True(t, m("/service/requirements.txt"))
}

func TestPythonActions_matchesMETADATA(t *testing.T) {
	m := python.Actions()[0].FilePathMatches
	assert.True(t, m("/usr/lib/python3/site-packages/Flask-2.2.1.dist-info/METADATA"))
	assert.False(t, m("/usr/lib/python3/site-packages/Flask-2.2.1.dist-info/WHEEL"))
	assert.False(t, m("/app/METADATA")) // not in .dist-info dir
	assert.False(t, m("/app/setup.py"))
}

func TestPythonActions_callbackReadsBytes(t *testing.T) {
	cb := python.Actions()[0].Callback
	r := strings.NewReader("flask==2.2.1")
	res, err := cb(r, 12)
	require.NoError(t, err)
	data, ok := res.([]byte)
	require.True(t, ok)
	assert.Equal(t, "flask==2.2.1", string(data))
}
