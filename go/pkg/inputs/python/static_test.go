package python_test

import (
	"strings"
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/inputs/python"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
