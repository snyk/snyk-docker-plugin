package node_test

import (
	"strings"
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/inputs/node"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNodeActions_count(t *testing.T) {
	assert.Len(t, node.Actions(), 1)
}

func TestNodeActions_actionName(t *testing.T) {
	assert.Equal(t, node.ActionName, node.Actions()[0].ActionName)
}

func TestNodeActions_matchesBinaryPaths(t *testing.T) {
	m := node.Actions()[0].FilePathMatches
	assert.True(t, m("/usr/bin/myapp"))
	assert.True(t, m("/opt/service"))
	assert.False(t, m("/usr/bin/script.sh"))
	assert.False(t, m("/etc/myapp")) // /etc is ignored
}

func TestNodeActions_callbackReadsBytes(t *testing.T) {
	cb := node.Actions()[0].Callback
	require.NotNil(t, cb)
	r := strings.NewReader("binary content")
	res, err := cb(r, 14)
	require.NoError(t, err)
	_, ok := res.([]byte)
	assert.True(t, ok)
}
