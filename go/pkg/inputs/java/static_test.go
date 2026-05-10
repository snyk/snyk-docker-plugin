package java_test

import (
	"strings"
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/inputs/java"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJavaActions_count(t *testing.T) {
	assert.Len(t, java.Actions(), 1)
}

func TestJavaActions_actionName(t *testing.T) {
	assert.Equal(t, java.ActionName, java.Actions()[0].ActionName)
}

func TestJavaActions_matchesJar(t *testing.T) {
	m := java.Actions()[0].FilePathMatches
	assert.True(t, m("/app/mylib.jar"))
	assert.True(t, m("/opt/app.WAR"))
	assert.True(t, m("/deploy/app.ear"))
	assert.False(t, m("/app/Main.class"))
	assert.False(t, m("/config.xml"))
}

func TestJavaActions_callbackReadsBytes(t *testing.T) {
	cb := java.Actions()[0].Callback
	require.NotNil(t, cb)
	r := strings.NewReader("fake jar content")
	res, err := cb(r, 16)
	require.NoError(t, err)
	data, ok := res.([]byte)
	require.True(t, ok)
	assert.Equal(t, "fake jar content", string(data))
}
