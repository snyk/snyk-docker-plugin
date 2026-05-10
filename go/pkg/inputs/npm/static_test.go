package npm_test

import (
	"strings"
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/inputs/npm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNpmActions_count(t *testing.T) {
	assert.Len(t, npm.Actions(), 1)
}

func TestNpmActions_actionName(t *testing.T) {
	assert.Equal(t, npm.ActionName, npm.Actions()[0].ActionName)
}

func TestNpmActions_matchesPackageJSON(t *testing.T) {
	m := npm.Actions()[0].FilePathMatches
	assert.True(t, m("/app/package.json"))
	assert.True(t, m("/deep/nested/app/package.json"))
}

func TestNpmActions_matchesPackageLockJSON(t *testing.T) {
	m := npm.Actions()[0].FilePathMatches
	assert.True(t, m("/app/package-lock.json"))
}

func TestNpmActions_matchesYarnLock(t *testing.T) {
	m := npm.Actions()[0].FilePathMatches
	assert.True(t, m("/app/yarn.lock"))
}

func TestNpmActions_matchesPnpmLock(t *testing.T) {
	m := npm.Actions()[0].FilePathMatches
	assert.True(t, m("/app/pnpm-lock.yaml"))
}

func TestNpmActions_matchesWhiteoutVariants(t *testing.T) {
	m := npm.Actions()[0].FilePathMatches
	assert.True(t, m("/app/.wh.package.json"))
	assert.True(t, m("/app/.wh.yarn.lock"))
	assert.True(t, m("/app/.wh.pnpm-lock.yaml"))
}

func TestNpmActions_noMatchForOtherFiles(t *testing.T) {
	m := npm.Actions()[0].FilePathMatches
	assert.False(t, m("/app/index.js"))
	assert.False(t, m("/app/requirements.txt"))
	assert.False(t, m("/app/composer.json"))
}

func TestNpmActions_matchesNestedPackageJSON(t *testing.T) {
	// package.json at any depth should match (base name check only)
	m := npm.Actions()[0].FilePathMatches
	assert.True(t, m("/app/node_modules/foo/package.json"))
}

func TestNpmActions_callbackReadsBytes(t *testing.T) {
	cb := npm.Actions()[0].Callback
	r := strings.NewReader(`{"name":"test"}`)
	res, err := cb(r, 15)
	require.NoError(t, err)
	data, ok := res.([]byte)
	require.True(t, ok)
	assert.Equal(t, `{"name":"test"}`, string(data))
}
