package php_test

import (
	"strings"
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/inputs/php"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPhpActions_count(t *testing.T) {
	assert.Len(t, php.Actions(), 1)
}

func TestPhpActions_actionName(t *testing.T) {
	assert.Equal(t, php.ActionName, php.Actions()[0].ActionName)
}

func TestPhpActions_matchesComposerFiles(t *testing.T) {
	m := php.Actions()[0].FilePathMatches
	assert.True(t, m("/app/composer.json"))
	assert.True(t, m("/app/composer.lock"))
	assert.False(t, m("/app/package.json"))
	assert.False(t, m("/app/composer.json.bak"))
}

func TestPhpActions_callbackReadsBytes(t *testing.T) {
	cb := php.Actions()[0].Callback
	r := strings.NewReader(`{"packages":[]}`)
	res, err := cb(r, 15)
	require.NoError(t, err)
	data, ok := res.([]byte)
	require.True(t, ok)
	assert.Contains(t, string(data), "packages")
}
