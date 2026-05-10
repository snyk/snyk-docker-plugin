package ruby_test

import (
	"strings"
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/inputs/ruby"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRubyActions_count(t *testing.T) {
	assert.Len(t, ruby.Actions(), 1)
}

func TestRubyActions_actionName(t *testing.T) {
	assert.Equal(t, ruby.ActionName, ruby.Actions()[0].ActionName)
	assert.Equal(t, "ruby-app-files", ruby.ActionName)
}

func TestRubyActions_matchesGemfileLock(t *testing.T) {
	m := ruby.Actions()[0].FilePathMatches
	assert.True(t, m("/app/Gemfile.lock"))
	assert.True(t, m("/service/deep/Gemfile.lock"))
}

func TestRubyActions_matchesWhiteoutVariant(t *testing.T) {
	m := ruby.Actions()[0].FilePathMatches
	assert.True(t, m("/app/.wh.Gemfile.lock"))
}

func TestRubyActions_doesNotMatchOtherFiles(t *testing.T) {
	m := ruby.Actions()[0].FilePathMatches
	assert.False(t, m("/app/Gemfile"))
	assert.False(t, m("/app/gemfile.lock")) // case-sensitive
	assert.False(t, m("/app/package.json"))
	assert.False(t, m("/app/Gemfile.lock.bak"))
}

func TestRubyActions_callbackReadsBytes(t *testing.T) {
	cb := ruby.Actions()[0].Callback
	content := "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.0)\n"
	r := strings.NewReader(content)
	res, err := cb(r, int64(len(content)))
	require.NoError(t, err)
	data, ok := res.([]byte)
	require.True(t, ok)
	assert.Equal(t, content, string(data))
}
