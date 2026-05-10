package ruby_test

import (
	"encoding/base64"
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/analyzer/applications/ruby"
	"github.com/snyk/snyk-docker-plugin/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const gemfileLockContent = `GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.0)
    rake (13.0.6)

PLATFORMS
  ruby

DEPENDENCIES
  rails (~> 7.0.0)

BUNDLED WITH
   2.3.26
`

func TestScanGemfile_BasicCase(t *testing.T) {
	pathToContent := map[string][]byte{
		"/app/Gemfile.lock": []byte(gemfileLockContent),
	}
	results := ruby.ScanGemfile(pathToContent)
	require.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, "rubygems", r.Identity.Type)
	assert.Equal(t, "/app/Gemfile.lock", r.Identity.TargetFile)

	require.Len(t, r.Facts, 1)
	assert.Equal(t, types.FactImageManifestFiles, r.Facts[0].Type)
}

func TestScanGemfile_ManifestFileContents(t *testing.T) {
	pathToContent := map[string][]byte{
		"/app/Gemfile.lock": []byte(gemfileLockContent),
	}
	results := ruby.ScanGemfile(pathToContent)
	require.Len(t, results, 1)

	manifests, ok := results[0].Facts[0].Data.([]types.ManifestFile)
	require.True(t, ok, "Data should be []types.ManifestFile")
	require.Len(t, manifests, 1)

	m := manifests[0]
	assert.Equal(t, "Gemfile.lock", m.Name)
	assert.Equal(t, "/app/Gemfile.lock", m.Path)

	// Contents must be base64-encoded original bytes.
	decoded, err := base64.StdEncoding.DecodeString(m.Contents)
	require.NoError(t, err)
	assert.Equal(t, gemfileLockContent, string(decoded))
}

func TestScanGemfile_EmptyMap(t *testing.T) {
	results := ruby.ScanGemfile(map[string][]byte{})
	assert.Nil(t, results)
}

func TestScanGemfile_NonGemfileIgnored(t *testing.T) {
	pathToContent := map[string][]byte{
		"/app/Gemfile":          []byte("source 'https://rubygems.org'\ngem 'rails'\n"),
		"/app/package.json":     []byte(`{"name":"foo"}`),
		"/app/requirements.txt": []byte("flask==2.0\n"),
	}
	results := ruby.ScanGemfile(pathToContent)
	assert.Nil(t, results)
}

func TestScanGemfile_MultipleGemfileLocks(t *testing.T) {
	pathToContent := map[string][]byte{
		"/app/Gemfile.lock":     []byte(gemfileLockContent),
		"/service/Gemfile.lock": []byte("GEM\n  specs:\n    sinatra (3.0.0)\n"),
	}
	results := ruby.ScanGemfile(pathToContent)
	assert.Len(t, results, 2)

	// Both results should be rubygems type with imageManifestFiles.
	for _, r := range results {
		assert.Equal(t, "rubygems", r.Identity.Type)
		require.Len(t, r.Facts, 1)
		assert.Equal(t, types.FactImageManifestFiles, r.Facts[0].Type)
	}
}

func TestScanGemfile_ContentsAreBase64(t *testing.T) {
	raw := []byte("some gem lock content")
	pathToContent := map[string][]byte{
		"/srv/Gemfile.lock": raw,
	}
	results := ruby.ScanGemfile(pathToContent)
	require.Len(t, results, 1)

	manifests := results[0].Facts[0].Data.([]types.ManifestFile)
	decoded, err := base64.StdEncoding.DecodeString(manifests[0].Contents)
	require.NoError(t, err)
	assert.Equal(t, raw, decoded)
}
