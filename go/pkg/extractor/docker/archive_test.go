package docker_test

import (
	"io"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/extractor"
	"github.com/snyk/snyk-docker-plugin/pkg/extractor/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	// file is at: go/pkg/extractor/docker/archive_test.go
	// 4 levels up = repo root
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "..")
}

func fixtureArchive(name string) string {
	return filepath.Join(repoRoot(), "test", "fixtures", "docker-archives", "docker-save", name)
}

func TestExtractArchive_helloWorld(t *testing.T) {
	result, err := docker.ExtractArchive(fixtureArchive("hello-world.tar"), nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.ImageID, "expected image ID")
	assert.NotEmpty(t, result.ManifestLayers, "expected at least one layer")
}

func TestExtractArchive_withAction(t *testing.T) {
	actions := []extractor.ExtractAction{
		{
			ActionName: "osRelease",
			FilePathMatches: func(p string) bool {
				return p == "/etc/os-release"
			},
			Callback: func(r io.Reader, _ int64) (interface{}, error) {
				data, err := io.ReadAll(r)
				return data, err
			},
		},
	}
	// hello-world has no /etc/os-release but should extract cleanly.
	result, err := docker.ExtractArchive(fixtureArchive("hello-world.tar"), actions)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestExtractArchive_notFound(t *testing.T) {
	_, err := docker.ExtractArchive("/nonexistent/path/foo.tar", nil)
	assert.Error(t, err)
}
