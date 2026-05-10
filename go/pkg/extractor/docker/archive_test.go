package docker_test

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/extractor"
	"github.com/snyk/snyk-docker-plugin/pkg/extractor/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixtureDir returns the directory containing test fixture archives.
// Under Bazel, the FIXTURE_DIR env var points at the fixtures dir relative to
// the workspace root (available via runfiles). Under plain `go test`, we walk
// up from the source file location.
func fixtureDir() string {
	if dir := os.Getenv("FIXTURE_DIR"); dir != "" {
		// Bazel sets TEST_SRCDIR to the runfiles tree root.
		srcdir := os.Getenv("TEST_SRCDIR")
		if srcdir == "" {
			srcdir = os.Getenv("BUILD_WORKSPACE_DIRECTORY")
		}
		if srcdir != "" {
			return filepath.Join(srcdir, "_main", dir)
		}
		return dir
	}
	// Plain go test: walk up from the source file.
	_, file, _, _ := runtime.Caller(0)
	// go/pkg/extractor/docker/archive_test.go → 4 levels up = repo root
	root := filepath.Join(filepath.Dir(file), "..", "..", "..", "..")
	return filepath.Join(root, "test", "fixtures", "docker-archives", "docker-save")
}

func fixtureArchive(name string) string {
	return filepath.Join(fixtureDir(), name)
}

func TestExtractArchive_helloWorld(t *testing.T) {
	path := fixtureArchive("hello-world.tar")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("fixture not found at %s: %v", path, err)
	}
	result, err := docker.ExtractArchive(path, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.ImageID, "expected image ID")
	assert.NotEmpty(t, result.ManifestLayers, "expected at least one layer")
}

func TestExtractArchive_withAction(t *testing.T) {
	path := fixtureArchive("hello-world.tar")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("fixture not found at %s: %v", path, err)
	}
	actions := []extractor.ExtractAction{
		{
			ActionName:      "osRelease",
			FilePathMatches: func(p string) bool { return p == "/etc/os-release" },
			Callback: func(r io.Reader, _ int64) (interface{}, error) {
				data, err := io.ReadAll(r)
				return data, err
			},
		},
	}
	result, err := docker.ExtractArchive(path, actions)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestExtractArchive_notFound(t *testing.T) {
	_, err := docker.ExtractArchive("/nonexistent/path/foo.tar", nil)
	assert.Error(t, err)
}
