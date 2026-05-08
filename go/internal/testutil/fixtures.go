// Package testutil provides shared test helpers for the Go implementation.
package testutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// RepoRoot returns the absolute path to the repository root.
func RepoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	// go/internal/testutil/fixtures.go → ../../..
	return filepath.Join(filepath.Dir(file), "..", "..", "..")
}

// FixturesDir returns the path to the test/fixtures directory.
func FixturesDir() string {
	return filepath.Join(RepoRoot(), "test", "fixtures")
}

// FixturePath joins the fixtures dir with the given path components.
func FixturePath(parts ...string) string {
	args := append([]string{FixturesDir()}, parts...)
	return filepath.Join(args...)
}

// ReadFixture reads a file from the fixtures directory.
func ReadFixture(t *testing.T, parts ...string) []byte {
	t.Helper()
	path := FixturePath(parts...)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", path, err)
	}
	return data
}
