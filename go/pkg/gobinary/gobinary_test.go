package gobinary_test

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/gobinary"
	"github.com/snyk/snyk-docker-plugin/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- FilePathMatches ---

func TestFilePathMatches_validBinaryPaths(t *testing.T) {
	for _, path := range []string{
		"/usr/bin/myapp",
		"/opt/server",
		"/app/bin/myservice",
		"/usr/local/bin/tool",
	} {
		assert.True(t, gobinary.FilePathMatches(path), "should match: %s", path)
	}
}

func TestFilePathMatches_ignoredDirectories(t *testing.T) {
	for _, path := range []string{
		"/etc/passwd",
		"/etc/hosts",
		"/tmp/something",
		"/var/log/app",
		"/proc/1/exe",
		"/sys/kernel/config",
		"/dev/null",
		"/run/lock",
		"/root/mybin",
		"/home/user/app",
		"/boot/vmlinuz",
		"/media/disk/app",
		"/mnt/vol/app",
		"/sbin/init",
	} {
		assert.False(t, gobinary.FilePathMatches(path), "should not match: %s", path)
	}
}

func TestFilePathMatches_filesWithExtensionsSkipped(t *testing.T) {
	for _, path := range []string{
		"/usr/bin/app.py",
		"/usr/local/bin/server.sh",
		"/opt/app.jar",
		"/usr/lib/app.so",
	} {
		assert.False(t, gobinary.FilePathMatches(path), "should not match (has extension): %s", path)
	}
}

// --- ReadBuildInfo (uses the real test binary) ---

func TestReadBuildInfo_self(t *testing.T) {
	exe, err := os.Executable()
	require.NoError(t, err)
	info, err := gobinary.ReadBuildInfo(exe)
	require.NoError(t, err)
	assert.NotEmpty(t, info.GoVersion)
	assert.Contains(t, info.GoVersion, runtime.Version()[:6])
}

func TestReadBuildInfo_nonBinary(t *testing.T) {
	// A regular text file should fail gracefully.
	tmp, err := os.CreateTemp("", "notabinary-*")
	require.NoError(t, err)
	defer os.Remove(tmp.Name())
	tmp.WriteString("hello world") //nolint:errcheck
	tmp.Close()

	_, err = gobinary.ReadBuildInfo(tmp.Name())
	assert.Error(t, err)
}

// --- ScanGoBinaries ---

func TestScanGoBinaries_empty(t *testing.T) {
	results := gobinary.ScanGoBinaries(map[string][]byte{})
	assert.Empty(t, results)
}

func TestScanGoBinaries_nonBinaryData(t *testing.T) {
	// Pass non-binary data for a path that matches — should not panic and return nothing.
	results := gobinary.ScanGoBinaries(map[string][]byte{
		"/usr/bin/notabinary": []byte("#!/bin/bash\necho hello"),
	})
	assert.Empty(t, results)
}

func TestScanGoBinaries_extensionSkipped(t *testing.T) {
	// Even if the data is valid, .sh files should not be processed.
	exe, _ := os.ReadFile(os.Args[0])
	results := gobinary.ScanGoBinaries(map[string][]byte{
		"/usr/bin/app.sh": exe,
	})
	assert.Empty(t, results)
}

func TestScanGoBinaries_ignoredDirSkipped(t *testing.T) {
	exe, err := os.ReadFile(os.Args[0])
	require.NoError(t, err)
	results := gobinary.ScanGoBinaries(map[string][]byte{
		"/tmp/myapp": exe, // /tmp is ignored
	})
	assert.Empty(t, results)
}

func TestScanGoBinaries_realBinaryProducesResult(t *testing.T) {
	exe, err := os.ReadFile(os.Args[0])
	require.NoError(t, err)
	results := gobinary.ScanGoBinaries(map[string][]byte{
		"/usr/local/bin/testbinary": exe,
	})
	require.Len(t, results, 1, "test binary should produce one result")
	r := results[0]
	assert.Equal(t, "gomodules", r.Identity.Type)
	assert.Equal(t, "/usr/local/bin/testbinary", r.Identity.TargetFile)
	require.Len(t, r.Facts, 1)
	assert.Equal(t, types.FactDepGraph, r.Facts[0].Type)

	dg, ok := r.Facts[0].Data.(types.DepGraphData)
	require.True(t, ok)
	assert.Equal(t, "gomodules", dg.PkgManager.Name)
	// Should have stdlib at least.
	pkgNames := map[string]bool{}
	for _, p := range dg.Pkgs {
		pkgNames[p.Info.Name] = true
	}
	assert.True(t, pkgNames["stdlib"], "stdlib should be in the dep-graph")
}

func TestScanGoBinaries_multipleBinaries(t *testing.T) {
	exe, err := os.ReadFile(os.Args[0])
	require.NoError(t, err)
	results := gobinary.ScanGoBinaries(map[string][]byte{
		"/usr/local/bin/app1": exe,
		"/usr/local/bin/app2": exe,
	})
	assert.Len(t, results, 2)
}

// --- ScanGoBinariesFromFiles ---

func TestScanGoBinariesFromFiles_empty(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gobinary-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	results := gobinary.ScanGoBinariesFromFiles(tmpDir)
	assert.Empty(t, results)
}

func TestScanGoBinariesFromFiles_realBinary(t *testing.T) {
	// Copy the test binary to a temp directory and scan it.
	tmpDir, err := os.MkdirTemp("", "gobinary-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	exe, err := os.ReadFile(os.Args[0])
	require.NoError(t, err)

	dst := tmpDir + "/usr/local/bin"
	require.NoError(t, os.MkdirAll(dst, 0o755))
	require.NoError(t, os.WriteFile(dst+"/testapp", exe, 0o755))

	results := gobinary.ScanGoBinariesFromFiles(tmpDir)
	require.Len(t, results, 1)
	assert.Equal(t, "gomodules", results[0].Identity.Type)
}

func TestReadBuildInfoFromReader_self(t *testing.T) {
	exe, err := os.Open(os.Args[0])
	require.NoError(t, err)
	defer exe.Close()
	bi, err := gobinary.ReadBuildInfoFromReader(exe)
	require.NoError(t, err)
	assert.NotNil(t, bi)
	assert.NotEmpty(t, bi.GoVersion)
}

func TestReadBuildInfoFromReader_nonBinary(t *testing.T) {
	r := strings.NewReader("not a binary")
	_, err := gobinary.ReadBuildInfoFromReader(r)
	assert.Error(t, err)
}

func TestScanGoBinaries_buildScanResultWithDeps(t *testing.T) {
	// Real binary has stdlib dep; verify the dep-graph has it.
	exe, err := os.ReadFile(os.Args[0])
	require.NoError(t, err)
	results := gobinary.ScanGoBinaries(map[string][]byte{
		"/usr/local/bin/app": exe,
	})
	require.Len(t, results, 1)
	dg, ok := results[0].Facts[0].Data.(types.DepGraphData)
	require.True(t, ok)
	// At minimum root + stdlib nodes should be in the graph.
	assert.GreaterOrEqual(t, len(dg.Graph.Nodes), 2)
}

func TestFilePathMatches_exactIgnoredDir(t *testing.T) {
	// Exactly /tmp (no trailing slash) — should also be rejected.
	assert.False(t, gobinary.FilePathMatches("/tmp"))
	assert.False(t, gobinary.FilePathMatches("/etc"))
}

func TestFilePathMatches_subpathOfIgnoredDir(t *testing.T) {
	// /etc/init.d/something — ignored because under /etc.
	assert.False(t, gobinary.FilePathMatches("/etc/init.d/myservice"))
}

func TestScanGoBinariesFromFiles_skipExtensionFiles(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gobinary-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Write a .sh file — should be skipped even if it contains Go binary content.
	dst := tmpDir + "/usr/local/bin"
	require.NoError(t, os.MkdirAll(dst, 0o755))

	exe, err := os.ReadFile(os.Args[0])
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(dst+"/script.sh", exe, 0o755))

	results := gobinary.ScanGoBinariesFromFiles(tmpDir)
	assert.Empty(t, results, "files with extension should be skipped")
}
