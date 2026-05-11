package main_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// builtBinary is the path to the binary compiled by TestMain.
var builtBinary string

// TestMain compiles the binary once for the entire package test run.
func TestMain(m *testing.M) {
	_, srcFile, _, _ := runtime.Caller(0)
	srcDir := filepath.Dir(srcFile)

	tmpDir, err := os.MkdirTemp("", "snyk-docker-plugin-test-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "mkdirtemp: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	builtBinary = filepath.Join(tmpDir, "snyk-docker-plugin")
	cmd := exec.Command("go", "build", "-o", builtBinary, ".")
	cmd.Dir = srcDir
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "building binary: %v\n", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// run executes the binary with the given stdin and args, returning stdout,
// stderr and exit code.
func run(t *testing.T, stdin string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command(builtBinary, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("unexpected exec error: %v", err)
		}
	}
	return outBuf.String(), errBuf.String(), exitCode
}

// repoRoot returns the snyk-docker-plugin repo root.
func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	// cmd/snyk-docker-plugin/main_test.go → 3 levels up = repo root
	return filepath.Join(filepath.Dir(file), "..", "..", "..")
}

// archiveFixture returns path to a docker-archive fixture.
func archiveFixture(name string) string {
	return filepath.Join(repoRoot(), "test", "fixtures", "docker-archives", "docker-save", name)
}

// ---- scan mode tests -------------------------------------------------------

func TestBinary_scanMode_emptyStdin(t *testing.T) {
	// Empty stdin → no path → scan.Scan returns error → exit 1.
	_, _, code := run(t, "")
	assert.Equal(t, 1, code)
}

func TestBinary_scanMode_invalidJSON(t *testing.T) {
	_, stderr, code := run(t, "not-json")
	assert.Equal(t, 1, code)
	assert.Contains(t, stderr, "decoding options")
}

func TestBinary_scanMode_validArchive(t *testing.T) {
	path := archiveFixture("hello-world.tar")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("fixture not found: %v", err)
	}
	input, _ := json.Marshal(map[string]string{"path": path})
	stdout, stderr, code := run(t, string(input))
	require.Equal(t, 0, code, "expected success; stderr: %s", stderr)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(stdout), &resp))
	assert.Contains(t, resp, "scanResults")
}

func TestBinary_scanMode_outputIsValidJSON(t *testing.T) {
	path := archiveFixture("hello-world.tar")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("fixture not found: %v", err)
	}
	input, _ := json.Marshal(map[string]string{"path": path})
	stdout, _, code := run(t, string(input))
	require.Equal(t, 0, code)

	var v interface{}
	require.NoError(t, json.Unmarshal([]byte(stdout), &v), "stdout must be valid JSON")
}

func TestBinary_scanMode_emptyOptionsObject(t *testing.T) {
	// {} is valid JSON but path is empty — should fail with exit 1.
	_, stderr, code := run(t, "{}")
	assert.Equal(t, 1, code)
	assert.NotEmpty(t, stderr)
}

func TestBinary_scanMode_nonExistentPath(t *testing.T) {
	input, _ := json.Marshal(map[string]string{"path": "/no/such/archive.tar"})
	_, stderr, code := run(t, string(input))
	assert.Equal(t, 1, code)
	assert.NotEmpty(t, stderr)
}

func TestBinary_scanMode_stderrOnError(t *testing.T) {
	// On error: nothing on stdout, something on stderr.
	stdout, stderr, code := run(t, "not-json")
	assert.Equal(t, 1, code)
	assert.Empty(t, stdout, "stdout should be empty on error")
	assert.NotEmpty(t, stderr)
}

func TestBinary_scanMode_scanResultsStructure(t *testing.T) {
	path := archiveFixture("hello-world.tar")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("fixture not found: %v", err)
	}
	input, _ := json.Marshal(map[string]string{"path": path})
	stdout, _, code := run(t, string(input))
	require.Equal(t, 0, code)

	var resp struct {
		ScanResults []struct {
			Identity struct{ Type string `json:"type"` } `json:"identity"`
			Facts []struct{ Type string `json:"type"` } `json:"facts"`
		} `json:"scanResults"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &resp))
	require.NotEmpty(t, resp.ScanResults)
	assert.NotEmpty(t, resp.ScanResults[0].Identity.Type)
	assert.NotEmpty(t, resp.ScanResults[0].Facts)
}

// ---- display mode tests ----------------------------------------------------

func minimalDisplayInput() string {
	return `{"scanResults":[],"testResults":[],"errors":[],"options":{"path":"test-image"}}`
}

func TestBinary_displayMode_minimalInput(t *testing.T) {
	_, _, code := run(t, minimalDisplayInput(), "--display")
	assert.Equal(t, 0, code)
}

func TestBinary_displayMode_invalidJSON(t *testing.T) {
	_, stderr, code := run(t, "not-json", "--display")
	assert.Equal(t, 1, code)
	assert.Contains(t, stderr, "decoding display input")
}

func TestBinary_displayMode_emptyStdin(t *testing.T) {
	_, stderr, code := run(t, "", "--display")
	assert.Equal(t, 1, code)
	assert.NotEmpty(t, stderr)
}

func TestBinary_displayMode_outputIsString(t *testing.T) {
	stdout, _, code := run(t, minimalDisplayInput(), "--display")
	assert.Equal(t, 0, code)
	// Output is a plain string, not a JSON value.
	var js interface{}
	err := json.Unmarshal([]byte(stdout), &js)
	assert.Error(t, err, "display output should not be valid JSON")
}

func TestBinary_displayMode_withOneTestResult(t *testing.T) {
	input := `{
		"scanResults": [{"identity":{"type":"rpm"},"target":{"image":"myimage"},"facts":[]}],
		"testResults": [{
			"org": "myorg",
			"issues": [],
			"issuesData": {},
			"depGraphData": {},
			"docker": {}
		}],
		"errors": [],
		"options": {"path": "myimage"}
	}`
	stdout, _, code := run(t, input, "--display")
	assert.Equal(t, 0, code)
	assert.NotEmpty(t, stdout)
}

func TestBinary_displayMode_pathAppearsInOutput(t *testing.T) {
	// Display iterates testResults; image name only appears when there is a
	// matching scan result + test result pair.
	input := fmt.Sprintf(`{
		"scanResults": [{"identity":{"type":"deb"},"target":{"image":%q},"facts":[]}],
		"testResults": [{"org":"o","issues":[],"issuesData":{},"depGraphData":{},"docker":{}}],
		"errors": [],
		"options": {"path": %q}
	}`, "my-unique-image-name", "my-unique-image-name")
	stdout, _, code := run(t, input, "--display")
	assert.Equal(t, 0, code)
	assert.Contains(t, stdout, "my-unique-image-name")
}

func TestBinary_displayMode_errorsAppearsInOutput(t *testing.T) {
	// Errors appear in the output only when paired with test results.
	input := `{
		"scanResults": [{"identity":{"type":"deb"},"target":{"image":"img"},"facts":[]}],
		"testResults": [{"org":"o","issues":[],"issuesData":{},"depGraphData":{},"docker":{}}],
		"errors": ["something went wrong"],
		"options": {"path": "img"}
	}`
	_, _, code := run(t, input, "--display")
	// Just ensure it doesn't crash; error rendering is tested in pkg/display.
	assert.Equal(t, 0, code)
}

// ---- argument routing -------------------------------------------------------

func TestBinary_unknownArgTriggersScanMode(t *testing.T) {
	// Only "--display" as args[0] routes to display; anything else is scan mode.
	// Empty path exits 1.
	_, _, code := run(t, "{}", "--some-unknown-flag")
	assert.Equal(t, 1, code)
}

func TestBinary_displayFlagFirstArgActivatesDisplayMode(t *testing.T) {
	stdout, _, code := run(t, minimalDisplayInput(), "--display")
	assert.Equal(t, 0, code)
	// If it fell through to scan mode it would exit 1 (no path).
	_ = stdout
}
