package benchmarks_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/snyk/snyk-docker-plugin/pkg/extractor"
	"github.com/snyk/snyk-docker-plugin/pkg/extractor/docker"
)

// repoRoot returns the repo root relative to this file.
func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	// go/benchmarks/perf_compare_test.go → go/benchmarks → go → repo root
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func fixtureArchive(name string) string {
	return filepath.Join(repoRoot(), "test", "fixtures", "docker-archives", "docker-save", name)
}

// corpus is the set of local archives used for comparison.
var corpus = []struct {
	name string
	file string
}{
	{"hello-world", "hello-world.tar"},
	{"nginx", "nginx.tar"},
	{"go-binaries", "go-binaries.tar"},
	{"pip", "pip.tar"},
	{"pip-flask", "pip-flask.tar"},
	{"poetry-flask", "poetry-flask.tar"},
}

// --- Go benchmarks ---

func benchmarkGoExtract(b *testing.B, archive string) {
	b.Helper()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := docker.ExtractArchive(archive, []extractor.ExtractAction{
			{
				ActionName:      "osRelease",
				FilePathMatches: func(p string) bool { return p == "/etc/os-release" },
			},
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGoExtract_HelloWorld(b *testing.B) { benchmarkGoExtract(b, fixtureArchive("hello-world.tar")) }
func BenchmarkGoExtract_Nginx(b *testing.B)      { benchmarkGoExtract(b, fixtureArchive("nginx.tar")) }
func BenchmarkGoExtract_GoBinaries(b *testing.B) { benchmarkGoExtract(b, fixtureArchive("go-binaries.tar")) }
func BenchmarkGoExtract_Pip(b *testing.B)        { benchmarkGoExtract(b, fixtureArchive("pip.tar")) }
func BenchmarkGoExtract_PipFlask(b *testing.B)   { benchmarkGoExtract(b, fixtureArchive("pip-flask.tar")) }
func BenchmarkGoExtract_PoetryFlask(b *testing.B) { benchmarkGoExtract(b, fixtureArchive("poetry-flask.tar")) }

// --- Head-to-head comparison ---

// tsRunnerScript is the inline Node.js runner (written to a temp file).
const tsRunnerScript = `
const plugin = require(%q);
const path = process.argv[2];
const start = process.hrtime.bigint();
plugin.scan({ path: 'docker-archive:' + path })
  .then(() => {
    const ns = Number(process.hrtime.bigint() - start);
    console.log(JSON.stringify({ ns }));
  })
  .catch(err => {
    console.error(err.message);
    process.exit(1);
  });
`

type timingResult struct {
	Name   string
	GoNs   int64
	TSNs   int64
	RatioX float64 // TS/Go — >1 means Go is faster
}

func timeGo(archive string, rounds int) (int64, error) {
	var total int64
	for i := 0; i < rounds; i++ {
		start := time.Now()
		_, err := docker.ExtractArchive(archive, nil)
		if err != nil {
			return 0, err
		}
		total += time.Since(start).Nanoseconds()
	}
	return total / int64(rounds), nil
}

func timeTS(indexJS, archive string, rounds int) (int64, error) {
	// Write runner script to temp file.
	script := fmt.Sprintf(tsRunnerScript, indexJS)
	tmpScript, err := os.CreateTemp("", "ts-runner-*.js")
	if err != nil {
		return 0, err
	}
	defer os.Remove(tmpScript.Name())
	if _, err := tmpScript.WriteString(script); err != nil {
		return 0, err
	}
	tmpScript.Close()

	var total int64
	for i := 0; i < rounds; i++ {
		start := time.Now()
		cmd := exec.CommandContext(context.Background(), "node", tmpScript.Name(), archive)
		out, err := cmd.Output()
		elapsed := time.Since(start).Nanoseconds()
		if err != nil {
			return 0, fmt.Errorf("node runner failed: %w\noutput: %s", err, out)
		}
		var result struct{ Ns int64 }
		if err := json.Unmarshal(out, &result); err != nil {
			return 0, fmt.Errorf("parsing ts output: %w (raw: %s)", err, out)
		}
		_ = elapsed
		total += result.Ns
	}
	return total / int64(rounds), nil
}

func TestComparePerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping perf comparison in short mode")
	}

	indexJS := filepath.Join(repoRoot(), "dist", "index.js")
	if _, err := os.Stat(indexJS); err != nil {
		t.Skipf("dist/index.js not found (run npm run build): %v", err)
	}

	const rounds = 3
	var results []timingResult

	for _, c := range corpus {
		archive := fixtureArchive(c.file)
		if _, err := os.Stat(archive); err != nil {
			t.Logf("SKIP %s: fixture not found (%v)", c.name, err)
			continue
		}

		goNs, err := timeGo(archive, rounds)
		if err != nil {
			t.Logf("SKIP %s (Go error): %v", c.name, err)
			continue
		}

		tsNs, err := timeTS(indexJS, archive, rounds)
		if err != nil {
			t.Logf("SKIP %s (TS error): %v", c.name, err)
			continue
		}

		ratio := float64(tsNs) / float64(goNs)
		results = append(results, timingResult{
			Name:   c.name,
			GoNs:   goNs,
			TSNs:   tsNs,
			RatioX: ratio,
		})
	}

	// Print table.
	t.Logf("\n%-20s  %12s  %12s  %8s", "Image", "Go (ms)", "TS (ms)", "Ratio TS/Go")
	t.Logf("%-20s  %12s  %12s  %8s", "-----", "-------", "-------", "-----------")
	for _, r := range results {
		goMs := float64(r.GoNs) / 1e6
		tsMs := float64(r.TSNs) / 1e6
		flag := ""
		if r.RatioX < 0.5 {
			flag = " ⚠ Go >2× slower than TS"
		} else if r.RatioX > 1 {
			flag = " ✓ Go faster"
		}
		t.Logf("%-20s  %12.1f  %12.1f  %8.2f×%s", r.Name, goMs, tsMs, r.RatioX, flag)
	}

	// Soft assertion: Go must not be more than 2× slower than TS on any image.
	for _, r := range results {
		if r.RatioX < 0.5 {
			t.Errorf("%s: Go is >2× slower than TS (ratio %.2f×)", r.Name, r.RatioX)
		}
	}
}
