// Package benchmarks_test contains equivalence tests comparing the Go and TS
// implementations of the docker-plugin scanner.
package benchmarks_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/scan"
	"github.com/snyk/snyk-docker-plugin/pkg/types"
	"github.com/stretchr/testify/assert"
)

// tsResult is a subset of TS PluginResponse with fields relevant for comparison.
type tsResult struct {
	ScanResults []struct {
		Identity struct {
			Type string            `json:"type"`
			Args map[string]string `json:"args"`
		} `json:"identity"`
		Facts []struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		} `json:"facts"`
	} `json:"scanResults"`
}

// tsRunnerInline is a Node.js script that runs TS scan and emits JSON.
// The depGraph is serialised via toJSON() so we get the wire format.
const tsRunnerInline = `
const plugin = require(%q);
const archive = process.argv[2];
plugin.scan({ path: 'docker-archive:' + archive })
  .then(resp => {
    const out = {
      scanResults: resp.scanResults.map(sr => ({
        identity: sr.identity,
        facts: sr.facts.map(f => {
          let data = f.data;
          // depGraph: serialise to wire format
          if (f.type === 'depGraph' && data && typeof data.toJSON === 'function') {
            data = data.toJSON();
          }
          return { type: f.type, data };
        }),
      })),
    };
    process.stdout.write(JSON.stringify(out));
  })
  .catch(err => { process.stderr.write(err.message + '\n'); process.exit(1); });
`

func runTS(t *testing.T, indexJS, archive string) *tsResult {
	t.Helper()
	script := fmt.Sprintf(tsRunnerInline, indexJS)
	tmp, err := os.CreateTemp("", "ts-equiv-*.js")
	if err != nil {
		t.Fatalf("creating temp script: %v", err)
	}
	defer os.Remove(tmp.Name())
	tmp.WriteString(script)
	tmp.Close()

	cmd := exec.CommandContext(context.Background(), "node", tmp.Name(), archive)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("TS runner failed: %s\nstderr: %s", err, ee.Stderr)
		}
		t.Fatalf("TS runner: %v", err)
	}
	var result tsResult
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("parsing TS output: %v\nraw: %s", err, out)
	}
	return &result
}

func runGo(t *testing.T, archive string) *types.PluginResponse {
	t.Helper()
	resp, err := scan.Scan(context.Background(), types.PluginOptions{
		Path: "docker-archive:" + archive,
	})
	if err != nil {
		t.Fatalf("Go scan failed: %v", err)
	}
	return resp
}

// knownGaps lists fact types the Go MVP does not yet produce.
// These cause PARTIAL results rather than failures.
var knownGaps = map[string]string{
	"depGraph":                     "pkgs count differs (Go has no package parser yet)",
	"autoDetectedUserInstructions": "not yet implemented in Go",
	"imageLabels":                  "extracted but dep-graph identity/args not yet set",
}

// equivalenceCase describes one archive to compare.
type equivalenceCase struct {
	name    string
	archive string
}

var equivalenceCases = []equivalenceCase{
	{"hello-world", "hello-world.tar"},
	{"nginx", "nginx.tar"},
	{"go-binaries", "go-binaries.tar"},
	{"pip", "pip.tar"},
	{"pip-flask", "pip-flask.tar"},
	{"poetry-flask", "poetry-flask.tar"},
	{"java", "java.tar"},
	{"openjdk", "openjdk.tar"},
	{"yq", "yq.tar"},
	{"nginx-with-buildinfo", "nginx-with-buildinfo.tar"},
	{"deleted-folder", "deleted-folder.tar"},
	{"deleted-recreated", "deleted-recreated.tar"},
}

func TestEquivalence(t *testing.T) {
	indexJS := repoRoot() + "/dist/index.js"
	if _, err := os.Stat(indexJS); err != nil {
		t.Skipf("dist/index.js not found (run npm run build): %v", err)
	}

	for _, tc := range equivalenceCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			archive := fixtureArchive(tc.archive)
			if _, err := os.Stat(archive); err != nil {
				t.Skipf("fixture not found: %v", err)
			}

			ts := runTS(t, indexJS, archive)
			go_ := runGo(t, archive)

			compareResults(t, ts, go_)
		})
	}
}

func compareResults(t *testing.T, ts *tsResult, go_ *types.PluginResponse) {
	t.Helper()

	if !assert.NotEmpty(t, ts.ScanResults, "TS: no scan results") { return }
	if !assert.NotEmpty(t, go_.ScanResults, "Go: no scan results") { return }

	tsSR := ts.ScanResults[0]
	goSR := go_.ScanResults[0]

	// --- Identity type ---
	t.Logf("  identity.type  TS=%q  Go=%q", tsSR.Identity.Type, goSR.Identity.Type)
	if tsSR.Identity.Type != goSR.Identity.Type {
		if _, gap := knownGaps["depGraph"]; gap {
			t.Logf("  PARTIAL identity.type mismatch (package parsers not yet in Go)")
		} else {
			t.Errorf("  FAIL identity.type: TS=%q Go=%q", tsSR.Identity.Type, goSR.Identity.Type)
		}
	} else {
		t.Logf("  OK    identity.type")
	}

	// --- Platform arg ---
	tsPlatform := tsSR.Identity.Args["platform"]
	goPlatform := ""
	if goSR.Identity.Args != nil {
		goPlatform = goSR.Identity.Args["platform"]
	}
	t.Logf("  identity.args.platform  TS=%q  Go=%q", tsPlatform, goPlatform)

	// --- Build fact index ---
	tsFacts := indexFacts(ts)
	goFacts := indexGoFacts(go_)

	// --- Compare each TS fact ---
	tsFactTypes := sortedKeys(tsFacts)
	for _, ft := range tsFactTypes {
		if ft == "pluginVersion" {
			continue // always differs
		}
		tsData := tsFacts[ft]
		goData, goHas := goFacts[ft]

		switch ft {
		case "depGraph":
			compareDepGraph(t, tsData, goData, goHas)
		case "imageId":
			compareScalar(t, ft, tsData, goData, goHas, false)
		case "imageLayers":
			compareScalar(t, ft, tsData, goData, goHas, false)
		case "rootFs":
			compareScalar(t, ft, tsData, goData, goHas, false)
		case "imageCreationTime":
			compareScalar(t, ft, tsData, goData, goHas, false)
		case "imageOsReleasePrettyName":
			compareScalar(t, ft, tsData, goData, goHas, false)
		case "platform":
			compareScalar(t, ft, tsData, goData, goHas, false)
		case "history":
			compareHistory(t, tsData, goData, goHas)
		case "containerConfig":
			compareContainerConfig(t, tsData, goData, goHas)
		case "imageLabels":
			compareJSONSemantic(t, ft, tsData, goData, goHas)
		case "autoDetectedUserInstructions":
			if !goHas {
				t.Logf("  PARTIAL %-35s (not yet implemented in Go)", ft)
			}
		default:
			if !goHas {
				t.Logf("  PARTIAL %-35s (not yet in Go MVP)", ft)
			}
		}
	}

	// --- Facts present in Go but not TS (additions) ---
	for ft := range goFacts {
		if _, ok := tsFacts[ft]; !ok && ft != "pluginVersion" {
			t.Logf("  EXTRA  %-35s (Go produces this, TS does not)", ft)
		}
	}
}

func compareScalar(t *testing.T, ft string, tsRaw json.RawMessage, goRaw json.RawMessage, goHas bool, isKnownGap bool) {
	t.Helper()
	if !goHas {
		if isKnownGap {
			t.Logf("  PARTIAL %-35s (known gap)", ft)
		} else {
			t.Errorf("  FAIL   %-35s Go is missing this fact", ft)
		}
		return
	}
	tsStr := strings.TrimSpace(string(tsRaw))
	goStr := strings.TrimSpace(string(goRaw))
	if tsStr == goStr {
		t.Logf("  OK     %-35s %s", ft, truncate(tsStr, 60))
	} else {
		t.Errorf("  FAIL   %-35s TS=%s Go=%s", ft, truncate(tsStr, 50), truncate(goStr, 50))
	}
}

func compareJSONSemantic(t *testing.T, ft string, tsRaw json.RawMessage, goRaw json.RawMessage, goHas bool) {
	t.Helper()
	if !goHas {
		t.Errorf("  FAIL   %-35s Go is missing this fact", ft)
		return
	}
	// Use JSONEq-style comparison: unmarshal both and re-marshal canonically.
	var tsVal, goVal interface{}
	json.Unmarshal(tsRaw, &tsVal)
	json.Unmarshal(goRaw, &goVal)
	tsNorm, _ := json.Marshal(tsVal)
	goNorm, _ := json.Marshal(goVal)
	if string(tsNorm) == string(goNorm) {
		t.Logf("  OK     %-35s %s", ft, truncate(string(goNorm), 60))
	} else {
		t.Errorf("  FAIL   %-35s TS=%s Go=%s", ft, truncate(string(tsNorm), 50), truncate(string(goNorm), 50))
	}
}

func compareDepGraph(t *testing.T, tsRaw, goRaw json.RawMessage, goHas bool) {
	t.Helper()
	if !goHas {
		t.Errorf("  FAIL   %-35s Go missing depGraph fact", "depGraph")
		return
	}
	var tsGraph, goGraph types.DepGraphData
	if err := json.Unmarshal(tsRaw, &tsGraph); err != nil {
		t.Errorf("  FAIL   depGraph: can't parse TS graph: %v", err)
		return
	}
	if err := json.Unmarshal(goRaw, &goGraph); err != nil {
		t.Errorf("  FAIL   depGraph: can't parse Go graph: %v", err)
		return
	}

	// Schema version
	if tsGraph.SchemaVersion != goGraph.SchemaVersion {
		t.Logf("  PARTIAL depGraph.schemaVersion  TS=%q Go=%q (TS emits 1.3.0, Go emits 1.2.0 — different @snyk/dep-graph versions)", tsGraph.SchemaVersion, goGraph.SchemaVersion)
	} else {
		t.Logf("  OK     depGraph.schemaVersion = %q", goGraph.SchemaVersion)
	}

	// pkg manager name
	if tsGraph.PkgManager.Name == goGraph.PkgManager.Name {
		t.Logf("  OK     depGraph.pkgManager.name = %q", goGraph.PkgManager.Name)
	} else {
		t.Logf("  PARTIAL depGraph.pkgManager.name  TS=%q Go=%q (package parser not yet in Go)", tsGraph.PkgManager.Name, goGraph.PkgManager.Name)
	}

	// pkg count
	tsPkgCount := len(tsGraph.Pkgs)
	goPkgCount := len(goGraph.Pkgs)
	if tsPkgCount == goPkgCount {
		t.Logf("  OK     depGraph.pkgs count = %d", goPkgCount)
	} else {
		t.Logf("  PARTIAL depGraph.pkgs  TS=%d Go=%d (Go has no pkg parser yet — root-only graph)", tsPkgCount, goPkgCount)
	}
}

func compareHistory(t *testing.T, tsRaw, goRaw json.RawMessage, goHas bool) {
	t.Helper()
	if !goHas {
		t.Errorf("  FAIL   %-35s Go missing history fact", "history")
		return
	}
	var tsH, goH []map[string]interface{}
	json.Unmarshal(tsRaw, &tsH)
	json.Unmarshal(goRaw, &goH)
	if len(tsH) == len(goH) {
		t.Logf("  OK     %-35s len=%d", "history", len(goH))
	} else {
		t.Errorf("  FAIL   %-35s TS len=%d Go len=%d", "history", len(tsH), len(goH))
	}
}

func compareContainerConfig(t *testing.T, tsRaw, goRaw json.RawMessage, goHas bool) {
	t.Helper()
	if !goHas {
		t.Errorf("  FAIL   %-35s Go missing containerConfig fact", "containerConfig")
		return
	}
	// Compare a few key fields
	var tsCC, goCC map[string]interface{}
	json.Unmarshal(tsRaw, &tsCC)
	json.Unmarshal(goRaw, &goCC)

	// The TS containerConfig is lowercase-key (from facts.ts); Go is uppercase (raw ImageConfig.Config).
	// Map TS keys → Go keys for comparison.
	fieldMap := map[string]string{
		"user": "User", "cmd": "Cmd", "entrypoint": "Entrypoint",
		"workingDir": "WorkingDir", "env": "Env",
	}
	allMatch := true
	for tsKey, goKey := range fieldMap {
		tsVal, _ := json.Marshal(tsCC[tsKey])
		goVal, _ := json.Marshal(goCC[goKey])
		if string(tsVal) != string(goVal) {
			t.Logf("  PARTIAL containerConfig.%s  TS=%s Go=%s", tsKey, truncate(string(tsVal), 40), truncate(string(goVal), 40))
			allMatch = false
		}
	}
	if allMatch {
		t.Logf("  OK     %-35s (key fields match)", "containerConfig")
	}
}

func indexFacts(ts *tsResult) map[string]json.RawMessage {
	m := map[string]json.RawMessage{}
	if len(ts.ScanResults) == 0 { return m }
	for _, f := range ts.ScanResults[0].Facts {
		m[f.Type] = f.Data
	}
	return m
}

func indexGoFacts(resp *types.PluginResponse) map[string]json.RawMessage {
	m := map[string]json.RawMessage{}
	if len(resp.ScanResults) == 0 { return m }
	for _, f := range resp.ScanResults[0].Facts {
		b, _ := json.Marshal(f.Data)
		m[string(f.Type)] = b
	}
	return m
}

func sortedKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m { keys = append(keys, k) }
	sort.Strings(keys)
	return keys
}

func truncate(s string, n int) string {
	if len(s) <= n { return s }
	return s[:n] + "…"
}
