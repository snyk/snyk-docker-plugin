// Package ruby provides Ruby Gemfile.lock scanning.
// It mirrors lib/analyzer/applications/ruby.ts.
// The TypeScript plugin collects Gemfile.lock as imageManifestFiles — no
// dep-graph is generated. This implementation follows the same behaviour.
package ruby

import (
	"encoding/base64"
	"path/filepath"

	"github.com/snyk/snyk-docker-plugin/pkg/types"
)

// AppScanResult is one scan result per Gemfile.lock.
type AppScanResult struct {
	Identity types.Identity
	Facts    []types.Fact
}

// ScanGemfile collects Gemfile.lock files and returns them as
// imageManifestFiles facts. No dep-graph is generated (mirrors TS behaviour).
// pathToContent maps absolute file paths to raw bytes.
func ScanGemfile(pathToContent map[string][]byte) []AppScanResult {
	var results []AppScanResult

	for path, content := range pathToContent {
		if filepath.Base(path) != "Gemfile.lock" {
			continue
		}

		manifestFile := types.ManifestFile{
			Name:     "Gemfile.lock",
			Path:     path,
			Contents: base64.StdEncoding.EncodeToString(content),
		}

		results = append(results, AppScanResult{
			Identity: types.Identity{
				Type:       "rubygems",
				TargetFile: path,
			},
			Facts: []types.Fact{
				{Type: types.FactImageManifestFiles, Data: []types.ManifestFile{manifestFile}},
			},
		})
	}
	return results
}
