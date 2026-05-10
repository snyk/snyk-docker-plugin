// Package python provides Python application dependency scanning.
// It mirrors lib/analyzer/applications/python/pip.ts.
package python

import (
	"path/filepath"
	"strings"

	"github.com/snyk/snyk-docker-plugin/pkg/depgraph"
	"github.com/snyk/snyk-docker-plugin/pkg/pythonparser"
	"github.com/snyk/snyk-docker-plugin/pkg/types"
)

// AppScanResult is a single per-file application scan result.
type AppScanResult struct {
	Identity types.Identity
	Facts    []types.Fact
}

// ScanPip builds dep-graphs for all requirements.txt + site-packages combos.
// pathToContent is a map of absolute paths to raw file bytes.
// It returns one AppScanResult per requirements.txt that has at least one dep.
func ScanPip(pathToContent map[string][]byte) []AppScanResult {
	// Separate requirements files from dist-info METADATA files.
	requirementsFiles := map[string][]byte{}
	for path, content := range pathToContent {
		if filepath.Base(path) == "requirements.txt" {
			requirementsFiles[path] = content
		}
	}

	// Parse all METADATA files (from all site-packages directories in layers).
	metadata := pythonparser.ParseSitePackagesMetadata(pathToContent)

	// Without metadata we cannot build dep-graphs (mirrors TS behaviour).
	if len(metadata) == 0 {
		return nil
	}

	var results []AppScanResult
	for _, entry := range requireirementsFilesSorted(requirementsFiles) {
		reqPath, reqContent := entry.path, entry.content
		reqs, err := pythonparser.ParseRequirementsTxt(string(reqContent))
		if err != nil || len(reqs) == 0 {
			continue
		}
		dg := buildDepGraph(reqPath, reqs, metadata)
		if dg == nil {
			continue
		}
		results = append(results, AppScanResult{
			Identity: types.Identity{
				Type:       "pip",
				TargetFile: reqPath,
			},
			Facts: []types.Fact{
				{Type: types.FactDepGraph, Data: *dg},
			},
		})
	}
	return results
}

// requirementsFilesSorted returns requirements files in deterministic order.
func requireirementsFilesSorted(m map[string][]byte) []requirementsEntry {
	out := make([]requirementsEntry, 0, len(m))
	for k, v := range m {
		out = append(out, requirementsEntry{k, v})
	}
	// Sort by path for deterministic output.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].path < out[j-1].path; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

type requirementsEntry struct {
	path    string
	content []byte
}

// buildDepGraph builds a DepGraphData for a single requirements file.
func buildDepGraph(
	reqPath string,
	reqs []pythonparser.Requirement,
	metadata pythonparser.PythonMetadataFiles,
) *types.DepGraphData {
	visited := map[string]bool{}
	deps := resolveRequirements(reqs, metadata, visited, 0)
	if len(deps) == 0 {
		return nil
	}
	dg := depgraph.FromDepTree("pip", reqPath, "", deps)
	return &dg
}

// resolveRequirements resolves a list of requirements to DepInfo entries,
// following transitive dependencies. maxDepth prevents infinite recursion.
const maxPipDepth = 10

func resolveRequirements(
	reqs []pythonparser.Requirement,
	metadata pythonparser.PythonMetadataFiles,
	visited map[string]bool,
	depth int,
) []depgraph.DepInfo {
	if depth > maxPipDepth {
		return nil
	}
	var result []depgraph.DepInfo
	for _, req := range reqs {
		pkg := findPackage(req, metadata)
		if pkg == nil {
			continue
		}
		nodeKey := pkg.Name + "@" + pkg.Version
		if visited[nodeKey] {
			continue
		}
		visited[nodeKey] = true
		// Only traverse non-extra-gated deps.
		var transitiveDeps []pythonparser.Requirement
		for _, d := range pkg.Dependencies {
			if !hasExtraMarker(d, req.Extras) {
				transitiveDeps = append(transitiveDeps, d)
			}
		}
		children := resolveRequirements(transitiveDeps, metadata, visited, depth+1)
		result = append(result, depgraph.DepInfo{
			Name:    pkg.Name,
			Version: pkg.Version,
			Deps:    children,
		})
	}
	return result
}

// hasExtraMarker returns true if the requirement's extras intersect the
// requestedExtras — i.e. we should NOT traverse this dep (it's optional).
// Wait — inverted: if the dep has no extra env markers it IS traversed;
// if it has extras but none match, skip it.
// Actually we want to skip deps that require extras we didn't ask for.
// This mirrors TS shouldTraverse().
func hasExtraMarker(dep pythonparser.Requirement, requestedExtras []string) bool {
	// If the dep has no extras it is always included — return false (don't skip).
	if len(dep.Extras) == 0 {
		return false
	}
	// If the parent req requested those extras, include them.
	for _, de := range dep.Extras {
		for _, re := range requestedExtras {
			if strings.EqualFold(de, re) {
				return false // include
			}
		}
	}
	return true // skip
}

// findPackage finds the best-matching package for a requirement in metadata.
func findPackage(req pythonparser.Requirement, metadata pythonparser.PythonMetadataFiles) *pythonparser.PythonPackage {
	matches := metadata[req.Name]
	if len(matches) == 0 {
		return nil
	}
	if len(matches) == 1 || req.Version == "" {
		return &matches[0]
	}
	// Try to find the version that satisfies the specifier.
	for i := range matches {
		if versionSatisfies(matches[i].Version, req.Specifier, req.Version) {
			return &matches[i]
		}
	}
	// Fallback to first.
	return &matches[0]
}

// versionSatisfies is a simple version comparator sufficient for pip specifiers.
// Full PEP 440 semantics are not required — just string equality for ==,
// and lexicographic comparisons for >=, <=, >, <.
func versionSatisfies(have string, spec pythonparser.Specifier, want string) bool {
	switch spec {
	case pythonparser.SpecEq, pythonparser.SpecAEq:
		return have == want
	case pythonparser.SpecNe:
		return have != want
	case pythonparser.SpecGte:
		return have >= want
	case pythonparser.SpecLte:
		return have <= want
	case pythonparser.SpecGt:
		return have > want
	case pythonparser.SpecLt:
		return have < want
	case pythonparser.SpecCom:
		// ~= X.Y means >= X.Y, == X.* — approximate, use >= for MVP.
		return have >= want
	}
	return true
}
