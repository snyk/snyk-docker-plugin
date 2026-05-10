package python

import (
	"bytes"
	"path/filepath"
	"strings"

	"github.com/snyk/snyk-docker-plugin/pkg/depgraph"
	"github.com/snyk/snyk-docker-plugin/pkg/types"
)

// ScanPoetry parses pyproject.toml + poetry.lock pairs and returns one
// AppScanResult per discovered project directory.
// pathToContent maps absolute file paths to raw bytes.
func ScanPoetry(pathToContent map[string][]byte) []AppScanResult {
	// Group files by directory.
	type dirFiles struct {
		pyproject []byte
		poetryLock []byte
	}
	byDir := map[string]*dirFiles{}

	for path, content := range pathToContent {
		base := filepath.Base(path)
		dir := filepath.Dir(path)
		switch base {
		case "pyproject.toml":
			if byDir[dir] == nil {
				byDir[dir] = &dirFiles{}
			}
			byDir[dir].pyproject = content
		case "poetry.lock":
			if byDir[dir] == nil {
				byDir[dir] = &dirFiles{}
			}
			byDir[dir].poetryLock = content
		}
	}

	var results []AppScanResult
	for dir, files := range byDir {
		if files.pyproject == nil || files.poetryLock == nil {
			continue
		}
		result := buildPoetryResult(dir, files.pyproject, files.poetryLock)
		if result == nil {
			continue
		}
		results = append(results, *result)
	}
	return results
}

func buildPoetryResult(dir string, pyprojectContent, lockContent []byte) *AppScanResult {
	rootName, rootVersion := parsePyprojectToml(pyprojectContent)
	if rootName == "" {
		// No [tool.poetry] section found — not a poetry project.
		return nil
	}

	deps := parsePoetryLock(lockContent)
	if len(deps) == 0 {
		return nil
	}

	lockPath := filepath.Join(dir, "poetry.lock")
	dg := depgraph.FromDepTree("poetry", rootName, rootVersion, deps)

	return &AppScanResult{
		Identity: types.Identity{
			Type:       "poetry",
			TargetFile: lockPath,
		},
		Facts: []types.Fact{
			{Type: types.FactDepGraph, Data: dg},
			{Type: types.FactTestedFiles, Data: []string{"pyproject.toml", "poetry.lock"}},
		},
	}
}

// parsePyprojectToml extracts name and version from the [tool.poetry] section
// of a pyproject.toml file using a simple line-by-line parser.
func parsePyprojectToml(content []byte) (name, version string) {
	inPoetrySection := false
	for _, line := range splitLines(content) {
		line = strings.TrimSpace(line)
		// Detect section headers.
		if strings.HasPrefix(line, "[") {
			inPoetrySection = line == "[tool.poetry]"
			continue
		}
		if !inPoetrySection {
			continue
		}
		if k, v, ok := parseTomlStringKV(line); ok {
			switch k {
			case "name":
				name = v
			case "version":
				version = v
			}
		}
	}
	return name, version
}

// parsePoetryLock extracts (name, version) pairs from a poetry.lock file.
// It iterates over [[package]] stanzas.
func parsePoetryLock(content []byte) []depgraph.DepInfo {
	var deps []depgraph.DepInfo
	inPackage := false
	var curName, curVersion string

	flush := func() {
		if curName != "" && curVersion != "" {
			deps = append(deps, depgraph.DepInfo{
				Name:    curName,
				Version: curVersion,
			})
		}
		curName = ""
		curVersion = ""
	}

	for _, line := range splitLines(content) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "[[package]]" {
			flush()
			inPackage = true
			continue
		}
		// A new section header (other than [[package]]) ends the current stanza.
		if strings.HasPrefix(trimmed, "[") && trimmed != "[[package]]" {
			inPackage = false
			continue
		}
		if !inPackage {
			continue
		}
		if k, v, ok := parseTomlStringKV(trimmed); ok {
			switch k {
			case "name":
				curName = v
			case "version":
				curVersion = v
			}
		}
	}
	flush()
	return deps
}

// parseTomlStringKV parses a line of the form: key = "value"
// Returns (key, value, true) on success.
func parseTomlStringKV(line string) (key, value string, ok bool) {
	// Split on the first '='.
	idx := strings.IndexByte(line, '=')
	if idx < 0 {
		return
	}
	key = strings.TrimSpace(line[:idx])
	rest := strings.TrimSpace(line[idx+1:])
	// Value must be a quoted string.
	if len(rest) < 2 || rest[0] != '"' {
		return
	}
	// Find closing quote.
	closeIdx := strings.LastIndexByte(rest[1:], '"')
	if closeIdx < 0 {
		return
	}
	value = rest[1 : 1+closeIdx]
	ok = true
	return
}

// splitLines splits content into lines, handling \r\n and \n.
func splitLines(content []byte) []string {
	content = bytes.ReplaceAll(content, []byte("\r\n"), []byte("\n"))
	parts := strings.Split(string(content), "\n")
	return parts
}
