// Package node provides Node.js lockfile parsing for npm, yarn, and pnpm.
// It mirrors lib/analyzer/applications/node.ts from the TypeScript codebase.
package node

import (
	"bufio"
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/snyk/snyk-docker-plugin/pkg/depgraph"
	"github.com/snyk/snyk-docker-plugin/pkg/types"
)

// AppScanResult is a single per-project application scan result.
type AppScanResult struct {
	Identity types.Identity
	Facts    []types.Fact
}

// ScanNode parses all Node.js lockfiles found in pathToContent and returns
// one AppScanResult per project directory. pathToContent maps file paths to
// raw bytes (as collected by the extractor).
//
// A package.json is preferred for root name/version but is not required:
// npm lockfiles carry the root info themselves, so a lone package-lock.json
// is sufficient.
func ScanNode(pathToContent map[string][]byte) []AppScanResult {
	// Group files by directory.
	byDir := map[string]map[string][]byte{}
	for path, content := range pathToContent {
		dir := filepath.Dir(path)
		base := filepath.Base(path)
		if byDir[dir] == nil {
			byDir[dir] = map[string][]byte{}
		}
		byDir[dir][base] = content
	}

	var results []AppScanResult
	for dir, files := range byDir {
		manifest := files["package.json"] // may be nil

		// Try each lockfile in priority order.
		if lockContent, ok := files["package-lock.json"]; ok {
			if r := buildNpmResult(dir, manifest, lockContent); r != nil {
				results = append(results, *r)
			}
		} else if lockContent, ok := files["yarn.lock"]; ok {
			if manifest == nil {
				continue // yarn requires package.json for root info
			}
			if r := buildYarnResult(dir, manifest, lockContent); r != nil {
				results = append(results, *r)
			}
		} else if lockContent, ok := files["pnpm-lock.yaml"]; ok {
			if manifest == nil {
				continue // pnpm requires package.json for root info
			}
			if r := buildPnpmResult(dir, manifest, lockContent); r != nil {
				results = append(results, *r)
			}
		}
	}
	return results
}

// ---------------------------------------------------------------------------
// package.json helpers
// ---------------------------------------------------------------------------

type packageJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func parseManifest(data []byte) (name, version string) {
	var m packageJSON
	if err := json.Unmarshal(data, &m); err == nil {
		name = m.Name
		version = m.Version
	}
	return
}

func rootNameVersion(dir string, manifest []byte) (string, string) {
	name, version := parseManifest(manifest)
	if name == "" {
		name = dir
	}
	return name, version
}

// ---------------------------------------------------------------------------
// npm lockfile v2/v3
// ---------------------------------------------------------------------------

type npmLockfile struct {
	Name            string                    `json:"name"`
	Version         string                    `json:"version"`
	LockfileVersion int                       `json:"lockfileVersion"`
	Packages        map[string]npmLockPackage `json:"packages"`
}

type npmLockPackage struct {
	Version string `json:"version"`
	Name    string `json:"name"` // only present in root ("") entry
}

// parseNpmLockV2 parses an npm lockfile v2 or v3 (packages map format).
func parseNpmLockV2(manifest, lockfile []byte) ([]depgraph.DepInfo, error) {
	var lock npmLockfile
	if err := json.Unmarshal(lockfile, &lock); err != nil {
		return nil, err
	}
	var deps []depgraph.DepInfo
	for key, pkg := range lock.Packages {
		if key == "" {
			// Root entry — skip.
			continue
		}
		// Keys look like "node_modules/foo" or "node_modules/foo/node_modules/bar".
		// Extract the package name by taking everything after the last "node_modules/".
		name := key
		if idx := strings.LastIndex(key, "node_modules/"); idx != -1 {
			name = key[idx+len("node_modules/"):]
		}
		if name == "" {
			continue
		}
		deps = append(deps, depgraph.DepInfo{
			Name:    name,
			Version: pkg.Version,
		})
	}
	return deps, nil
}

func buildNpmResult(dir string, manifest, lockContent []byte) *AppScanResult {
	var lock npmLockfile
	if err := json.Unmarshal(lockContent, &lock); err != nil {
		return nil
	}
	if lock.LockfileVersion < 2 {
		// v1 not supported in this implementation.
		return nil
	}
	deps, err := parseNpmLockV2(manifest, lockContent)
	if err != nil || len(deps) == 0 {
		return nil
	}

	// Determine root name/version: prefer package.json, fall back to lockfile top-level fields.
	var rootName, rootVersion string
	if manifest != nil {
		rootName, rootVersion = rootNameVersion(dir, manifest)
	}
	// Fall back to lockfile-embedded name/version (npm v2+ embeds them).
	if rootName == "" || rootName == dir {
		if lock.Name != "" {
			rootName = lock.Name
		} else {
			rootName = dir
		}
	}
	if rootVersion == "" && lock.Version != "" {
		rootVersion = lock.Version
	}

	dg := depgraph.FromDepTree("npm", rootName, rootVersion, deps)
	lockPath := filepath.Join(dir, "package-lock.json")

	testedFiles := []string{"package-lock.json"}
	if manifest != nil {
		testedFiles = []string{"package.json", "package-lock.json"}
	}
	return &AppScanResult{
		Identity: types.Identity{
			Type:       "npm",
			TargetFile: lockPath,
		},
		Facts: []types.Fact{
			{Type: types.FactDepGraph, Data: dg},
			{Type: types.FactTestedFiles, Data: testedFiles},
		},
	}
}

// ---------------------------------------------------------------------------
// yarn lockfile v1 (custom text format)
// ---------------------------------------------------------------------------

// parseYarnLockV1 parses a yarn v1 lockfile (text format).
// It returns a flat list of DepInfo (name + version, no transitive deps).
func parseYarnLockV1(manifest, lockfile []byte) ([]depgraph.DepInfo, error) {
	return parseYarnLockText(lockfile)
}

// parseYarnLockV2 parses a yarn v2+ (Berry) lockfile (text format).
// Structure is similar to v1 but has a leading __metadata block.
func parseYarnLockV2(manifest, lockfile []byte) ([]depgraph.DepInfo, error) {
	return parseYarnLockText(lockfile)
}

// parseYarnLockText is the shared parser for both yarn v1 and v2 text formats.
// Each stanza looks like:
//
//	"package@^1.0.0", "package@~1.0.0":
//	  version "1.0.1"
//	  resolved "..."
//	  dependencies:
//	    dep "^2.0.0"
func parseYarnLockText(data []byte) ([]depgraph.DepInfo, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))

	seen := map[string]bool{}
	var deps []depgraph.DepInfo

	var currentNames []string // package names for current stanza
	var currentVersion string
	inStanza := false

	flushStanza := func() {
		if len(currentNames) > 0 && currentVersion != "" {
			for _, name := range currentNames {
				key := name + "@" + currentVersion
				if !seen[key] {
					seen[key] = true
					deps = append(deps, depgraph.DepInfo{
						Name:    name,
						Version: currentVersion,
					})
				}
			}
		}
		currentNames = nil
		currentVersion = ""
		inStanza = false
	}

	for scanner.Scan() {
		line := scanner.Text()

		// Skip comments and __metadata block.
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			if inStanza {
				flushStanza()
			}
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "__metadata:") {
			// Skip the metadata block until blank line.
			for scanner.Scan() {
				if strings.TrimSpace(scanner.Text()) == "" {
					break
				}
			}
			continue
		}

		// A stanza header line does not start with whitespace and ends with ':'.
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			// Flush previous stanza.
			if inStanza {
				flushStanza()
			}
			if strings.HasSuffix(trimmed, ":") {
				// Parse the header: comma-separated "name@range" entries,
				// possibly quoted.
				header := strings.TrimSuffix(trimmed, ":")
				currentNames = parseYarnHeader(header)
				inStanza = true
			}
			continue
		}

		// Inside a stanza: look for "version" line.
		if inStanza && strings.Contains(trimmed, "version") {
			// Handles:
			//   version "1.2.3"     (yarn v1)
			//   version: 1.2.3      (yarn v2)
			if strings.HasPrefix(trimmed, "version \"") {
				v := strings.TrimPrefix(trimmed, "version \"")
				v = strings.TrimSuffix(v, "\"")
				currentVersion = v
			} else if strings.HasPrefix(trimmed, "version: ") {
				currentVersion = strings.TrimPrefix(trimmed, "version: ")
			}
		}
	}
	if inStanza {
		flushStanza()
	}
	return deps, nil
}

// parseYarnHeader splits a yarn stanza header into package names.
// Input examples:
//
//	"foo@^1.0.0"
//	"@scope/foo@^1.0.0", "@scope/foo@~1.0.0"
//	foo@npm:^1.0.0
func parseYarnHeader(header string) []string {
	// Split on ", " to get individual specifiers.
	var names []string
	seen := map[string]bool{}
	parts := splitYarnHeaderParts(header)
	for _, part := range parts {
		// Strip quotes.
		part = strings.Trim(part, "\"'")
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name := extractYarnPackageName(part)
		if name != "" && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	return names
}

// splitYarnHeaderParts splits on ", " respecting quoted strings.
func splitYarnHeaderParts(header string) []string {
	// Simple split on ", " — yarn headers don't contain commas in names.
	var parts []string
	for _, p := range strings.Split(header, ", ") {
		p = strings.TrimSpace(p)
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

// extractYarnPackageName returns the package name from a "name@version" specifier.
// Handles scoped packages like "@scope/name@version".
func extractYarnPackageName(spec string) string {
	if spec == "" {
		return ""
	}
	// yarn v2 uses "name@npm:version" — strip npm: and similar protocol prefixes.
	// Find the last '@' that separates name from range.
	start := 0
	if spec[0] == '@' {
		start = 1 // skip leading @ of scoped package
	}
	idx := strings.Index(spec[start:], "@")
	if idx == -1 {
		return spec // no version part
	}
	return spec[:start+idx]
}

func buildYarnResult(dir string, manifest, lockContent []byte) *AppScanResult {
	// Detect yarn version by scanning the first few lines for the marker.
	// yarn v1 has "# yarn lockfile v1" in the header comments.
	// yarn v2+ (Berry) has "__metadata:" block instead.
	pkgManager := "yarn"
	var parser func([]byte, []byte) ([]depgraph.DepInfo, error)

	isV1 := false
	scanner := bufio.NewScanner(bytes.NewReader(lockContent))
	for i := 0; i < 10 && scanner.Scan(); i++ {
		if strings.Contains(scanner.Text(), "yarn lockfile v1") {
			isV1 = true
			break
		}
	}

	if isV1 {
		parser = parseYarnLockV1
	} else {
		// yarn v2+
		parser = parseYarnLockV2
	}

	deps, err := parser(manifest, lockContent)
	if err != nil || len(deps) == 0 {
		return nil
	}

	rootName, rootVersion := rootNameVersion(dir, manifest)
	dg := depgraph.FromDepTree(pkgManager, rootName, rootVersion, deps)
	lockPath := filepath.Join(dir, "yarn.lock")
	return &AppScanResult{
		Identity: types.Identity{
			Type:       "yarn",
			TargetFile: lockPath,
		},
		Facts: []types.Fact{
			{Type: types.FactDepGraph, Data: dg},
			{Type: types.FactTestedFiles, Data: []string{"package.json", "yarn.lock"}},
		},
	}
}

// ---------------------------------------------------------------------------
// pnpm lockfile v6
// ---------------------------------------------------------------------------

// pnpmLockV6 is the YAML structure for pnpm lockfile version 6.x.
type pnpmLockV6 struct {
	LockfileVersion string                       `yaml:"lockfileVersion"`
	Packages        map[string]pnpmV6PackageEntry `yaml:"packages"`
}

type pnpmV6PackageEntry struct {
	Resolution map[string]interface{} `yaml:"resolution"`
	Dev        bool                   `yaml:"dev"`
}

// parsePnpmLockV6 parses a pnpm v6 lockfile.
// Package keys look like "/name@version" or "/@scope/name@version".
func parsePnpmLockV6(manifest, lockfile []byte) ([]depgraph.DepInfo, error) {
	var lock pnpmLockV6
	if err := yaml.Unmarshal(lockfile, &lock); err != nil {
		return nil, err
	}
	var deps []depgraph.DepInfo
	seen := map[string]bool{}
	for key := range lock.Packages {
		name, version := parsePnpmV6Key(key)
		if name == "" || version == "" {
			continue
		}
		k := name + "@" + version
		if seen[k] {
			continue
		}
		seen[k] = true
		deps = append(deps, depgraph.DepInfo{Name: name, Version: version})
	}
	return deps, nil
}

// parsePnpmV6Key extracts name and version from a pnpm v6 packages key.
// Key format: "/name@version" or "/@scope/name@version".
func parsePnpmV6Key(key string) (name, version string) {
	// Strip leading slash.
	key = strings.TrimPrefix(key, "/")
	if key == "" {
		return
	}
	return splitPnpmNameVersion(key)
}

// splitPnpmNameVersion splits "name@version" handling scoped packages.
func splitPnpmNameVersion(key string) (name, version string) {
	// For scoped packages (@scope/name@version), skip the leading @.
	start := 0
	if key[0] == '@' {
		start = 1
	}
	idx := strings.LastIndex(key[start:], "@")
	if idx == -1 {
		return key, ""
	}
	name = key[:start+idx]
	version = key[start+idx+1:]
	// Strip any parenthesized suffix like "(supports-color@5.5.0)".
	if i := strings.Index(version, "("); i != -1 {
		version = version[:i]
	}
	version = strings.TrimSpace(version)
	return
}

// ---------------------------------------------------------------------------
// pnpm lockfile v9
// ---------------------------------------------------------------------------

// pnpmLockV9 is the YAML structure for pnpm lockfile version 9.x.
type pnpmLockV9 struct {
	LockfileVersion string                       `yaml:"lockfileVersion"`
	Packages        map[string]pnpmV9PackageEntry `yaml:"packages"`
	Snapshots       map[string]interface{}        `yaml:"snapshots"`
}

type pnpmV9PackageEntry struct {
	Resolution map[string]interface{} `yaml:"resolution"`
}

// parsePnpmLockV9 parses a pnpm v9 lockfile.
// Package keys look like "name@version" (no leading slash).
func parsePnpmLockV9(manifest, lockfile []byte) ([]depgraph.DepInfo, error) {
	var lock pnpmLockV9
	if err := yaml.Unmarshal(lockfile, &lock); err != nil {
		return nil, err
	}
	var deps []depgraph.DepInfo
	seen := map[string]bool{}
	for key := range lock.Packages {
		name, version := splitPnpmNameVersion(key)
		if name == "" || version == "" {
			continue
		}
		k := name + "@" + version
		if seen[k] {
			continue
		}
		seen[k] = true
		deps = append(deps, depgraph.DepInfo{Name: name, Version: version})
	}
	return deps, nil
}

func buildPnpmResult(dir string, manifest, lockContent []byte) *AppScanResult {
	// Detect pnpm lockfile version.
	var header struct {
		LockfileVersion string `yaml:"lockfileVersion"`
	}
	if err := yaml.Unmarshal(lockContent, &header); err != nil {
		return nil
	}

	var deps []depgraph.DepInfo
	var err error
	// lockfileVersion is a string in v6/v9 (e.g. "6.0", "9.0").
	// Treat anything >= "9" as v9, else v6.
	lv := strings.TrimSpace(header.LockfileVersion)
	if strings.HasPrefix(lv, "9") {
		deps, err = parsePnpmLockV9(manifest, lockContent)
	} else {
		deps, err = parsePnpmLockV6(manifest, lockContent)
	}
	if err != nil || len(deps) == 0 {
		return nil
	}

	rootName, rootVersion := rootNameVersion(dir, manifest)
	dg := depgraph.FromDepTree("pnpm", rootName, rootVersion, deps)
	lockPath := filepath.Join(dir, "pnpm-lock.yaml")
	return &AppScanResult{
		Identity: types.Identity{
			Type:       "pnpm",
			TargetFile: lockPath,
		},
		Facts: []types.Fact{
			{Type: types.FactDepGraph, Data: dg},
			{Type: types.FactTestedFiles, Data: []string{"package.json", "pnpm-lock.yaml"}},
		},
	}
}
