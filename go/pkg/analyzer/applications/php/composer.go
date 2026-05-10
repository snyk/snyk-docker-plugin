// Package php provides PHP Composer dependency scanning.
// It mirrors lib/analyzer/applications/php.ts.
package php

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/snyk/snyk-docker-plugin/pkg/depgraph"
	"github.com/snyk/snyk-docker-plugin/pkg/types"
)

// AppScanResult is one scan result per composer.lock + composer.json pair.
type AppScanResult struct {
	Identity types.Identity
	Facts    []types.Fact
}

// composerLock is the JSON structure of a composer.lock file.
type composerLock struct {
	Packages []composerPackage `json:"packages"`
}

// composerPackage is a single package entry in composer.lock.
type composerPackage struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Require map[string]string `json:"require"`
}

// ScanComposer builds dep-graphs for all composer.lock + composer.json pairs
// found in the same directory.
// pathToContent maps absolute paths → raw file bytes.
func ScanComposer(pathToContent map[string][]byte) []AppScanResult {
	// Group files by directory.
	byDir := map[string]map[string][]byte{}
	for path, content := range pathToContent {
		dir := filepath.Dir(path)
		base := filepath.Base(path)
		if base != "composer.json" && base != "composer.lock" {
			continue
		}
		if byDir[dir] == nil {
			byDir[dir] = map[string][]byte{}
		}
		byDir[dir][base] = content
	}

	var results []AppScanResult
	for dir, files := range byDir {
		_, hasJSON := files["composer.json"]
		lockContent, hasLock := files["composer.lock"]
		if !hasJSON || !hasLock {
			continue
		}
		result := buildComposerResult(dir, lockContent)
		if result == nil {
			continue
		}
		results = append(results, *result)
	}
	return results
}

func buildComposerResult(dir string, lockContent []byte) *AppScanResult {
	var lock composerLock
	if err := json.Unmarshal(lockContent, &lock); err != nil {
		return nil
	}
	if len(lock.Packages) == 0 {
		return nil
	}

	// Build a name → version lookup for all packages in the lockfile.
	pkgVersions := map[string]string{}
	for _, pkg := range lock.Packages {
		norm := normalisePHPVersion(pkg.Version)
		pkgVersions[strings.ToLower(pkg.Name)] = norm
	}

	// Build flat dep-infos; we resolve one level of requires.
	// PHP doesn't have deeply nested dep-graph support in the TS impl either
	// (it uses buildDepTree from @snyk/composer-lockfile-parser which
	// resolves transitives). We build it recursively here.
	visited := map[string]bool{}
	var deps []depgraph.DepInfo
	for _, pkg := range lock.Packages {
		norm := normalisePHPVersion(pkg.Version)
		key := strings.ToLower(pkg.Name) + "@" + norm
		if visited[key] {
			continue
		}
		visited[key] = true
		children := resolveComposerDeps(pkg.Require, pkgVersions, visited, 0)
		deps = append(deps, depgraph.DepInfo{
			Name:    pkg.Name,
			Version: norm,
			Deps:    children,
		})
	}

	if len(deps) == 0 {
		return nil
	}

	lockPath := filepath.Join(dir, "composer.lock")
	dg := depgraph.FromDepTree("composer", lockPath, "", deps)

	return &AppScanResult{
		Identity: types.Identity{
			Type:       "composer",
			TargetFile: lockPath,
		},
		Facts: []types.Fact{
			{Type: types.FactDepGraph, Data: dg},
			{Type: types.FactTestedFiles, Data: []string{"composer.json", "composer.lock"}},
		},
	}
}

const maxComposerDepth = 10

func resolveComposerDeps(
	requires map[string]string,
	pkgVersions map[string]string,
	visited map[string]bool,
	depth int,
) []depgraph.DepInfo {
	if depth >= maxComposerDepth {
		return nil
	}
	var result []depgraph.DepInfo
	for name := range requires {
		name = strings.ToLower(name)
		// Skip platform requirements (php, ext-*, lib-*).
		if strings.HasPrefix(name, "php") || strings.HasPrefix(name, "ext-") || strings.HasPrefix(name, "lib-") {
			continue
		}
		ver, ok := pkgVersions[name]
		if !ok {
			continue
		}
		key := name + "@" + ver
		if visited[key] {
			continue
		}
		visited[key] = true
		result = append(result, depgraph.DepInfo{Name: name, Version: ver})
	}
	return result
}

// normalisePHPVersion strips the leading 'v' that Composer often uses.
func normalisePHPVersion(v string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "v") || strings.HasPrefix(v, "V") {
		return v[1:]
	}
	return v
}
