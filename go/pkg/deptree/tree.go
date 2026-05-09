// Package deptree builds dependency trees from flat package-manager results,
// mirroring lib/dependency-tree/index.ts buildTree / buildTreeRecursive /
// countDepsRecursive.
package deptree

import (
	"sort"

	"github.com/snyk/snyk-docker-plugin/pkg/depgraph"
)

// depFreqThreshold is the DEP_FREQ_THRESHOLD from the TypeScript source.
// Any package referenced more than this many times across the full dep graph
// is considered "too frequent" and is moved under the meta-common-packages
// node instead of being inlined at every reference point.
const depFreqThreshold = 100

// AnalyzedPackage is a single package as emitted by a package-manager
// analyzer (apk, apt, rpm, …). It is the Go equivalent of
// AnalyzedPackageWithVersion from lib/analyzer/types.ts.
type AnalyzedPackage struct {
	// Name is the canonical package name (e.g. "curl").
	Name string
	// Version is the installed version string.
	Version string
	// Source is the source package name. When non-empty the dep-graph node
	// name becomes "Source/Name" (mirrors depFullName in the TS code).
	Source string
	// Provides lists virtual package names that this package satisfies.
	Provides []string
	// Deps is the set of dependency names (values are always true).
	Deps map[string]bool
	// AutoInstalled is true when the package was pulled in automatically as a
	// dependency, not explicitly installed by the user.
	AutoInstalled bool
	// Purl is the package-URL, if available.
	Purl string
}

// internalPkg augments AnalyzedPackage with the _visited bookkeeping flag
// used by buildTreeRecursive.
type internalPkg struct {
	AnalyzedPackage
	visited bool
}

// pkgFullName mirrors the TS depFullName helper: if Source is set the node
// name is "Source/Name", otherwise just "Name".
func pkgFullName(p *internalPkg) string {
	if p.Source != "" {
		return p.Source + "/" + p.Name
	}
	return p.Name
}

// BuildDepInfos converts a flat list of analyzed packages into a slice of
// top-level depgraph.DepInfo entries whose .Deps fields contain the full
// transitive dependency tree.
//
// The algorithm is a direct port of the TypeScript buildTree /
// buildTreeRecursive / countDepsRecursive functions from
// lib/dependency-tree/index.ts.
//
// Returned slice ordering:
//  1. Manually-installed packages (AutoInstalled == false).
//  2. Auto-installed packages that were never visited as a transitive dep.
//  3. A single "meta-common-packages"@"meta" node holding every package
//     referenced more than depFreqThreshold times (if any).
func BuildDepInfos(pkgs []AnalyzedPackage) []depgraph.DepInfo {
	if len(pkgs) == 0 {
		return nil
	}

	// ------------------------------------------------------------------ //
	// Step 1: Build internal package slice (adds the _visited flag).
	// ------------------------------------------------------------------ //
	internal := make([]*internalPkg, len(pkgs))
	for i := range pkgs {
		ip := &internalPkg{AnalyzedPackage: pkgs[i]}
		internal[i] = ip
	}

	// ------------------------------------------------------------------ //
	// Step 2: Build depsMap (realName → pkg) and virtualDepsMap
	//         (providesName → pkg).
	// ------------------------------------------------------------------ //
	depsMap := make(map[string]*internalPkg, len(internal))
	for _, ip := range internal {
		depsMap[ip.Name] = ip
	}

	virtualDepsMap := make(map[string]*internalPkg)
	for _, ip := range internal {
		for _, prov := range ip.Provides {
			virtualDepsMap[prov] = ip
		}
	}

	// ------------------------------------------------------------------ //
	// Step 3: Count how many times each package is referenced transitively.
	// ------------------------------------------------------------------ //
	depCounts := make(map[string]int)
	for _, ip := range internal {
		countDepsRecursive(ip.Name, make(map[string]bool), depsMap, virtualDepsMap, depCounts)
	}

	// Identify too-frequent packages (count > threshold).
	tooFrequentSet := make(map[string]bool)
	var tooFrequentNames []string
	for name, count := range depCounts {
		if count > depFreqThreshold {
			tooFrequentSet[name] = true
			tooFrequentNames = append(tooFrequentNames, name)
		}
	}
	// Sort for determinism (map iteration order is undefined in Go).
	sort.Strings(tooFrequentNames)

	// ------------------------------------------------------------------ //
	// Step 4: attachDeps — mirrors the inner attachDeps closure in TS.
	// ------------------------------------------------------------------ //
	// result holds the final top-level DepInfo entries.
	var result []depgraph.DepInfo
	// addedNames deduplicates by fullName, mirroring the JS object-key
	// behaviour of root.dependencies[subtree.name] = subtree.
	addedNames := make(map[string]bool)

	attachDeps := func(batch []*internalPkg) {
		for _, ip := range batch {
			ancestors := make(map[string]bool)
			subtree := buildTreeRecursive(
				ip.Name,
				ancestors,
				depsMap,
				virtualDepsMap,
				tooFrequentSet,
			)
			if subtree == nil {
				continue
			}
			if !addedNames[subtree.Name] {
				addedNames[subtree.Name] = true
				result = append(result, *subtree)
			}
		}
	}

	// Pass 1: manually-installed packages (AutoInstalled == false).
	var manuallyInstalled []*internalPkg
	for _, ip := range internal {
		if !ip.AutoInstalled {
			manuallyInstalled = append(manuallyInstalled, ip)
		}
	}
	attachDeps(manuallyInstalled)

	// Pass 2: auto-installed packages not yet visited as a transitive dep.
	var notVisited []*internalPkg
	for _, ip := range internal {
		// Check via depsMap so we always read the pointer we track.
		if tracked := depsMap[ip.Name]; tracked != nil && !tracked.visited {
			notVisited = append(notVisited, ip)
		}
	}
	attachDeps(notVisited)

	// ------------------------------------------------------------------ //
	// Step 5: Attach too-frequent deps.
	//
	// In the TS code the behaviour differs by packageFormat:
	//   - deb/apk/rpm → add directly to root.dependencies
	//   - others       → add under a meta-common-packages@meta node
	//
	// BuildDepInfos does not receive the packageFormat, so we always use the
	// meta-common-packages node (the caller can flatten if needed).
	// ------------------------------------------------------------------ //
	if len(tooFrequentNames) > 0 {
		var metaDeps []depgraph.DepInfo
		for _, name := range tooFrequentNames {
			ip := depsMap[name]
			if ip == nil {
				continue
			}
			metaDeps = append(metaDeps, depgraph.DepInfo{
				Name:    pkgFullName(ip),
				Version: ip.Version,
			})
		}
		if len(metaDeps) > 0 {
			result = append(result, depgraph.DepInfo{
				Name:    "meta-common-packages",
				Version: "meta",
				Deps:    metaDeps,
			})
		}
	}

	return result
}

// buildTreeRecursive is the Go port of the TS function of the same name.
//
// It looks up depName in depsMap (then virtualDepsMap), builds a DepInfo
// node for it, marks it visited, and recurses into its dependencies.
//
// Cycle detection uses a backtracking ancestors set keyed on fullName.
// When a package has already been visited (was reached earlier in the tree)
// a stub node (no Deps) is returned instead of recursing again.
func buildTreeRecursive(
	depName string,
	ancestors map[string]bool,
	depsMap map[string]*internalPkg,
	virtualDepsMap map[string]*internalPkg,
	tooFrequentSet map[string]bool,
) *depgraph.DepInfo {
	// Resolve the package — depsMap takes priority over virtualDepsMap.
	ip := depsMap[depName]
	if ip == nil {
		ip = virtualDepsMap[depName]
	}
	if ip == nil {
		return nil
	}

	realName := ip.Name
	fullName := pkgFullName(ip)

	// Cycle or too-frequent: skip.
	if ancestors[fullName] || tooFrequentSet[realName] {
		return nil
	}

	// Build the stub node that is always returned.
	node := &depgraph.DepInfo{
		Name:    fullName,
		Version: ip.Version,
	}

	// If already visited, return the stub without recursing (mirrors TS).
	if ip.visited {
		return node
	}
	ip.visited = true

	// Recurse into children.
	if len(ip.Deps) > 0 {
		// Add current node to ancestors (backtracking DFS).
		ancestors[fullName] = true

		// Use a childNames map to deduplicate children by fullName,
		// mirroring the JS `if (!tree.dependencies[subTree.name])` guard.
		childNames := make(map[string]bool, len(ip.Deps))

		for childDepName := range ip.Deps {
			child := buildTreeRecursive(
				childDepName,
				ancestors,
				depsMap,
				virtualDepsMap,
				tooFrequentSet,
			)
			if child != nil && !childNames[child.Name] {
				childNames[child.Name] = true
				node.Deps = append(node.Deps, *child)
			}
		}

		// Backtrack: remove current node from ancestors.
		delete(ancestors, fullName)
	}

	return node
}

// countDepsRecursive is the Go port of the TS function of the same name.
//
// It increments depCounts[realName] for each package reachable from depName
// (excluding packages that are ancestors of the current call, to avoid
// infinite loops on cycles).
func countDepsRecursive(
	depName string,
	ancestors map[string]bool,
	depsMap map[string]*internalPkg,
	virtualDepsMap map[string]*internalPkg,
	depCounts map[string]int,
) {
	ip := depsMap[depName]
	if ip == nil {
		ip = virtualDepsMap[depName]
	}
	if ip == nil {
		return
	}

	realName := ip.Name

	// Cycle detection: ancestors is keyed on realName (mirrors TS).
	if ancestors[realName] {
		return
	}

	depCounts[realName]++

	// Recurse into children using backtracking.
	ancestors[realName] = true
	for childDepName := range ip.Deps {
		countDepsRecursive(childDepName, ancestors, depsMap, virtualDepsMap, depCounts)
	}
	delete(ancestors, realName)
}
