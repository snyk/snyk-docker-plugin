// Package deptree builds dependency trees from package manager results.
package deptree

import "github.com/snyk/snyk-docker-plugin/pkg/depgraph"

// BuildTree converts a flat list of packages into dep-graph entries.
// Placeholder - full implementation in follow-up.
func BuildTree(pkgManagerName, rootName, rootVersion string, deps []depgraph.DepInfo) []depgraph.DepInfo {
	return deps
}
