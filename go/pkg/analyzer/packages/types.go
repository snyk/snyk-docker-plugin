// Package packages provides OS package manager parsers.
// All parsers return []AnalyzedPackage which feeds directly into deptree.BuildDepInfos.
package packages

// AnalyzedPackage is the canonical per-package type for all OS package managers.
// Mirrors lib/analyzer/types.ts AnalyzedPackageWithVersion.
type AnalyzedPackage struct {
	Name          string
	Version       string
	Source        string          // source package name (dpkg Source: field, apk o: field)
	SourceVersion string          // source package version (dpkg only)
	Provides      []string        // virtual package names this pkg satisfies
	Deps          map[string]bool // dependency names (keys only; values always true)
	Purl          string
	AutoInstalled bool
}
