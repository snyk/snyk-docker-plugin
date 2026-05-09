// Package apt provides ExtractActions for dpkg/apt package database files.
package apt

import "github.com/snyk/snyk-docker-plugin/pkg/extractor"

const (
	ActionNameDpkg = "dpkg"
	ActionNameExt  = "dpkg-ext"
)

// DpkgAction extracts /var/lib/dpkg/status.
var DpkgAction = extractor.ExtractAction{
	ActionName:      ActionNameDpkg,
	FilePathMatches: func(p string) bool { return p == "/var/lib/dpkg/status" },
}

// ExtAction extracts /var/lib/apt/extended_states (auto-installed markers).
var ExtAction = extractor.ExtractAction{
	ActionName:      ActionNameExt,
	FilePathMatches: func(p string) bool { return p == "/var/lib/apt/extended_states" },
}

// Actions returns all ExtractActions needed for APT/dpkg analysis.
func Actions() []extractor.ExtractAction { return []extractor.ExtractAction{DpkgAction, ExtAction} }
