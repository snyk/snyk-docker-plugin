// Package apk provides ExtractActions for APK package database files.
package apk

import "github.com/snyk/snyk-docker-plugin/pkg/extractor"

const ActionName = "apk-db"

// Action extracts /lib/apk/db/installed (and the /usr/lib variant).
var Action = extractor.ExtractAction{
	ActionName: ActionName,
	FilePathMatches: func(p string) bool {
		return p == "/lib/apk/db/installed" || p == "/usr/lib/apk/db/installed"
	},
}

// Actions returns all ExtractActions needed for APK analysis.
func Actions() []extractor.ExtractAction { return []extractor.ExtractAction{Action} }
