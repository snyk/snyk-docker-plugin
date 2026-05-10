// Package npm provides extraction actions for Node.js lockfile scanning.
package npm

import (
	"io"
	"path/filepath"
	"strings"

	"github.com/snyk/snyk-docker-plugin/pkg/extractor"
)

const ActionName = "node-app-files"

// nodeFiles is the set of Node.js manifest/lockfile basenames we collect.
var nodeFiles = map[string]bool{
	"package.json":      true,
	"package-lock.json": true,
	"yarn.lock":         true,
	"pnpm-lock.yaml":    true,
}

// filePathMatches returns true for any of the four Node.js lockfile/manifest
// filenames, at any depth. Whiteout variants (.wh.<name>) are also matched
// so the extractor can handle layer deletions correctly.
func filePathMatches(path string) bool {
	base := filepath.Base(path)
	// Strip whiteout prefix if present.
	if strings.HasPrefix(base, ".wh.") {
		base = strings.TrimPrefix(base, ".wh.")
	}
	return nodeFiles[base]
}

// Actions returns the ExtractActions needed for Node.js lockfile scanning.
func Actions() []extractor.ExtractAction {
	return []extractor.ExtractAction{
		{
			ActionName:      ActionName,
			FilePathMatches: filePathMatches,
			Callback: func(r io.Reader, _ int64) (interface{}, error) {
				return io.ReadAll(r)
			},
		},
	}
}
