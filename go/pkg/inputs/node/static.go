// Package node provides extraction actions for Go binary scanning.
// Note: Node.js lockfile parsing would require shelling out to Node (see plan Phase 6a);
// for the Go implementation we collect Go binaries instead.
// This package is named "node" for historical reasons matching the inputs layout,
// but it serves the gobinary scanner.
package node

import (
	"io"

	"github.com/snyk/snyk-docker-plugin/pkg/extractor"
	"github.com/snyk/snyk-docker-plugin/pkg/gobinary"
)

const ActionName = "gobinaries"

// Actions returns the ExtractActions needed for Go binary scanning.
func Actions() []extractor.ExtractAction {
	return []extractor.ExtractAction{
		{
			ActionName:      ActionName,
			FilePathMatches: gobinary.FilePathMatches,
			Callback: func(r io.Reader, _ int64) (interface{}, error) {
				return io.ReadAll(r)
			},
		},
	}
}
