// Package python provides extraction actions for Python pip scanning.
package python

import (
	"io"
	"path/filepath"
	"strings"

	"github.com/snyk/snyk-docker-plugin/pkg/extractor"
)

const ActionName = "python-pip"

// filePathMatches returns true for:
//   - requirements.txt (any depth)
//   - METADATA inside a *.dist-info directory
func filePathMatches(path string) bool {
	base := filepath.Base(path)
	dir := filepath.Dir(path)
	if base == "requirements.txt" {
		return true
	}
	if base == "METADATA" && strings.HasSuffix(dir, ".dist-info") {
		return true
	}
	return false
}

// Actions returns the ExtractActions needed for Python pip scanning.
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
