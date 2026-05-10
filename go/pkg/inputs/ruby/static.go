// Package ruby provides extraction actions for Ruby Gemfile.lock scanning.
package ruby

import (
	"io"
	"path/filepath"
	"strings"

	"github.com/snyk/snyk-docker-plugin/pkg/extractor"
)

const ActionName = "ruby-app-files"

// filePathMatches returns true for Gemfile.lock (and its .wh. whiteout variant).
func filePathMatches(path string) bool {
	base := filepath.Base(path)
	// Strip whiteout prefix.
	base = strings.TrimPrefix(base, ".wh.")
	return base == "Gemfile.lock"
}

// Actions returns the ExtractActions needed for Ruby Gemfile.lock scanning.
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
