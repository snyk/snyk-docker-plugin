// Package python provides extraction actions for Python pip and poetry scanning.
package python

import (
	"io"
	"path/filepath"
	"strings"

	"github.com/snyk/snyk-docker-plugin/pkg/extractor"
)

const ActionName = "python-pip"

// PoetryActionName is the action name for Poetry project file extraction.
const PoetryActionName = "poetry-app-files"

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

// poetryFilePathMatches returns true for pyproject.toml and poetry.lock
// (and their .wh. whiteout variants).
func poetryFilePathMatches(path string) bool {
	base := filepath.Base(path)
	// Strip whiteout prefix so we still recognise whiteout variants.
	base = strings.TrimPrefix(base, ".wh.")
	return base == "pyproject.toml" || base == "poetry.lock"
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

// PoetryActions returns the ExtractActions needed for Python Poetry scanning.
func PoetryActions() []extractor.ExtractAction {
	return []extractor.ExtractAction{
		{
			ActionName:      PoetryActionName,
			FilePathMatches: poetryFilePathMatches,
			Callback: func(r io.Reader, _ int64) (interface{}, error) {
				return io.ReadAll(r)
			},
		},
	}
}
