// Package php provides extraction actions for PHP Composer scanning.
package php

import (
	"io"
	"path/filepath"

	"github.com/snyk/snyk-docker-plugin/pkg/extractor"
)

const ActionName = "php-composer"

func filePathMatches(path string) bool {
	base := filepath.Base(path)
	return base == "composer.json" || base == "composer.lock"
}

// Actions returns the ExtractActions needed for PHP Composer scanning.
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
