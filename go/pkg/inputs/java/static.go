// Package java provides extraction actions for Java JAR scanning.
package java

import (
	"io"
	"strings"

	"github.com/snyk/snyk-docker-plugin/pkg/extractor"
)

const ActionName = "java-jars"

// javaExtensions is the set of Java archive extensions we collect.
var javaExtensions = map[string]bool{
	".jar": true,
	".war": true,
	".ear": true,
}

func filePathMatches(path string) bool {
	lower := strings.ToLower(path)
	for ext := range javaExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// Actions returns the ExtractActions needed for Java JAR scanning.
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
