// Package kaniko provides extraction of kaniko-archive format images.
// Kaniko archives use the same docker-archive format.
package kaniko

import (
	"github.com/snyk/snyk-docker-plugin/pkg/extractor"
	"github.com/snyk/snyk-docker-plugin/pkg/extractor/docker"
)

// ExtractArchive delegates to the docker-archive extractor since kaniko uses the same format.
func ExtractArchive(archivePath string, actions []extractor.ExtractAction) (*extractor.ExtractionResult, error) {
	return docker.ExtractArchive(archivePath, actions)
}
