package extractor

import (
	"context"
	"fmt"
)

// ArchiveExtractor extracts an archive and returns an ExtractionResult.
type ArchiveExtractor func(archivePath string, actions []ExtractAction) (*ExtractionResult, error)

// ExtractImageContent is the main entry point.
func ExtractImageContent(
	_ context.Context,
	extract ArchiveExtractor,
	archivePath string,
	actions []ExtractAction,
) (*ExtractionResult, error) {
	if extract == nil {
		return nil, fmt.Errorf("no extractor provided")
	}
	return extract(archivePath, actions)
}
