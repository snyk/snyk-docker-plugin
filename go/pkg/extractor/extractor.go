package extractor

import (
	"context"
	"fmt"
)

// ArchiveExtractor is a function that extracts an archive and returns an ExtractionResult.
type ArchiveExtractor func(archivePath string, actions []ExtractAction) (*ExtractionResult, error)

// ExtractImageContent is the main entry point for extracting image content.
// imageType is one of the constants from the image package; archivePath is the
// filesystem path to the archive. actions describe which files to extract.
//
// NOTE: The actual extractor dispatch (docker vs oci vs kaniko) is done in
// the scan package to avoid circular imports. This package only defines types.
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
