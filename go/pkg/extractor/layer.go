package extractor

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
)

const whiteoutPrefix = ".wh."
const opaqueWhiteout = ".wh..opq"

// IsWhitedOutFile returns true if the path contains a whiteout marker.
func IsWhitedOutFile(filename string) bool {
	return strings.Contains(filepath.Base(filename), whiteoutPrefix)
}

// ExtractLayer reads a (possibly compressed) tar stream for one image layer
// and applies the given ExtractActions.
// The result is a map from actionName → content.
func ExtractLayer(layerStream io.Reader, actions []ExtractAction) (map[string]interface{}, error) {
	decompressed, err := decompressStream(layerStream)
	if err != nil {
		return nil, err
	}

	result := map[string]interface{}{}
	tr := tar.NewReader(decompressed)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}

		// Normalise path to absolute.
		absPath := "/" + strings.TrimPrefix(filepath.ToSlash(hdr.Name), "/")
		base := filepath.Base(absPath)
		_ = base // used for whiteout detection via IsWhitedOutFile

		for _, action := range actions {
			if !action.FilePathMatches(absPath) {
				continue
			}
			var content interface{}
			if action.Callback != nil {
				content, err = action.Callback(tr, hdr.Size)
				if err != nil {
					continue // non-fatal per TS behaviour
				}
			} else {
				raw, err := io.ReadAll(tr)
				if err != nil {
					continue
				}
				content = raw
			}
			if IsWhitedOutFile(absPath) || content != nil {
				result[action.ActionName] = content
			}
		}
	}
	return result, nil
}

// decompressStream auto-detects gzip / zstd / uncompressed.
func decompressStream(r io.Reader) (io.Reader, error) {
	// Peek at the first few bytes to detect format.
	previewBuf := &bytes.Buffer{}
	preview := make([]byte, 4)
	n, _ := io.ReadFull(r, preview)
	previewBuf.Write(preview[:n])

	peeked := io.MultiReader(previewBuf, r)

	if n >= 2 && preview[0] == 0x1f && preview[1] == 0x8b {
		return gzip.NewReader(peeked)
	}
	// zstd magic: 0xFD2FB528 (little-endian)
	if n >= 4 && preview[0] == 0x28 && preview[1] == 0xB5 && preview[2] == 0x2F && preview[3] == 0xFD {
		return zstd.NewReader(peeked)
	}
	// Uncompressed tar.
	return peeked, nil
}

// MergeLayers merges per-layer ExtractedLayers maps, applying whiteout semantics.
// Later layers override earlier ones. Whiteout files (`.wh.` prefix) mark deletions.
func MergeLayers(layers []map[string]map[string]interface{}) ExtractedLayers {
	merged := ExtractedLayers{}
	for _, layer := range layers {
		for key, files := range layer {
			if files == nil {
				delete(merged, key)
			} else {
				merged[key] = files
			}
		}
	}
	return merged
}
