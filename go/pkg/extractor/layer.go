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

// IsWhitedOutFile returns true if the path contains a whiteout marker.
func IsWhitedOutFile(filename string) bool {
	return strings.Contains(filepath.Base(filename), whiteoutPrefix)
}

// LayerFiles maps actionName → path → content for a single layer.
// When multiple paths can satisfy one action (e.g. OS release files), each
// matching path is stored under its own key so callers know exactly which
// file was found.
type LayerFiles map[string]map[string]interface{} // actionName → path → content

// ExtractLayer reads a (possibly compressed) tar stream for one image layer
// and applies the given ExtractActions.
// Returns a LayerFiles map.
func ExtractLayer(layerStream io.Reader, actions []ExtractAction) (LayerFiles, error) {
	decompressed, err := decompressStream(layerStream)
	if err != nil {
		return nil, err
	}

	result := LayerFiles{}
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

		absPath := "/" + strings.TrimPrefix(filepath.ToSlash(hdr.Name), "/")

		for _, action := range actions {
			if !action.FilePathMatches(absPath) {
				continue
			}
			var content interface{}
			if action.Callback != nil {
				content, err = action.Callback(tr, hdr.Size)
				if err != nil {
					continue
				}
			} else {
				raw, err := io.ReadAll(tr)
				if err != nil {
					continue
				}
				content = raw
			}
			if result[action.ActionName] == nil {
				result[action.ActionName] = map[string]interface{}{}
			}
			result[action.ActionName][absPath] = content
		}
	}
	return result, nil
}

// decompressStream auto-detects gzip / zstd / uncompressed.
func decompressStream(r io.Reader) (io.Reader, error) {
	preview := make([]byte, 4)
	n, _ := io.ReadFull(r, preview)
	peeked := io.MultiReader(bytes.NewReader(preview[:n]), r)

	if n >= 2 && preview[0] == 0x1f && preview[1] == 0x8b {
		return gzip.NewReader(peeked)
	}
	if n >= 4 && preview[0] == 0x28 && preview[1] == 0xB5 && preview[2] == 0x2F && preview[3] == 0xFD {
		return zstd.NewReader(peeked)
	}
	return peeked, nil
}

// MergedLayers merges per-layer LayerFiles maps into a single flat map.
// Later layers override earlier ones; whiteout semantics are applied.
type MergedLayers map[string]map[string]interface{} // actionName → path → content

// MergeLayers merges a slice of LayerFiles (from oldest to newest layer).
func MergeLayers(layers []LayerFiles) MergedLayers {
	merged := MergedLayers{}
	for _, layer := range layers {
		for actionName, pathMap := range layer {
			if merged[actionName] == nil {
				merged[actionName] = map[string]interface{}{}
			}
			for path, content := range pathMap {
				merged[actionName][path] = content
			}
		}
	}
	return merged
}

// GetContent returns the content for an action from merged layers.
// Returns the content of the first (alphabetically) matched path, or nil.
func (m MergedLayers) GetContent(actionName string) []byte {
	paths := m[actionName]
	if len(paths) == 0 {
		return nil
	}
	for _, content := range paths {
		if raw, ok := content.([]byte); ok {
			return raw
		}
	}
	return nil
}

// GetContentByPath returns the content for a specific path under an action.
func (m MergedLayers) GetContentByPath(actionName, path string) []byte {
	paths := m[actionName]
	if paths == nil {
		return nil
	}
	if content, ok := paths[path]; ok {
		if raw, ok := content.([]byte); ok {
			return raw
		}
	}
	return nil
}

// AllPathContents returns all path→[]byte entries for an action.
func (m MergedLayers) AllPathContents(actionName string) map[string][]byte {
	paths := m[actionName]
	result := map[string][]byte{}
	for path, content := range paths {
		if raw, ok := content.([]byte); ok {
			result[path] = raw
		}
	}
	return result
}

// ExtractedLayers is the legacy type alias kept for docker/oci archive compatibility.
type ExtractedLayers = MergedLayers
