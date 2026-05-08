// Package docker provides extraction of docker-archive format images.
package docker

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/snyk/snyk-docker-plugin/pkg/extractor"
)


// DockerManifest is the manifest.json entry in a docker-archive.
type DockerManifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

// ExtractArchive opens a docker-archive tar at archivePath and extracts layers.
func ExtractArchive(archivePath string, actions []extractor.ExtractAction) (*extractor.ExtractionResult, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("opening docker archive: %w", err)
	}
	defer f.Close()

	return extractFromReader(f, actions)
}

// ExtractArchiveFromBytes extracts from in-memory tar data (used in tests).
func ExtractArchiveFromBytes(data []byte, actions []extractor.ExtractAction) (*extractor.ExtractionResult, error) {
	return extractFromReader(bytes.NewReader(data), actions)
}

func extractFromReader(r io.ReadSeeker, actions []extractor.ExtractAction) (*extractor.ExtractionResult, error) {
	// First pass: read manifest.json and config JSON.
	var manifests []DockerManifest
	var configJSON []byte
	var layerContents = map[string][]byte{} // layerName → raw tar bytes

	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		switch {
		case hdr.Name == "manifest.json":
			if err := json.Unmarshal(data, &manifests); err != nil {
				return nil, fmt.Errorf("parsing manifest.json: %w", err)
			}
		default:
			// Store all entries by name so we can look up config + layers later.
			layerContents[hdr.Name] = data
		}
	}

	if len(manifests) == 0 {
		return nil, fmt.Errorf("manifest.json not found or empty in docker archive")
	}

	manifest := manifests[0]
	if configData, ok := layerContents[manifest.Config]; ok {
		configJSON = configData
	}

	var imgConfig extractor.ImageConfig
	if configJSON != nil {
		if err := json.Unmarshal(configJSON, &imgConfig); err != nil {
			return nil, fmt.Errorf("parsing image config: %w", err)
		}
	}

	// Extract each layer.
	var layerResults []map[string]interface{}
	for _, layerName := range manifest.Layers {
		data, ok := layerContents[layerName]
		if !ok {
			return nil, fmt.Errorf("layer %q not found in archive", layerName)
		}
		layerResult, err := extractor.ExtractLayer(bytes.NewReader(data), actions)
		if err != nil {
			return nil, fmt.Errorf("extracting layer %s: %w", layerName, err)
		}
		layerResults = append(layerResults, layerResult)
	}

	// Build per-layer ExtractedLayers map.
	layers := make([]map[string]map[string]interface{}, len(manifest.Layers))
	for i, name := range manifest.Layers {
		if i < len(layerResults) {
			layers[i] = map[string]map[string]interface{}{
				name: layerResults[i],
			}
		}
	}

	result := &extractor.ExtractionResult{
		ImageID:         GetImageIDFromManifest(manifest),
		ManifestLayers:  manifest.Layers,
		ExtractedLayers: extractor.MergeLayers(layers),
		RootFsLayers:    imgConfig.RootFS.DiffIDs,
		ImageCreationTime: imgConfig.Created,
		ContainerConfig: imgConfig.Config,
		History:         imgConfig.History,
	}

	if imgConfig.Config != nil {
		result.ImageLabels = imgConfig.Config.Labels
	}

	if imgConfig.OS != "" && imgConfig.Architecture != "" {
		result.Platform = imgConfig.OS + "/" + imgConfig.Architecture
	}

	return result, nil
}

// GetImageIDFromManifest extracts the image ID from the config filename.
// The config file is named "<sha256>.json"; we strip the .json suffix.
func GetImageIDFromManifest(manifest DockerManifest) string {
	cfg := manifest.Config
	// Remove path prefix if any.
	parts := strings.Split(cfg, "/")
	base := parts[len(parts)-1]
	return strings.TrimSuffix(base, ".json")
}


