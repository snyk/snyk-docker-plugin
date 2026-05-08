// Package docker provides extraction of docker-archive format images.
package docker

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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
// The outer archive may be plain tar or gzip-compressed tar.
func ExtractArchive(archivePath string, actions []extractor.ExtractAction) (*extractor.ExtractionResult, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("opening docker archive: %w", err)
	}
	defer f.Close()

	// Peek for gzip magic bytes.
	header := make([]byte, 2)
	if _, err := io.ReadFull(f, header); err != nil {
		return nil, fmt.Errorf("reading archive header: %w", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seeking archive: %w", err)
	}

	var reader io.Reader = f
	if header[0] == 0x1f && header[1] == 0x8b {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, fmt.Errorf("decompressing gzip archive: %w", err)
		}
		defer gz.Close()
		reader = gz
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("reading archive: %w", err)
	}
	return extractFromReader(bytes.NewReader(data), actions)
}

// ExtractArchiveFromBytes extracts from in-memory tar data (used in tests).
func ExtractArchiveFromBytes(data []byte, actions []extractor.ExtractAction) (*extractor.ExtractionResult, error) {
	return extractFromReader(bytes.NewReader(data), actions)
}

func extractFromReader(r io.ReadSeeker, actions []extractor.ExtractAction) (*extractor.ExtractionResult, error) {
	var manifests []DockerManifest
	layerContents := map[string][]byte{}

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
			layerContents[hdr.Name] = data
		}
	}

	if len(manifests) == 0 {
		return nil, fmt.Errorf("manifest.json not found or empty in docker archive")
	}

	manifest := manifests[0]

	var configJSON []byte
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

	layers := make([]map[string]map[string]interface{}, len(manifest.Layers))
	for i, name := range manifest.Layers {
		if i < len(layerResults) {
			layers[i] = map[string]map[string]interface{}{
				name: layerResults[i],
			}
		}
	}

	// Normalise imageId and imageLayers to the sha256:<hex> format that TS produces.
	imageID := normaliseID(manifest.Config)
	manifestLayers := make([]string, len(manifest.Layers))
	for i, l := range manifest.Layers {
		manifestLayers[i] = normaliseLayerName(l)
	}

	result := &extractor.ExtractionResult{
		ImageID:           imageID,
		ManifestLayers:    manifestLayers,
		ExtractedLayers:   extractor.MergeLayers(layers),
		RootFsLayers:      imgConfig.RootFS.DiffIDs,
		ImageCreationTime: imgConfig.Created,
		ContainerConfig:   imgConfig.Config,
		History:           imgConfig.History,
	}

	if imgConfig.Config != nil {
		result.ImageLabels = imgConfig.Config.Labels
	}

	if imgConfig.OS != "" && imgConfig.Architecture != "" {
		result.Platform = imgConfig.OS + "/" + imgConfig.Architecture
	}

	return result, nil
}

// normaliseID converts a config path from manifest.json to sha256:<hex>.
//
// Two formats appear in the wild:
//
//	"<sha256hex>.json"              → sha256:<sha256hex>
//	"blobs/sha256/<sha256hex>"      → sha256:<sha256hex>
func normaliseID(config string) string {
	// OCI-layout inside docker-archive: "blobs/sha256/<hex>"
	if after, ok := strings.CutPrefix(config, "blobs/sha256/"); ok {
		return "sha256:" + after
	}
	// Classic docker-archive: "<hex>.json"
	base := config
	if idx := strings.LastIndex(base, "/"); idx >= 0 {
		base = base[idx+1:]
	}
	base = strings.TrimSuffix(base, ".json")
	return "sha256:" + base
}

// normaliseLayerName normalises a layer name from manifest.json.
//
// The TS plugin passes classic layer names through unchanged
// (e.g. "<hex>/layer.tar" or "<hex>.tar") and only converts
// OCI-layout embedded paths ("blobs/sha256/<hex>") to "sha256:<hex>".
func normaliseLayerName(layer string) string {
	// OCI-layout inside docker-archive: "blobs/sha256/<hex>" → "sha256:<hex>"
	if after, ok := strings.CutPrefix(layer, "blobs/sha256/"); ok {
		return "sha256:" + after
	}
	// Classic formats ("<hex>/layer.tar", "<hex>.tar") — pass through unchanged.
	return layer
}

// GetImageIDFromManifest extracts the normalised image ID from a manifest.
func GetImageIDFromManifest(manifest DockerManifest) string {
	return normaliseID(manifest.Config)
}
