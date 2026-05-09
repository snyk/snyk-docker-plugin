// Package oci provides extraction of oci-archive format images.
package oci

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	specsv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/snyk/snyk-docker-plugin/pkg/extractor"
)

// ExtractArchive opens an OCI-archive tar at archivePath and extracts layers.
func ExtractArchive(archivePath string, actions []extractor.ExtractAction) (*extractor.ExtractionResult, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("opening oci archive: %w", err)
	}
	defer f.Close()
	return extractFromReader(f, actions)
}

func extractFromReader(r io.Reader, actions []extractor.ExtractAction) (*extractor.ExtractionResult, error) {
	entries := map[string][]byte{}
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
		entries[hdr.Name] = data
	}

	indexData, ok := entries["index.json"]
	if !ok {
		return nil, fmt.Errorf("index.json not found in OCI archive")
	}
	var index specsv1.Index
	if err := json.Unmarshal(indexData, &index); err != nil {
		return nil, fmt.Errorf("parsing index.json: %w", err)
	}
	if len(index.Manifests) == 0 {
		return nil, fmt.Errorf("no manifests in OCI index")
	}

	manifestDesc := index.Manifests[0]
	manifestKey := blobKey(manifestDesc.Digest.String())
	manifestData, ok := entries[manifestKey]
	if !ok {
		return nil, fmt.Errorf("manifest blob %s not found", manifestKey)
	}
	var manifest specsv1.Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, fmt.Errorf("parsing OCI manifest: %w", err)
	}

	configKey := blobKey(manifest.Config.Digest.String())
	configData, ok := entries[configKey]
	if !ok {
		return nil, fmt.Errorf("config blob %s not found", configKey)
	}
	var imgConfig extractor.ImageConfig
	if err := json.Unmarshal(configData, &imgConfig); err != nil {
		return nil, fmt.Errorf("parsing OCI image config: %w", err)
	}

	var layerNames []string
	var layerResults []extractor.LayerFiles
	for _, layerDesc := range manifest.Layers {
		layerKey := blobKey(layerDesc.Digest.String())
		layerData, ok := entries[layerKey]
		if !ok {
			return nil, fmt.Errorf("layer blob %s not found", layerKey)
		}
		lf, err := extractor.ExtractLayer(bytes.NewReader(layerData), actions)
		if err != nil {
			return nil, fmt.Errorf("extracting layer %s: %w", layerKey, err)
		}
		layerNames = append(layerNames, "sha256:"+strings.TrimPrefix(layerDesc.Digest.String(), "sha256:"))
		layerResults = append(layerResults, lf)
	}

	imageID := strings.TrimPrefix(manifest.Config.Digest.String(), "sha256:")

	result := &extractor.ExtractionResult{
		ImageID:           "sha256:" + imageID,
		ManifestLayers:    layerNames,
		Layers:            extractor.MergeLayers(layerResults),
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

func blobKey(digest string) string {
	alg, hex, ok := strings.Cut(digest, ":")
	if !ok {
		return "blobs/" + digest
	}
	return "blobs/" + alg + "/" + hex
}
