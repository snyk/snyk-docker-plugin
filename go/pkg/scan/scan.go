// Package scan provides the top-level Scan() entry point, mirroring lib/scan.ts.
package scan

import (
	"context"
	"fmt"
	"os"

	"github.com/snyk/snyk-docker-plugin/pkg/analyzer/osrelease"
	"github.com/snyk/snyk-docker-plugin/pkg/depgraph"
	"github.com/snyk/snyk-docker-plugin/pkg/extractor"
	dockerextractor "github.com/snyk/snyk-docker-plugin/pkg/extractor/docker"
	"github.com/snyk/snyk-docker-plugin/pkg/extractor/kaniko"
	ociextractor "github.com/snyk/snyk-docker-plugin/pkg/extractor/oci"
	"github.com/snyk/snyk-docker-plugin/pkg/image"
	"github.com/snyk/snyk-docker-plugin/pkg/types"
)

const pluginVersion = "go-0.0.1"

// MergeEnvVarsIntoCredentials fills in registry credentials from environment
// variables if not already set (mirrors scan.ts:mergeEnvVarsIntoCredentials).
func MergeEnvVarsIntoCredentials(opts *types.PluginOptions) {
	if opts.Username == "" {
		opts.Username = os.Getenv("SNYK_REGISTRY_USERNAME")
	}
	if opts.Password == "" {
		opts.Password = os.Getenv("SNYK_REGISTRY_PASSWORD")
	}
}

// Scan is the Go equivalent of the TS plugin.scan() function.
// It detects the image type, extracts the archive, analyses the OS and packages,
// and returns a PluginResponse.
func Scan(ctx context.Context, opts types.PluginOptions) (*types.PluginResponse, error) {
	if opts.Path == "" {
		return nil, fmt.Errorf("no image identifier or path provided")
	}

	MergeEnvVarsIntoCredentials(&opts)

	targetImage := image.AppendLatestTagIfMissing(opts.Path)
	imgType := image.GetImageType(targetImage)

	archivePath, err := image.GetArchivePath(targetImage)
	if err != nil {
		// Not an archive — live image pull not yet implemented in Go MVP.
		// Return a minimal response indicating the image type was identified.
		return nil, fmt.Errorf("live image pull not yet implemented: %w", err)
	}

	// Select the right extractor.
	var extractFn extractor.ArchiveExtractor
	switch imgType {
	case image.DockerArchive, image.UnspecifiedArchiveType:
		extractFn = dockerextractor.ExtractArchive
	case image.OciArchive:
		extractFn = ociextractor.ExtractArchive
	case image.KanikoArchive:
		extractFn = kaniko.ExtractArchive
	default:
		return nil, fmt.Errorf("unsupported image type: %v", imgType)
	}

	// Define extraction actions — we need os-release files for now.
	osReleaseAction := extractor.ExtractAction{
		ActionName: "osRelease",
		FilePathMatches: func(p string) bool {
			switch p {
			case "/etc/os-release", "/usr/lib/os-release",
				"/etc/lsb-release", "/etc/debian_version",
				"/etc/alpine-release", "/etc/redhat-release",
				"/etc/oracle-release", "/etc/centos-release":
				return true
			}
			return false
		},
	}

	extractionResult, err := extractor.ExtractImageContent(ctx, extractFn, archivePath, []extractor.ExtractAction{osReleaseAction})
	if err != nil {
		return nil, fmt.Errorf("extracting image content: %w", err)
	}

	// Detect OS release.
	fileContents := map[string]string{}
	for _, layerFiles := range extractionResult.ExtractedLayers {
		if content, ok := layerFiles["osRelease"]; ok {
			if raw, ok := content.([]byte); ok {
				// We need to know which path it came from — simplify by trying all parsers.
				// In a full implementation, each action would carry its path.
				fileContents["/etc/os-release"] = string(raw)
			}
		}
	}

	osRelease, _ := osrelease.Detect(fileContents)

	// Build a minimal dep-graph for the OS.
	var pkgMgrName = "unknown"
	var rootName = targetImage
	var rootVersion = ""
	if osRelease != nil {
		rootVersion = osRelease.Version
		switch osRelease.Name {
		case "alpine":
			pkgMgrName = "apk"
		case "debian", "ubuntu":
			pkgMgrName = "deb"
		case "centos", "rhel", "fedora", "ol", "amzn", "sles", "opensuse":
			pkgMgrName = "rpm"
		}
	}

	depGraph := depgraph.FromDepTree(pkgMgrName, rootName, rootVersion, nil)

	// Assemble facts.
	facts := []types.Fact{
		{Type: types.FactDepGraph, Data: depGraph},
		{Type: types.FactImageID, Data: extractionResult.ImageID},
		{Type: types.FactImageLayers, Data: extractionResult.ManifestLayers},
		{Type: types.FactPluginVersion, Data: pluginVersion},
	}
	if len(extractionResult.RootFsLayers) > 0 {
		facts = append(facts, types.Fact{Type: types.FactRootFs, Data: extractionResult.RootFsLayers})
	}
	if osRelease != nil && osRelease.PrettyName != "" {
		facts = append(facts, types.Fact{Type: types.FactImageOsReleasePrettyName, Data: osRelease.PrettyName})
	}
	if extractionResult.ImageCreationTime != "" {
		facts = append(facts, types.Fact{Type: types.FactImageCreationTime, Data: extractionResult.ImageCreationTime})
	}
	if len(extractionResult.ImageLabels) > 0 {
		facts = append(facts, types.Fact{Type: types.FactImageLabels, Data: extractionResult.ImageLabels})
	}
	if extractionResult.Platform != "" {
		facts = append(facts, types.Fact{Type: types.FactPlatform, Data: extractionResult.Platform})
	}
	if len(extractionResult.History) > 0 {
		facts = append(facts, types.Fact{Type: types.FactHistory, Data: extractionResult.History})
	}

	scanResult := types.ScanResult{
		Target:   types.ContainerTarget{Image: targetImage},
		Identity: types.Identity{Type: pkgMgrName},
		Facts:    facts,
	}

	return &types.PluginResponse{
		ScanResults: []types.ScanResult{scanResult},
	}, nil
}
