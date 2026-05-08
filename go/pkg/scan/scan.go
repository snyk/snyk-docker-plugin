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
func Scan(ctx context.Context, opts types.PluginOptions) (*types.PluginResponse, error) {
	if opts.Path == "" {
		return nil, fmt.Errorf("no image identifier or path provided")
	}

	MergeEnvVarsIntoCredentials(&opts)

	targetImage := image.AppendLatestTagIfMissing(opts.Path)
	imgType := image.GetImageType(targetImage)

	archivePath, err := image.GetArchivePath(targetImage)
	if err != nil {
		return nil, fmt.Errorf("live image pull not yet implemented: %w", err)
	}

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

	// OS-release extraction actions.
	osReleaseFiles := map[string]bool{
		"/etc/os-release": true, "/usr/lib/os-release": true,
		"/etc/lsb-release": true, "/etc/debian_version": true,
		"/etc/alpine-release": true, "/etc/redhat-release": true,
		"/etc/oracle-release": true, "/etc/centos-release": true,
	}
	osReleaseByPath := map[string]string{}
	// nil Callback → raw []byte returned
	osReleaseAction := extractor.ExtractAction{
		ActionName: "osRelease",
		FilePathMatches: func(p string) bool {
			return osReleaseFiles[p]
		},
	}

	extractionResult, err := extractor.ExtractImageContent(ctx, extractFn, archivePath, []extractor.ExtractAction{osReleaseAction})
	if err != nil {
		return nil, fmt.Errorf("extracting image content: %w", err)
	}

	// Collect os-release file contents from extracted layers.
	for _, layerFiles := range extractionResult.ExtractedLayers {
		if content, ok := layerFiles["osRelease"]; ok {
			if raw, ok := content.([]byte); ok && len(raw) > 0 {
				// We can't know which path without threaded context; try each known path.
				// The extractor matched one of the known paths — store under a sentinel key
				// and let the detector try all parsers.
				if _, already := osReleaseByPath["/etc/os-release"]; !already {
					osReleaseByPath["/etc/os-release"] = string(raw)
				}
			}
		}
	}

	osRelease, _ := osrelease.Detect(osReleaseByPath)

	// Determine package manager.
	pkgMgrName := "linux" // TS fallback when OS detected but no specific PM
	rootVersion := ""
	if osRelease != nil {
		rootVersion = osRelease.Version
		switch osRelease.Name {
		case "alpine":
			pkgMgrName = "apk"
		case "debian", "ubuntu", "linuxmint", "kali":
			pkgMgrName = "deb"
		case "centos", "rhel", "fedora", "ol", "amzn", "sles", "opensuse",
			"opensuse-leap", "opensuse-tumbleweed", "rocky", "almalinux":
			pkgMgrName = "rpm"
		default:
			pkgMgrName = "linux"
		}
	} else {
		pkgMgrName = "linux"
	}

	depGraph := depgraph.FromDepTree(pkgMgrName, targetImage, rootVersion, nil)

	// Platform: prefer explicit option, then from image config.
	platform := opts.Platform
	if platform == "" {
		platform = extractionResult.Platform
	}
	if platform == "" {
		platform = "linux/amd64" // TS default
	}

	// Assemble facts.
	facts := []types.Fact{
		{Type: types.FactDepGraph, Data: depGraph},
		{Type: types.FactImageID, Data: extractionResult.ImageID},
		{Type: types.FactImageLayers, Data: extractionResult.ManifestLayers},
	}
	if len(extractionResult.ImageLabels) > 0 {
		facts = append(facts, types.Fact{Type: types.FactImageLabels, Data: extractionResult.ImageLabels})
	}
	if extractionResult.ContainerConfig != nil {
		facts = append(facts, types.Fact{Type: types.FactContainerConfig, Data: containerConfigFact(extractionResult.ContainerConfig)})
	}
	if len(extractionResult.History) > 0 {
		facts = append(facts, types.Fact{Type: types.FactHistory, Data: historyFacts(extractionResult.History)})
	}
	if extractionResult.ImageCreationTime != "" {
		facts = append(facts, types.Fact{Type: types.FactImageCreationTime, Data: extractionResult.ImageCreationTime})
	}
	if len(extractionResult.RootFsLayers) > 0 {
		facts = append(facts, types.Fact{Type: types.FactRootFs, Data: extractionResult.RootFsLayers})
	}
	if osRelease != nil && osRelease.PrettyName != "" {
		facts = append(facts, types.Fact{Type: types.FactImageOsReleasePrettyName, Data: osRelease.PrettyName})
	}
	facts = append(facts, types.Fact{Type: types.FactPlatform, Data: platform})
	facts = append(facts, types.Fact{Type: types.FactPluginVersion, Data: pluginVersion})

	// Identity: type = pkgManager, args.platform = detected platform.
	identity := types.Identity{
		Type: pkgMgrName,
		Args: map[string]string{"platform": platform},
	}

	scanResult := types.ScanResult{
		Target:   types.ContainerTarget{Image: targetImage},
		Identity: identity,
		Facts:    facts,
	}

	return &types.PluginResponse{
		ScanResults: []types.ScanResult{scanResult},
	}, nil
}

// containerConfigFact converts an extractor.ContainerConfig into the
// lowercase-keyed map that the TS plugin emits in the containerConfig fact.
func containerConfigFact(cc *extractor.ContainerConfig) map[string]interface{} {
	if cc == nil {
		return nil
	}
	m := map[string]interface{}{}
	if cc.User != "" {
		m["user"] = cc.User
	}
	if len(cc.ExposedPorts) > 0 {
		ports := make([]string, 0, len(cc.ExposedPorts))
		for p := range cc.ExposedPorts {
			ports = append(ports, p)
		}
		m["exposedPorts"] = ports
	}
	if len(cc.Env) > 0 {
		m["env"] = cc.Env
	}
	if len(cc.Entrypoint) > 0 {
		m["entrypoint"] = cc.Entrypoint
	}
	if len(cc.Cmd) > 0 {
		m["cmd"] = cc.Cmd
	}
	if len(cc.Volumes) > 0 {
		vols := make([]string, 0, len(cc.Volumes))
		for v := range cc.Volumes {
			vols = append(vols, v)
		}
		m["volumes"] = vols
	}
	if cc.WorkingDir != "" {
		m["workingDir"] = cc.WorkingDir
	}
	if cc.StopSignal != "" {
		m["stopSignal"] = cc.StopSignal
	}
	if cc.ArgsEscaped != nil {
		m["argsEscaped"] = *cc.ArgsEscaped
	}
	return m
}

// historyFacts converts extractor.HistoryEntry slice to the fact format.
func historyFacts(history []extractor.HistoryEntry) []map[string]interface{} {
	out := make([]map[string]interface{}, len(history))
	for i, h := range history {
		entry := map[string]interface{}{}
		if h.Created != "" {
			entry["created"] = h.Created
		}
		if h.Author != "" {
			entry["author"] = h.Author
		}
		if h.CreatedBy != "" {
			entry["createdBy"] = h.CreatedBy
		}
		if h.Comment != "" {
			entry["comment"] = h.Comment
		}
		if h.EmptyLayer {
			entry["emptyLayer"] = h.EmptyLayer
		}
		out[i] = entry
	}
	return out
}
