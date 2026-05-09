// Package scan provides the top-level Scan() entry point, mirroring lib/scan.ts.
package scan

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/snyk/snyk-docker-plugin/pkg/analyzer/osrelease"
	pkgpkgs "github.com/snyk/snyk-docker-plugin/pkg/analyzer/packages"
	"github.com/snyk/snyk-docker-plugin/pkg/depgraph"
	"github.com/snyk/snyk-docker-plugin/pkg/deptree"
	"github.com/snyk/snyk-docker-plugin/pkg/extractor"
	dockerextractor "github.com/snyk/snyk-docker-plugin/pkg/extractor/docker"
	"github.com/snyk/snyk-docker-plugin/pkg/extractor/kaniko"
	ociextractor "github.com/snyk/snyk-docker-plugin/pkg/extractor/oci"
	"github.com/snyk/snyk-docker-plugin/pkg/image"
	inputsapk "github.com/snyk/snyk-docker-plugin/pkg/inputs/apk"
	inputsapt "github.com/snyk/snyk-docker-plugin/pkg/inputs/apt"
	inputsos "github.com/snyk/snyk-docker-plugin/pkg/inputs/osrelease"
	"github.com/snyk/snyk-docker-plugin/pkg/parser"
	"github.com/snyk/snyk-docker-plugin/pkg/types"
)

const pluginVersion = "go-0.0.1"

// MergeEnvVarsIntoCredentials fills registry credentials from env vars.
func MergeEnvVarsIntoCredentials(opts *types.PluginOptions) {
	if opts.Username == "" {
		opts.Username = os.Getenv("SNYK_REGISTRY_USERNAME")
	}
	if opts.Password == "" {
		opts.Password = os.Getenv("SNYK_REGISTRY_PASSWORD")
	}
}

// Scan is the Go equivalent of the TS plugin.scan().
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

	// Collect all extraction actions: OS release files + package DBs.
	actions := append(
		append(
			inputsos.Actions,
			inputsapk.Actions()...,
		),
		inputsapt.Actions()...,
	)

	extractionResult, err := extractor.ExtractImageContent(ctx, extractFn, archivePath, actions)
	if err != nil {
		return nil, fmt.Errorf("extracting image content: %w", err)
	}

	// Detect OS release from per-path content.
	osRelease := detectOSRelease(extractionResult.Layers)

	// Detect platform.
	platform := opts.Platform
	if platform == "" {
		platform = extractionResult.Platform
	}
	if platform == "" {
		platform = "linux/amd64"
	}

	// Run package parsers on extracted content.
	analyses := runPackageParsers(extractionResult.Layers, osRelease)

	// Parse into dep-infos.
	parsed := parser.ParseAnalysisResults(
		targetImage,
		analyses,
		extractionResult.ImageID,
		extractionResult.ManifestLayers,
		platform,
		osRelease,
	)

	// Build dep-graph root name mirroring TS: "docker-image|<imageName>"
	rootName, rootVersion := imageRootNameVersion(targetImage)
	rootOSVersion := ""
	if osRelease != nil {
		rootOSVersion = osRelease.Version
	}
	_ = rootVersion      // TS uses imageVersion here, but dep-graph root is OS version
	_ = rootOSVersion

	depGraph := depgraph.FromDepTree(parsed.PackageFormat, rootName, rootOSVersion, parsed.DepInfos)

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

	identity := types.Identity{
		Type: parsed.PackageFormat,
		Args: map[string]string{"platform": platform},
	}

	return &types.PluginResponse{
		ScanResults: []types.ScanResult{{
			Target:   types.ContainerTarget{Image: targetImage},
			Identity: identity,
			Facts:    facts,
		}},
	}, nil
}

// detectOSRelease reads OS release file contents from merged layers and runs
// the appropriate parser for each known path.
func detectOSRelease(layers extractor.MergedLayers) *osrelease.OSRelease {
	for _, action := range inputsos.Actions {
		pathContents := layers.AllPathContents(action.ActionName)
		for path, content := range pathContents {
			if len(content) == 0 {
				continue
			}
			text := string(content)
			var rel *osrelease.OSRelease
			var err error
			switch path {
			case "/etc/os-release", "/usr/lib/os-release":
				rel, err = osrelease.TryOSRelease(text)
			case "/etc/lsb-release":
				rel, err = osrelease.TryLsbRelease(text)
			case "/etc/debian_version":
				rel, err = osrelease.TryDebianVersion(text)
			case "/etc/alpine-release":
				rel, err = osrelease.TryAlpineRelease(text)
			case "/etc/redhat-release":
				rel, err = osrelease.TryRedHatRelease(text)
			case "/etc/oracle-release":
				rel, err = osrelease.TryOracleRelease(text)
			case "/etc/centos-release":
				rel, err = osrelease.TryCentosRelease(text)
			}
			if err == nil && rel != nil {
				return rel
			}
		}
	}
	return nil
}

// runPackageParsers runs all OS package manager parsers against extracted layers.
func runPackageParsers(layers extractor.MergedLayers, osRel *osrelease.OSRelease) []parser.ImagePackagesAnalysis {
	var analyses []parser.ImagePackagesAnalysis

	// APK
	if apkContent := layers.GetContent(inputsapk.ActionName); len(apkContent) > 0 {
		pkgs, err := pkgpkgs.ParseAPKDatabase(string(apkContent))
		if err == nil && len(pkgs) > 0 {
			analyses = append(analyses, parser.ImagePackagesAnalysis{
				AnalyzeType: parser.AnalysisTypeApk,
				Packages:    apkToDepTree(pkgs),
			})
		}
	}

	// DEB/dpkg
	if dpkgContent := layers.GetContent(inputsapt.ActionNameDpkg); len(dpkgContent) > 0 {
		pkgs, err := pkgpkgs.ParseDPKGStatus(string(dpkgContent), osRel)
		if err == nil && len(pkgs) > 0 {
			// Apply auto-installed markers if extended_states was extracted.
			if extContent := layers.GetContent(inputsapt.ActionNameExt); len(extContent) > 0 {
				pkgpkgs.SetAutoInstalled(string(extContent), pkgs)
			}
			analyses = append(analyses, parser.ImagePackagesAnalysis{
				AnalyzeType: parser.AnalysisTypeApt,
				Packages:    aptToDepTree(pkgs),
			})
		}
	}

	return analyses
}

// apkToDepTree converts []packages.AnalyzedPackage → []deptree.AnalyzedPackage.
func apkToDepTree(pkgs []pkgpkgs.AnalyzedPackage) []deptree.AnalyzedPackage {
	out := make([]deptree.AnalyzedPackage, len(pkgs))
	for i, p := range pkgs {
		out[i] = deptree.AnalyzedPackage{
			Name:          p.Name,
			Version:       p.Version,
			Source:        p.Source,
			Provides:      p.Provides,
			Deps:          p.Deps,
			AutoInstalled: p.AutoInstalled,
			Purl:          p.Purl,
		}
	}
	return out
}

// aptToDepTree converts []packages.AnalyzedPackage → []deptree.AnalyzedPackage.
func aptToDepTree(pkgs []pkgpkgs.AnalyzedPackage) []deptree.AnalyzedPackage {
	return apkToDepTree(pkgs) // same struct layout
}

// imageRootNameVersion mirrors the TS buildTree root-name logic.
func imageRootNameVersion(targetImage string) (name, version string) {
	// Strip archive prefix.
	for _, prefix := range []string{"docker-archive:", "oci-archive:", "kaniko-archive:"} {
		targetImage = strings.TrimPrefix(targetImage, prefix)
	}
	finalSlash := strings.LastIndex(targetImage, "/")
	segment := targetImage
	if finalSlash >= 0 {
		segment = targetImage[finalSlash:]
	}
	hasVersion := strings.Contains(segment, ":")
	imageName := targetImage
	imageVersion := "latest"
	if hasVersion {
		sep := strings.LastIndex(targetImage, ":")
		imageName = targetImage[:sep]
		imageVersion = targetImage[sep+1:]
	}
	if strings.HasSuffix(imageName, ".tar") {
		imageVersion = ""
	}
	if strings.HasSuffix(imageName, "@sha256") {
		imageName = imageName[:len(imageName)-len("@sha256")]
		imageVersion = ""
	}
	return "docker-image|" + imageName, imageVersion
}

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
