// Package scan provides the top-level Scan() entry point, mirroring lib/scan.ts.
package scan

import (
	"context"
	"fmt"
	"os"
	"strings"

	appjava "github.com/snyk/snyk-docker-plugin/pkg/analyzer/applications/java"
	appphp "github.com/snyk/snyk-docker-plugin/pkg/analyzer/applications/php"
	appython "github.com/snyk/snyk-docker-plugin/pkg/analyzer/applications/python"
	"github.com/snyk/snyk-docker-plugin/pkg/analyzer/osrelease"
	pkgpkgs "github.com/snyk/snyk-docker-plugin/pkg/analyzer/packages"
	"github.com/snyk/snyk-docker-plugin/pkg/depgraph"
	"github.com/snyk/snyk-docker-plugin/pkg/deptree"
	"github.com/snyk/snyk-docker-plugin/pkg/extractor"
	dockerextractor "github.com/snyk/snyk-docker-plugin/pkg/extractor/docker"
	"github.com/snyk/snyk-docker-plugin/pkg/extractor/kaniko"
	ociextractor "github.com/snyk/snyk-docker-plugin/pkg/extractor/oci"
	"github.com/snyk/snyk-docker-plugin/pkg/gobinary"
	"github.com/snyk/snyk-docker-plugin/pkg/image"
	inputsapk "github.com/snyk/snyk-docker-plugin/pkg/inputs/apk"
	inputsapt "github.com/snyk/snyk-docker-plugin/pkg/inputs/apt"
	inputsjava "github.com/snyk/snyk-docker-plugin/pkg/inputs/java"
	inputsnode "github.com/snyk/snyk-docker-plugin/pkg/inputs/node"
	inputsos "github.com/snyk/snyk-docker-plugin/pkg/inputs/osrelease"
	inputsphp "github.com/snyk/snyk-docker-plugin/pkg/inputs/php"
	inputspython "github.com/snyk/snyk-docker-plugin/pkg/inputs/python"
	inputsrpm "github.com/snyk/snyk-docker-plugin/pkg/inputs/rpm"
	"github.com/snyk/snyk-docker-plugin/pkg/parser"
	"github.com/snyk/snyk-docker-plugin/pkg/registry"
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

	// Resolve archive path — pulling from registry when needed.
	archivePath, cleanup, err := resolveArchive(ctx, targetImage, imgType, opts)
	if err != nil {
		return nil, err
	}
	if cleanup != nil {
		defer cleanup()
	}

	// Select archive extractor.
	var extractFn extractor.ArchiveExtractor
	switch imgType {
	case image.DockerArchive, image.UnspecifiedArchiveType, image.Identifier:
		extractFn = dockerextractor.ExtractArchive
	case image.OciArchive:
		extractFn = ociextractor.ExtractArchive
	case image.KanikoArchive:
		extractFn = kaniko.ExtractArchive
	default:
		return nil, fmt.Errorf("unsupported image type: %v", imgType)
	}

	// Build extraction actions: OS release + all package managers.
	actions := buildExtractActions()

	extractionResult, err := extractor.ExtractImageContent(ctx, extractFn, archivePath, actions)
	if err != nil {
		return nil, fmt.Errorf("extracting image content: %w", err)
	}

	// Detect OS release.
	osRel := detectOSRelease(extractionResult.Layers)

	// Resolve platform.
	platform := opts.Platform
	if platform == "" {
		platform = extractionResult.Platform
	}
	if platform == "" {
		platform = "linux/amd64"
	}

	// Run package parsers.
	analyses := runPackageParsers(ctx, extractionResult.Layers, osRel)

	// Parse into dep-infos.
	parsed := parser.ParseAnalysisResults(
		targetImage,
		analyses,
		extractionResult.ImageID,
		extractionResult.ManifestLayers,
		platform,
		osRel,
	)

	// Build dep-graph root name ("docker-image|<imageName>") mirroring TS.
	rootName, _ := imageRootNameVersion(targetImage)
	rootOSVersion := ""
	if osRel != nil {
		rootOSVersion = osRel.Version
	}

	depGraph := depgraph.FromDepTree(parsed.PackageFormat, rootName, rootOSVersion, parsed.DepInfos)

	facts := assembleFacts(depGraph, extractionResult, osRel, platform)

	identity := types.Identity{
		Type: parsed.PackageFormat,
		Args: map[string]string{"platform": platform},
	}

	// Build OS scan result (always index 0).
	osScanResult := types.ScanResult{
		Target:   types.ContainerTarget{Image: targetImage},
		Identity: identity,
		Facts:    facts,
	}

	scanResults := []types.ScanResult{osScanResult}

	// Phase 6: Application scanning (unless excluded).
	if !types.OptBool(opts.ExcludeAppVulns) {
		appResults := runAppScanners(extractionResult.Layers, targetImage, opts)
		scanResults = append(scanResults, appResults...)
	}

	return &types.PluginResponse{
		ScanResults: scanResults,
	}, nil
}

// runAppScanners runs all application-level scanners over extracted layers
// and returns one ScanResult per discovered application.
func runAppScanners(
	layers extractor.MergedLayers,
	targetImage string,
	opts types.PluginOptions,
) []types.ScanResult {
	var results []types.ScanResult

	// Java JAR fingerprinting.
	{
		javaFiles := layers.AllPathContents(inputsjava.ActionName)
		if len(javaFiles) > 0 {
			nestedDepth := types.OptInt(opts.NestedJarsDepth, 1)
			if nestedDepth == 0 {
				nestedDepth = 1
			}
			for _, r := range appjava.ScanJars(javaFiles, targetImage, nestedDepth) {
				results = append(results, types.ScanResult{
					Target:   types.ContainerTarget{Image: targetImage},
					Identity: r.Identity,
					Facts:    r.Facts,
				})
			}
		}
	}

	// Python pip scanning.
	{
		pyFiles := layers.AllPathContents(inputspython.ActionName)
		if len(pyFiles) > 0 {
			for _, r := range appython.ScanPip(pyFiles) {
				results = append(results, types.ScanResult{
					Target:   types.ContainerTarget{Image: targetImage},
					Identity: r.Identity,
					Facts:    r.Facts,
				})
			}
		}
	}

	// PHP Composer scanning.
	{
		phpFiles := layers.AllPathContents(inputsphp.ActionName)
		if len(phpFiles) > 0 {
			for _, r := range appphp.ScanComposer(phpFiles) {
				results = append(results, types.ScanResult{
					Target:   types.ContainerTarget{Image: targetImage},
					Identity: r.Identity,
					Facts:    r.Facts,
				})
			}
		}
	}

	// Go binary scanning.
	{
		goFiles := layers.AllPathContents(inputsnode.ActionName)
		if len(goFiles) > 0 {
			for _, r := range gobinary.ScanGoBinaries(goFiles) {
				results = append(results, types.ScanResult{
					Target:   types.ContainerTarget{Image: targetImage},
					Identity: r.Identity,
					Facts:    r.Facts,
				})
			}
		}
	}

	return results
}

// resolveArchive returns (archivePath, cleanupFn, error).
// For archive-type images, archivePath comes directly from the path.
// For Identifier-type images, it pulls from the registry.
func resolveArchive(ctx context.Context, targetImage string, imgType image.ImageType, opts types.PluginOptions) (string, func(), error) {
	if imgType == image.Identifier {
		result, err := registry.GetImageArchive(ctx, targetImage, opts)
		if err != nil {
			return "", nil, fmt.Errorf("pulling image %s: %w", targetImage, err)
		}
		return result.Path, result.Cleanup, nil
	}

	archivePath, err := image.GetArchivePath(targetImage)
	if err != nil {
		return "", nil, err
	}
	return archivePath, nil, nil
}

// buildExtractActions returns the full set of actions needed for a complete scan.
func buildExtractActions() []extractor.ExtractAction {
	actions := make([]extractor.ExtractAction, 0, 30)
	// OS release.
	actions = append(actions, inputsos.Actions...)
	// OS package managers.
	actions = append(actions, inputsapk.Actions()...)
	actions = append(actions, inputsapt.Actions()...)
	actions = append(actions, inputsrpm.Actions()...)
	// Application scanners.
	actions = append(actions, inputsjava.Actions()...)
	actions = append(actions, inputspython.Actions()...)
	actions = append(actions, inputsphp.Actions()...)
	actions = append(actions, inputsnode.Actions()...) // Go binary scanner
	return actions
}

// detectOSRelease reads OS release file contents from merged layers.
func detectOSRelease(layers extractor.MergedLayers) *osrelease.OSRelease {
	parsers := map[string]func(string) (*osrelease.OSRelease, error){
		"/etc/os-release":      osrelease.TryOSRelease,
		"/usr/lib/os-release":  osrelease.TryOSRelease,
		"/etc/lsb-release":     osrelease.TryLsbRelease,
		"/etc/debian_version":  osrelease.TryDebianVersion,
		"/etc/alpine-release":  osrelease.TryAlpineRelease,
		"/etc/redhat-release":  osrelease.TryRedHatRelease,
		"/etc/oracle-release":  osrelease.TryOracleRelease,
		"/etc/centos-release":  osrelease.TryCentosRelease,
	}
	// Process in priority order matching TS.
	priorityPaths := []string{
		"/etc/os-release", "/usr/lib/os-release", "/etc/lsb-release",
		"/etc/debian_version", "/etc/alpine-release", "/etc/redhat-release",
		"/etc/oracle-release", "/etc/centos-release",
	}
	for _, action := range inputsos.Actions {
		for _, path := range priorityPaths {
			content := layers.GetContentByPath(action.ActionName, path)
			if len(content) == 0 {
				continue
			}
			parseFn, ok := parsers[path]
			if !ok {
				continue
			}
			rel, err := parseFn(string(content))
			if err == nil && rel != nil {
				return rel
			}
		}
	}
	return nil
}

// runPackageParsers runs all OS package parsers over extracted layers.
func runPackageParsers(ctx context.Context, layers extractor.MergedLayers, osRel *osrelease.OSRelease) []parser.ImagePackagesAnalysis {
	var analyses []parser.ImagePackagesAnalysis

	// APK
	if content := layers.GetContent(inputsapk.ActionName); len(content) > 0 {
		pkgs, err := pkgpkgs.ParseAPKDatabase(string(content))
		if err == nil && len(pkgs) > 0 {
			analyses = append(analyses, parser.ImagePackagesAnalysis{
				AnalyzeType: parser.AnalysisTypeApk,
				Packages:    convertPackages(pkgs),
			})
		}
	}

	// DEB
	if dpkgContent := layers.GetContent(inputsapt.ActionNameDpkg); len(dpkgContent) > 0 {
		pkgs, err := pkgpkgs.ParseDPKGStatus(string(dpkgContent), osRel)
		if err == nil && len(pkgs) > 0 {
			if extContent := layers.GetContent(inputsapt.ActionNameExt); len(extContent) > 0 {
				pkgpkgs.SetAutoInstalled(string(extContent), pkgs)
			}
			analyses = append(analyses, parser.ImagePackagesAnalysis{
				AnalyzeType: parser.AnalysisTypeApt,
				Packages:    convertPackages(pkgs),
			})
		}
	}

	// RPM (BDB, NDB, SQLite) — try all three, use first that yields packages.
	rpmPkgs := parseRPM(ctx, layers)
	if len(rpmPkgs) > 0 {
		analyses = append(analyses, parser.ImagePackagesAnalysis{
			AnalyzeType: parser.AnalysisTypeRpm,
			Packages:    rpmPkgs,
		})
	}

	return analyses
}

// parseRPM tries BDB → NDB → SQLite RPM database formats.
func parseRPM(_ context.Context, layers extractor.MergedLayers) []deptree.AnalyzedPackage {
	// BDB
	if content := layers.GetContent(inputsrpm.ActionNameBDB); len(content) > 0 {
		pkgs, err := pkgpkgs.ParseRPMBDB(content)
		if err == nil && len(pkgs) > 0 {
			return rpmToDepTree(pkgs)
		}
	}
	// NDB
	if content := layers.GetContent(inputsrpm.ActionNameNDB); len(content) > 0 {
		pkgs, err := pkgpkgs.ParseRPMNDB(content)
		if err == nil && len(pkgs) > 0 {
			return rpmToDepTree(pkgs)
		}
	}
	// SQLite
	if content := layers.GetContent(inputsrpm.ActionNameSQLite); len(content) > 0 {
		pkgs, err := pkgpkgs.ParseRPMSQLite(content)
		if err == nil && len(pkgs) > 0 {
			return rpmToDepTree(pkgs)
		}
	}
	return nil
}

func rpmToDepTree(pkgs []pkgpkgs.RPMPackage) []deptree.AnalyzedPackage {
	out := make([]deptree.AnalyzedPackage, len(pkgs))
	for i, p := range pkgs {
		out[i] = deptree.AnalyzedPackage{
			Name:    p.Name,
			Version: p.FullVersion(),
			Purl:    p.Purl,
			Deps:    map[string]bool{},
		}
	}
	return out
}

func convertPackages(pkgs []pkgpkgs.AnalyzedPackage) []deptree.AnalyzedPackage {
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

func assembleFacts(
	depGraph types.DepGraphData,
	result *extractor.ExtractionResult,
	osRel *osrelease.OSRelease,
	platform string,
) []types.Fact {
	facts := []types.Fact{
		{Type: types.FactDepGraph, Data: depGraph},
		{Type: types.FactImageID, Data: result.ImageID},
		{Type: types.FactImageLayers, Data: result.ManifestLayers},
	}
	if len(result.ImageLabels) > 0 {
		facts = append(facts, types.Fact{Type: types.FactImageLabels, Data: result.ImageLabels})
	}
	if result.ContainerConfig != nil {
		facts = append(facts, types.Fact{Type: types.FactContainerConfig, Data: containerConfigFact(result.ContainerConfig)})
	}
	if len(result.History) > 0 {
		facts = append(facts, types.Fact{Type: types.FactHistory, Data: historyFacts(result.History)})
	}
	if result.ImageCreationTime != "" {
		facts = append(facts, types.Fact{Type: types.FactImageCreationTime, Data: result.ImageCreationTime})
	}
	if len(result.RootFsLayers) > 0 {
		facts = append(facts, types.Fact{Type: types.FactRootFs, Data: result.RootFsLayers})
	}
	if osRel != nil && osRel.PrettyName != "" {
		facts = append(facts, types.Fact{Type: types.FactImageOsReleasePrettyName, Data: osRel.PrettyName})
	}
	facts = append(facts, types.Fact{Type: types.FactPlatform, Data: platform})
	facts = append(facts, types.Fact{Type: types.FactPluginVersion, Data: pluginVersion})
	return facts
}

func imageRootNameVersion(targetImage string) (name, version string) {
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
