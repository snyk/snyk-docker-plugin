// Package parser converts package-manager analysis results into dep-graph inputs.
// Mirrors lib/parser/index.ts parseAnalysisResults().
package parser

import (
	"strings"

	"github.com/snyk/snyk-docker-plugin/pkg/analyzer/osrelease"
	"github.com/snyk/snyk-docker-plugin/pkg/depgraph"
	"github.com/snyk/snyk-docker-plugin/pkg/deptree"
)

// AnalysisType enumerates the OS package manager types.
type AnalysisType string

const (
	AnalysisTypeApk    AnalysisType = "Apk"
	AnalysisTypeApt    AnalysisType = "Apt"
	AnalysisTypeRpm    AnalysisType = "Rpm"
	AnalysisTypeChisel AnalysisType = "Chisel"
	AnalysisTypeLinux  AnalysisType = "linux"
)

// ImagePackagesAnalysis holds the result of one package-manager analysis pass.
type ImagePackagesAnalysis struct {
	AnalyzeType AnalysisType
	Packages    []deptree.AnalyzedPackage
}

// ParsedResult is the output of ParseAnalysisResults.
type ParsedResult struct {
	PackageFormat string // "apk", "deb", "rpm", "linux"
	TargetOS      *osrelease.OSRelease
	DepInfos      []depgraph.DepInfo // ready to pass to depgraph.FromDepTree
	ImageID       string
	ImageLayers   []string
	Platform      string
}

// PackageFormatFor maps an AnalysisType to its dep-graph package-format string.
// Mirrors the switch in lib/parser/index.ts parseAnalysisResults.
func PackageFormatFor(t AnalysisType) string {
	switch t {
	case AnalysisTypeApt, AnalysisTypeChisel:
		return "deb"
	default:
		return strings.ToLower(string(t))
	}
}

// ParseAnalysisResults picks the first non-empty analysis result, determines
// the package format, runs BuildDepInfos, and returns a ParsedResult.
// Mirrors lib/parser/index.ts parseAnalysisResults().
func ParseAnalysisResults(
	targetImage string,
	analyses []ImagePackagesAnalysis,
	imageID string,
	imageLayers []string,
	platform string,
	osRel *osrelease.OSRelease,
) ParsedResult {
	// Find first result with packages.
	var chosen *ImagePackagesAnalysis
	for i := range analyses {
		if len(analyses[i].Packages) > 0 {
			chosen = &analyses[i]
			break
		}
	}

	if chosen == nil {
		// Scratch / unknown PM — mirror TS: AnalysisType.Linux, empty deps.
		return ParsedResult{
			PackageFormat: "linux",
			TargetOS:      osRel,
			DepInfos:      nil,
			ImageID:       imageID,
			ImageLayers:   imageLayers,
			Platform:      platform,
		}
	}

	depInfos := deptree.BuildDepInfos(chosen.Packages)

	return ParsedResult{
		PackageFormat: PackageFormatFor(chosen.AnalyzeType),
		TargetOS:      osRel,
		DepInfos:      depInfos,
		ImageID:       imageID,
		ImageLayers:   imageLayers,
		Platform:      platform,
	}
}
