package parser_test

import (
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/deptree"
	"github.com/snyk/snyk-docker-plugin/pkg/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAnalysisResults_empty(t *testing.T) {
	result := parser.ParseAnalysisResults("nginx:latest", nil, "sha256:abc", nil, "linux/amd64", nil)
	assert.Equal(t, "linux", result.PackageFormat)
	assert.Nil(t, result.DepInfos)
	assert.Equal(t, "sha256:abc", result.ImageID)
}

func TestParseAnalysisResults_apk(t *testing.T) {
	pkgs := []deptree.AnalyzedPackage{
		{Name: "musl", Version: "1.1.24"},
	}
	analyses := []parser.ImagePackagesAnalysis{
		{AnalyzeType: parser.AnalysisTypeApk, Packages: pkgs},
	}
	result := parser.ParseAnalysisResults("alpine:3.12", analyses, "sha256:xyz", nil, "linux/amd64", nil)
	assert.Equal(t, "apk", result.PackageFormat)
	require.Len(t, result.DepInfos, 1)
}

func TestParseAnalysisResults_apt(t *testing.T) {
	pkgs := []deptree.AnalyzedPackage{{Name: "curl", Version: "7.74.0"}}
	analyses := []parser.ImagePackagesAnalysis{
		{AnalyzeType: parser.AnalysisTypeApt, Packages: pkgs},
	}
	result := parser.ParseAnalysisResults("debian:11", analyses, "sha256:d", nil, "linux/amd64", nil)
	assert.Equal(t, "deb", result.PackageFormat)
}

func TestParseAnalysisResults_chisel(t *testing.T) {
	pkgs := []deptree.AnalyzedPackage{{Name: "base-files_base", Version: "1"}}
	analyses := []parser.ImagePackagesAnalysis{
		{AnalyzeType: parser.AnalysisTypeChisel, Packages: pkgs},
	}
	result := parser.ParseAnalysisResults("ubuntu:chisel", analyses, "sha256:c", nil, "linux/amd64", nil)
	assert.Equal(t, "deb", result.PackageFormat)
}

func TestParseAnalysisResults_firstNonEmptyWins(t *testing.T) {
	analyses := []parser.ImagePackagesAnalysis{
		{AnalyzeType: parser.AnalysisTypeApk, Packages: nil}, // empty — skip
		{AnalyzeType: parser.AnalysisTypeApt, Packages: []deptree.AnalyzedPackage{
			{Name: "curl", Version: "7.74.0"},
		}},
	}
	result := parser.ParseAnalysisResults("img", analyses, "sha256:x", nil, "", nil)
	assert.Equal(t, "deb", result.PackageFormat)
}

func TestPackageFormatFor(t *testing.T) {
	assert.Equal(t, "apk", parser.PackageFormatFor(parser.AnalysisTypeApk))
	assert.Equal(t, "deb", parser.PackageFormatFor(parser.AnalysisTypeApt))
	assert.Equal(t, "deb", parser.PackageFormatFor(parser.AnalysisTypeChisel))
	assert.Equal(t, "rpm", parser.PackageFormatFor(parser.AnalysisTypeRpm))
	assert.Equal(t, "linux", parser.PackageFormatFor(parser.AnalysisTypeLinux))
}
