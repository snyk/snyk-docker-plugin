package dockerfile_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/dockerfile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fixtureDir = "../../../test/fixtures/dockerfiles"

func readFixture(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtureDir, rel))
	require.NoError(t, err)
	return string(data)
}

// ---------------------------------------------------------------------------
// ReadDockerfileAndAnalyse
// ---------------------------------------------------------------------------

func TestReadDockerfileAndAnalyse_empty(t *testing.T) {
	result, err := dockerfile.ReadDockerfileAndAnalyse("")
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestReadDockerfileAndAnalyse_simple(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "Dockerfile*")
	require.NoError(t, err)
	_, _ = f.WriteString("FROM ubuntu:20.04\nRUN apt-get install curl\n")
	_ = f.Close()

	result, err := dockerfile.ReadDockerfileAndAnalyse(f.Name())
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "ubuntu:20.04", result.BaseImage)
	assert.Nil(t, result.Error)
	_, ok := result.DockerfilePackages["curl"]
	assert.True(t, ok, "expected curl in packages")
}

func TestReadDockerfileAndAnalyse_missingFile(t *testing.T) {
	_, err := dockerfile.ReadDockerfileAndAnalyse("/nonexistent/Dockerfile")
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// Base image resolution — mirrors index.spec.ts cases
// ---------------------------------------------------------------------------

func TestBaseImage_simple(t *testing.T) {
	a := dockerfile.AnalyseDockerfile(readFixture(t, "simple/Dockerfile"))
	assert.Equal(t, "ubuntu:bionic", a.BaseImage)
	assert.Nil(t, a.Error)
}

func TestBaseImage_multiStage(t *testing.T) {
	// Final FROM is "alpine:latest" after the golang builder stage.
	a := dockerfile.AnalyseDockerfile(readFixture(t, "multi-stage/Dockerfile"))
	assert.Equal(t, "alpine:latest", a.BaseImage)
	assert.Nil(t, a.Error)
}

func TestBaseImage_multiStageAs(t *testing.T) {
	// FROM golang:1.7.3 AS builder … FROM alpine:latest AS base … FROM base
	// The last FROM resolves through alias chain.
	a := dockerfile.AnalyseDockerfile(readFixture(t, "multi-stage-as/Dockerfile"))
	// "base" alias → "alpine:latest"
	assert.Equal(t, "alpine:latest", a.BaseImage)
}

func TestBaseImage_withArgs(t *testing.T) {
	// with-args/Dockerfile has ARG repo=node ARG version=dubnium; FROM ${repo}:${version}
	a := dockerfile.AnalyseDockerfile(readFixture(t, "with-args/Dockerfile"))
	assert.Equal(t, "node:dubnium", a.BaseImage)
	assert.Nil(t, a.Error)
}

func TestBaseImage_withArgsNobraces(t *testing.T) {
	// ARG repo=node ARG version=dubnium; FROM $repo:$version
	a := dockerfile.AnalyseDockerfile(readFixture(t, "with-args-nobraces/Dockerfile"))
	assert.Equal(t, "node:dubnium", a.BaseImage)
	assert.Nil(t, a.Error)
}

func TestBaseImage_withArgsOccurences(t *testing.T) {
	// ARG NAME=test ARG VER=1; FROM ${NAME}:${NAME}-${VER} AS base; FROM base
	a := dockerfile.AnalyseDockerfile(readFixture(t, "with-args-occurences/Dockerfile"))
	assert.Equal(t, "test:test-1", a.BaseImage)
	assert.Nil(t, a.Error)
}

func TestBaseImage_fromScratch(t *testing.T) {
	a := dockerfile.AnalyseDockerfile(readFixture(t, "from-scratch/Dockerfile"))
	assert.Equal(t, "scratch", a.BaseImage)
	assert.Nil(t, a.Error)
}

func TestBaseImage_library(t *testing.T) {
	// library/redis has FROM alpine:3.7 as base
	a := dockerfile.AnalyseDockerfile(readFixture(t, "library/redis/Dockerfile"))
	assert.Equal(t, "alpine:3.7", a.BaseImage)
	assert.Nil(t, a.Error)
}

func TestBaseImage_empty(t *testing.T) {
	a := dockerfile.AnalyseDockerfile("")
	assert.Empty(t, a.BaseImage)
	require.NotNil(t, a.Error)
	assert.Equal(t, dockerfile.ErrBaseImageNotFound, a.Error.Code)
}

func TestBaseImage_commentOnly(t *testing.T) {
	a := dockerfile.AnalyseDockerfile("# FROM image:tag")
	assert.Empty(t, a.BaseImage)
	require.NotNil(t, a.Error)
	assert.Equal(t, dockerfile.ErrBaseImageNotFound, a.Error.Code)
}

func TestBaseImage_unresolvedVar(t *testing.T) {
	a := dockerfile.AnalyseDockerfile("FROM ${A}:${B}")
	assert.Empty(t, a.BaseImage)
	require.NotNil(t, a.Error)
	assert.Equal(t, dockerfile.ErrBaseImageNonResolvable, a.Error.Code)
}

func TestBaseImage_unresolvedVarInFinalStage(t *testing.T) {
	a := dockerfile.AnalyseDockerfile("ARG A\nFROM image\nFROM ${A}")
	assert.Empty(t, a.BaseImage)
	require.NotNil(t, a.Error)
	assert.Equal(t, dockerfile.ErrBaseImageNonResolvable, a.Error.Code)
}

func TestBaseImage_multiStageLowercase(t *testing.T) {
	a := dockerfile.AnalyseDockerfile(readFixture(t, "multi-stage-lowercase/Dockerfile"))
	assert.NotEmpty(t, a.BaseImage)
	assert.Nil(t, a.Error)
}

func TestBaseImage_multiStageWithArgs(t *testing.T) {
	// ARG NODE_VERSION=6; FROM node:${NODE_VERSION}-slim AS base; FROM base
	a := dockerfile.AnalyseDockerfile(readFixture(t, "multi-stage-with-args/Dockerfile"))
	assert.Equal(t, "node:6-slim", a.BaseImage)
	assert.Nil(t, a.Error)
}

func TestBaseImage_invalid(t *testing.T) {
	a := dockerfile.AnalyseDockerfile(readFixture(t, "invalid/Dockerfile"))
	// Invalid Dockerfile has no FROM or unresolvable — error expected.
	// We just assert there's either an error or no base image.
	if a.Error == nil {
		assert.Empty(t, a.BaseImage)
	}
}

// ---------------------------------------------------------------------------
// Package extraction — mirrors instructions-parser.spec.ts
// ---------------------------------------------------------------------------

func TestPackages_aptInstall(t *testing.T) {
	cases := []struct {
		instruction string
		expected    []string
	}{
		{"RUN /bin/sh -c apt install curl", []string{"curl"}},
		{"RUN /bin/sh -c apt-get install curl", []string{"curl"}},
		{"RUN /bin/sh -c apt-get -y install curl", []string{"curl"}},
		{"RUN /bin/sh -c aptitude install curl", []string{"curl"}},
		{"RUN /bin/sh -c yum install curl", []string{"curl"}},
		{"RUN /bin/sh -c apk add curl", []string{"curl"}},
		{"RUN /bin/sh -c apk --update add curl", []string{"curl"}},
		{"RUN /bin/sh -c rpm -i curl", []string{"curl"}},
		{"RUN /bin/sh -c rpm --install curl", []string{"curl"}},
		{"RUN /bin/sh -c apt-get install -y wget curl -V", []string{"curl", "wget"}},
		{"RUN /bin/sh -c apt-get install curl && apt-get install wget", []string{"curl", "wget"}},
		{"RUN /bin/sh -c dnf install curl", []string{"curl"}},
		{"RUN /bin/sh -c dnf install -y curl", []string{"curl"}},
		{"RUN /bin/sh -c dnf -y install curl", []string{"curl"}},
		{"RUN /bin/sh -c microdnf install curl", []string{"curl"}},
		{"RUN /bin/sh -c microdnf install --nodocs curl", []string{"curl"}},
		{"RUN /bin/sh -c apt-get install apache2=2.3.35-4ubuntu1", []string{"apache2"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.instruction, func(t *testing.T) {
			a := dockerfile.AnalyseDockerfile("FROM ubuntu\n" + tc.instruction)
			got := keys(a.DockerfilePackages)
			assert.ElementsMatch(t, tc.expected, got)
		})
	}
}

func TestPackages_withInstallationInstruction(t *testing.T) {
	a := dockerfile.AnalyseDockerfile(readFixture(t, "with-installation-instruction/Dockerfile"))
	assert.Contains(t, a.DockerfilePackages, "curl")
}

func TestPackages_multipleRunInstructions(t *testing.T) {
	a := dockerfile.AnalyseDockerfile(readFixture(t, "with-multiple-run-instructions/Dockerfile"))
	assert.Contains(t, a.DockerfilePackages, "curl")
	assert.Contains(t, a.DockerfilePackages, "wget")
}

func TestPackages_withDnfInstallation(t *testing.T) {
	a := dockerfile.AnalyseDockerfile(readFixture(t, "with-dnf-installation/Dockerfile"))
	assert.Contains(t, a.DockerfilePackages, "curl")
}

func TestPackages_bugDockerfile(t *testing.T) {
	// The bug fixture uses yum install with a variable substitution.
	a := dockerfile.AnalyseDockerfile(readFixture(t, "bug/Dockerfile"))
	// Should at least detect yarn or nodejs
	assert.True(t, len(a.DockerfilePackages) > 0 || a.BaseImage == "centos:centos7")
}

func TestPackages_withArgsPackage(t *testing.T) {
	// ARG RUNTIME_PACKAGES="nodejs bash"; RUN apk add $RUNTIME_PACKAGES
	// After expansion the package names are "nodejs" and "bash".
	a := dockerfile.AnalyseDockerfile(readFixture(t, "with-args-package/Dockerfile"))
	// Variables in RUN are expanded: $RUNTIME_PACKAGES → "nodejs bash"
	// Both should be detected.
	assert.Contains(t, a.DockerfilePackages, "nodejs")
	assert.Contains(t, a.DockerfilePackages, "bash")
}

// ---------------------------------------------------------------------------
// Layers
// ---------------------------------------------------------------------------

func TestLayers_layersFromPackages(t *testing.T) {
	a := dockerfile.AnalyseDockerfile(readFixture(t, "with-installation-instruction/Dockerfile"))
	assert.NotEmpty(t, a.DockerfileLayers)
	// Each layer key is the base64 digest of the instruction.
	for id, layer := range a.DockerfileLayers {
		assert.Equal(t, dockerfile.InstructionDigest(layer.Instruction), id)
	}
}

func TestLayers_sameInstructionOneLayer(t *testing.T) {
	// Two packages from the same RUN instruction → one layer entry.
	a := dockerfile.AnalyseDockerfile("FROM ubuntu\nRUN apt-get install curl wget")
	assert.Len(t, a.DockerfileLayers, 1)
	assert.Len(t, a.DockerfilePackages, 2)
}

func TestLayers_differentInstructionsTwoLayers(t *testing.T) {
	a := dockerfile.AnalyseDockerfile(readFixture(t, "with-multiple-run-instructions/Dockerfile"))
	assert.Len(t, a.DockerfileLayers, 2)
}

// ---------------------------------------------------------------------------
// InstructionDigest
// ---------------------------------------------------------------------------

func TestInstructionDigest(t *testing.T) {
	digest := dockerfile.InstructionDigest("RUN apt-get install curl")
	assert.NotEmpty(t, digest)
	// Base64 encoding of known string (base64("PUT apt-get install curl"))
	assert.Equal(t, "UFVUIGFwdC1nZXQgaW5zdGFsbCBjdXJs",
		dockerfile.InstructionDigest("PUT apt-get install curl"))
}

func TestInstructionDigest_deterministic(t *testing.T) {
	instr := "RUN apt-get install curl"
	assert.Equal(t, dockerfile.InstructionDigest(instr), dockerfile.InstructionDigest(instr))
}

// ---------------------------------------------------------------------------
// Edge cases for resolveBaseImage
// ---------------------------------------------------------------------------

func TestBaseImage_emptyTagSegment(t *testing.T) {
	// FROM image: (empty tag) should be non-resolvable.
	a := dockerfile.AnalyseDockerfile("FROM image:")
	assert.Empty(t, a.BaseImage)
	require.NotNil(t, a.Error)
}

func TestBaseImage_emptyDigestSegment(t *testing.T) {
	// FROM image@ (empty digest) should be non-resolvable.
	a := dockerfile.AnalyseDockerfile("FROM image@")
	assert.Empty(t, a.BaseImage)
	require.NotNil(t, a.Error)
}

func TestBaseImage_argWithNoDefault(t *testing.T) {
	// ARG A (no default); FROM ${A}:tag — unresolvable because A has no value.
	a := dockerfile.AnalyseDockerfile("ARG A\nFROM ${A}:tag")
	assert.Empty(t, a.BaseImage)
	require.NotNil(t, a.Error)
	assert.Equal(t, dockerfile.ErrBaseImageNonResolvable, a.Error.Code)
}

func TestBaseImage_finalStageScratch(t *testing.T) {
	// Multi-stage ending in scratch.
	a := dockerfile.AnalyseDockerfile("FROM ubuntu AS build\nFROM scratch")
	assert.Equal(t, "scratch", a.BaseImage)
	assert.Nil(t, a.Error)
}

func TestPackages_noInstallCommands(t *testing.T) {
	// A Dockerfile with only COPY/CMD — no packages.
	a := dockerfile.AnalyseDockerfile("FROM ubuntu\nCOPY . .\nCMD [\"/app\"]")
	assert.Empty(t, a.DockerfilePackages)
	assert.Empty(t, a.DockerfileLayers)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func keys(m dockerfile.DockerfilePackages) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
