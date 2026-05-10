// Package java provides JAR fingerprinting for the Java ecosystem.
// It mirrors lib/analyzer/applications/java.ts.
package java

import (
	"archive/zip"
	"bytes"
	"crypto/sha1" //nolint:gosec // SHA-1 is mandated by the TS implementation for JAR fingerprinting
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/snyk/snyk-docker-plugin/pkg/types"
)

// JarCoords holds Maven coordinates extracted from pom.properties.
type JarCoords struct {
	GroupID    string `json:"groupId,omitempty"`
	ArtifactID string `json:"artifactId,omitempty"`
	Version    string `json:"version,omitempty"`
}

// JarDependency is a dependency coord found in a JAR's pom.properties.
type JarDependency struct {
	GroupID    string `json:"groupId,omitempty"`
	ArtifactID string `json:"artifactId,omitempty"`
	Version    string `json:"version,omitempty"`
}

// JarFingerprint is the wire format emitted for each JAR, matching the TS type.
type JarFingerprint struct {
	Location   string          `json:"location"`
	Digest     *string         `json:"digest"`
	GroupID    string          `json:"groupId,omitempty"`
	ArtifactID string          `json:"artifactId,omitempty"`
	Version    string          `json:"version,omitempty"`
	Deps       []JarDependency `json:"dependencies"`
}

// JarFingerprintsData is the Data payload for FactJarFingerprints.
type JarFingerprintsData struct {
	Fingerprints []JarFingerprint `json:"fingerprints"`
	Origin       string           `json:"origin"`
	Path         string           `json:"path"`
}

// AppScanResult is one scan result per directory containing JARs.
type AppScanResult struct {
	Identity types.Identity
	Facts    []types.Fact
}

// pomPropertiesOverrides lists groupId:artifactId combos that should
// be resolved by SHA lookup rather than pom.properties coords.
var pomPropertiesOverrides = map[string]bool{
	"com.microsoft.sqlserver:mssql-jdbc": true,
}

// ScanJars walks all jar bytes in pathToContent, fingerprints them,
// and returns one AppScanResult per directory.
// pathToContent maps absolute paths → raw JAR bytes.
// nestedJarsDepth mirrors --nested-jars-depth (default 1).
func ScanJars(pathToContent map[string][]byte, targetImage string, nestedJarsDepth int) []AppScanResult {
	// Group JARs by directory.
	byDir := map[string][]jarEntry{}
	for path, data := range pathToContent {
		if !isJarPath(path) {
			continue
		}
		dir := filepath.Dir(path)
		byDir[dir] = append(byDir[dir], jarEntry{location: path, data: data})
	}

	var results []AppScanResult
	for dir, jars := range byDir {
		fingerprints := fingerprintJars(jars, nestedJarsDepth, 0)
		if len(fingerprints) == 0 {
			continue
		}
		results = append(results, AppScanResult{
			Identity: types.Identity{
				Type:       "maven",
				TargetFile: dir,
			},
			Facts: []types.Fact{{
				Type: types.FactJarFingerprints,
				Data: JarFingerprintsData{
					Fingerprints: fingerprints,
					Origin:       targetImage,
					Path:         dir,
				},
			}},
		})
	}
	return results
}

type jarEntry struct {
	location string
	data     []byte
}

func isJarPath(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".jar" || ext == ".war" || ext == ".ear"
}

// fingerprintJars recursively unpacks and fingerprints JAR entries.
// depth is the current unpack level (starts at 0).
func fingerprintJars(jars []jarEntry, desiredDepth, depth int) []JarFingerprint {
	// We always unpack one level more than desired to read pom.properties.
	requiredDepth := desiredDepth + 1

	var fingerprints []JarFingerprint
	for _, jar := range jars {
		info, nestedJars := unpackJar(jar, desiredDepth, requiredDepth, depth+1)

		// Only JAR files get fingerprinted; WAR/EAR are merely containers.
		if jar.location != "" && strings.ToLower(filepath.Ext(jar.location)) == ".jar" {
			fingerprints = append(fingerprints, buildFingerprint(info))
		}

		if len(nestedJars) > 0 {
			nested := fingerprintJars(nestedJars, desiredDepth, depth+1)
			fingerprints = append(fingerprints, nested...)
		}
	}
	return fingerprints
}

type jarInfo struct {
	location string
	data     []byte
	coords   *JarCoords
	deps     []JarDependency
}

func unpackJar(jar jarEntry, desiredDepth, requiredDepth, unpackedLevels int) (jarInfo, []jarEntry) {
	info := jarInfo{location: jar.location, data: jar.data}

	zr, err := zip.NewReader(bytes.NewReader(jar.data), int64(len(jar.data)))
	if err != nil {
		// Not a valid zip/jar — return as-is.
		return info, nil
	}

	var nestedJars []jarEntry
	for _, f := range zr.File {
		name := f.Name
		if strings.HasSuffix(name, "pom.properties") {
			rc, err := f.Open()
			if err != nil {
				continue
			}
			raw, _ := io.ReadAll(rc)
			rc.Close()
			coords := parsePomProperties(string(raw))
			if coords != nil {
				// Determine if these coords belong to the jar itself or a dep.
				if isOwnCoords(jar.location, coords) {
					info.coords = coords
				} else {
					info.deps = append(info.deps, JarDependency{
						GroupID:    coords.GroupID,
						ArtifactID: coords.ArtifactID,
						Version:    coords.Version,
					})
				}
			}
		}
		// Collect nested JARs if within depth.
		if desiredDepth > 0 && unpackedLevels < requiredDepth && strings.HasSuffix(name, ".jar") {
			rc, err := f.Open()
			if err != nil {
				continue
			}
			nestedData, _ := io.ReadAll(rc)
			rc.Close()
			nestedJars = append(nestedJars, jarEntry{
				location: jar.location + "/" + name,
				data:     nestedData,
			})
		}
	}
	return info, nestedJars
}

func isOwnCoords(jarPath string, coords *JarCoords) bool {
	base := filepath.Base(jarPath)
	// Strip .jar extension.
	base = strings.TrimSuffix(base, filepath.Ext(base))
	return strings.Contains(base, coords.ArtifactID)
}

func buildFingerprint(info jarInfo) JarFingerprint {
	fp := JarFingerprint{
		Location: info.location,
		Deps:     info.deps,
	}
	if fp.Deps == nil {
		fp.Deps = []JarDependency{}
	}
	if info.coords != nil {
		fp.GroupID = info.coords.GroupID
		fp.ArtifactID = info.coords.ArtifactID
		fp.Version = info.coords.Version
		// coords present → no SHA digest needed.
		fp.Digest = nil
	} else {
		// No coords → compute SHA-1 digest for maven-deps fallback.
		digest := sha1sum(info.data)
		fp.Digest = &digest
	}
	return fp
}

// sha1sum computes the hex SHA-1 of data, mirroring TS bufferToSha1().
func sha1sum(data []byte) string {
	h := sha1.New() //nolint:gosec
	h.Write(data)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// ParsePomProperties is the exported entry point for tests.
func ParsePomProperties(content string) *JarCoords {
	return parsePomProperties(content)
}

// parsePomProperties parses a pom.properties file.
// Returns nil if any required field is missing or the coords are overridden.
func parsePomProperties(content string) *JarCoords {
	coords := JarCoords{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "groupId="):
			coords.GroupID = strings.TrimPrefix(line, "groupId=")
		case strings.HasPrefix(line, "artifactId="):
			coords.ArtifactID = strings.TrimPrefix(line, "artifactId=")
		case strings.HasPrefix(line, "version="):
			coords.Version = strings.TrimPrefix(line, "version=")
		}
	}
	if coords.GroupID == "" || coords.ArtifactID == "" || coords.Version == "" {
		return nil
	}
	key := coords.GroupID + ":" + coords.ArtifactID
	if pomPropertiesOverrides[key] {
		return nil
	}
	return &coords
}
