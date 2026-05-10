// Package gobinary provides Go binary / build-info scanning.
// It uses debug/buildinfo (Go 1.18+) to read module information embedded
// in Go binaries. This mirrors lib/go-parser/ from the TS implementation.
package gobinary

import (
	"debug/buildinfo"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/snyk/snyk-docker-plugin/pkg/depgraph"
	"github.com/snyk/snyk-docker-plugin/pkg/types"
)

// ignoredDirs is the set of top-level directories that cannot contain
// user-installed Go binaries. Mirrors the TS ignoredPaths list.
var ignoredDirs = map[string]bool{
	"/boot": true,
	"/dev":  true,
	"/etc":  true,
	"/home": true,
	"/media": true,
	"/mnt":  true,
	"/proc": true,
	"/root": true,
	"/run":  true,
	"/sbin": true,
	"/sys":  true,
	"/tmp":  true,
	"/var":  true,
}

// GoBinaryInfo holds build information extracted from a Go binary.
type GoBinaryInfo struct {
	GoVersion string
	Path      string
	Deps      []string
}

// AppScanResult is one scan result per discovered Go binary.
type AppScanResult struct {
	Identity types.Identity
	Facts    []types.Fact
}

// ReadBuildInfo reads Go build info from a binary file at path.
func ReadBuildInfo(path string) (*GoBinaryInfo, error) {
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return nil, err
	}
	result := &GoBinaryInfo{
		GoVersion: info.GoVersion,
		Path:      info.Path,
	}
	for _, dep := range info.Deps {
		result.Deps = append(result.Deps, dep.Path+"@"+dep.Version)
	}
	return result, nil
}

// ReadBuildInfoFromReader reads Go build info from a reader by writing to a
// temp file first (buildinfo.ReadFile requires seekable access).
func ReadBuildInfoFromReader(r io.Reader) (*buildinfo.BuildInfo, error) {
	tmp, err := os.CreateTemp("", "gobinary-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if _, err := io.Copy(tmp, r); err != nil {
		return nil, err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return buildinfo.ReadFile(tmp.Name())
}

// FilePathMatches returns true for paths that could contain Go binaries:
// no extension, not in an ignored top-level directory.
func FilePathMatches(path string) bool {
	// Must have no file extension.
	if filepath.Ext(filepath.Base(path)) != "" {
		return false
	}
	// Check if any ignored top-level prefix matches.
	clean := filepath.ToSlash(path)
	if !strings.HasPrefix(clean, "/") {
		clean = "/" + clean
	}
	for ignored := range ignoredDirs {
		if clean == ignored || strings.HasPrefix(clean, ignored+"/") {
			return false
		}
	}
	return true
}

// ScanGoBinaries inspects candidate files from the extracted image layers.
// pathToContent maps absolute paths → raw binary bytes.
// Returns one AppScanResult per binary that contains valid Go build info.
func ScanGoBinaries(pathToContent map[string][]byte) []AppScanResult {
	var results []AppScanResult
	for path, data := range pathToContent {
		if !FilePathMatches(path) {
			continue
		}
		info, err := buildinfo.Read(strings.NewReader("")) // sentinel
		_ = info
		_ = err
		// Use the reader variant to avoid disk I/O in tests.
		bi, err := readBuildInfoFromBytes(data)
		if err != nil {
			continue // not a Go binary
		}
		result := buildScanResult(path, bi)
		if result != nil {
			results = append(results, *result)
		}
	}
	return results
}

// ScanGoBinariesFromFiles scans real files on disk (used for testing with actual binaries).
func ScanGoBinariesFromFiles(root string) []AppScanResult {
	var results []AppScanResult
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		// Derive the absolute path as it would appear in the image.
		rel, _ := filepath.Rel(root, path)
		imgPath := "/" + filepath.ToSlash(rel)
		if !FilePathMatches(imgPath) {
			return nil
		}
		bi, err := buildinfo.ReadFile(path)
		if err != nil {
			return nil
		}
		result := buildScanResult(imgPath, bi)
		if result != nil {
			results = append(results, *result)
		}
		return nil
	})
	return results
}

func readBuildInfoFromBytes(data []byte) (*buildinfo.BuildInfo, error) {
	tmp, err := os.CreateTemp("", "gobinary-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if _, err := tmp.Write(data); err != nil {
		return nil, err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return buildinfo.ReadFile(tmp.Name())
}

func buildScanResult(imgPath string, bi *buildinfo.BuildInfo) *AppScanResult {
	if bi == nil {
		return nil
	}
	// Build dep-infos from module list.
	var deps []depgraph.DepInfo
	for _, dep := range bi.Deps {
		if dep.Replace != nil {
			deps = append(deps, depgraph.DepInfo{
				Name:    dep.Replace.Path,
				Version: dep.Replace.Version,
			})
		} else {
			deps = append(deps, depgraph.DepInfo{
				Name:    dep.Path,
				Version: dep.Version,
			})
		}
	}
	// Add stdlib.
	if bi.GoVersion != "" {
		deps = append(deps, depgraph.DepInfo{
			Name:    "stdlib",
			Version: bi.GoVersion,
		})
	}

	if bi.Main.Path == "" && len(deps) == 0 {
		return nil
	}

	rootName := bi.Main.Path
	if rootName == "" {
		rootName = imgPath
	}
	dg := depgraph.FromDepTree("gomodules", rootName, bi.Main.Version, deps)

	return &AppScanResult{
		Identity: types.Identity{
			Type:       "gomodules",
			TargetFile: imgPath,
		},
		Facts: []types.Fact{
			{Type: types.FactDepGraph, Data: dg},
		},
	}
}
