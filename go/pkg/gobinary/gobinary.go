// Package gobinary provides Go binary / build-info parsing.
package gobinary

import (
	"debug/buildinfo"
)

// GoBinaryInfo holds build information extracted from a Go binary.
type GoBinaryInfo struct {
	GoVersion  string
	Path       string
	Deps       []string
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
