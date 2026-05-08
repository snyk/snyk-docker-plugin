// Package extractor provides tar-archive reading for docker, OCI and kaniko images.
package extractor

import "io"

// ExtractAction describes a file to look for in an image archive and
// how to process it.
type ExtractAction struct {
	// ActionName is used as the key in ExtractedLayers.
	ActionName string
	// FilePathMatches returns true if the given absolute path in the tar
	// should be processed by this action.
	FilePathMatches func(path string) bool
	// Callback is called with the file reader and size. If nil, the raw
	// []byte contents are returned.
	Callback func(r io.Reader, size int64) (interface{}, error)
}

// ExtractionResult collects everything extracted from an image archive.
type ExtractionResult struct {
	ImageID       string
	ManifestLayers []string
	ExtractedLayers ExtractedLayers
	RootFsLayers  []string
	Platform      string
	ImageLabels   map[string]string
	ImageCreationTime string
	ContainerConfig   *ContainerConfig
	History           []HistoryEntry
}

// ExtractedLayers maps layer name → action name → content.
type ExtractedLayers map[string]map[string]interface{}

// ImageConfig is the image configuration JSON embedded in a docker / OCI archive.
type ImageConfig struct {
	Architecture string          `json:"architecture"`
	OS           string          `json:"os"`
	RootFS       RootFS          `json:"rootfs"`
	Config       *ContainerConfig `json:"config"`
	Created      string          `json:"created"`
	History      []HistoryEntry  `json:"history"`
}

type RootFS struct {
	Type   string   `json:"type"`
	DiffIDs []string `json:"diff_ids"`
}

// ContainerConfig mirrors the Docker image config ContainerConfig section.
type ContainerConfig struct {
	User          string                 `json:"User,omitempty"`
	ExposedPorts  map[string]interface{} `json:"ExposedPorts,omitempty"`
	Env           []string               `json:"Env,omitempty"`
	Entrypoint    []string               `json:"Entrypoint,omitempty"`
	Cmd           []string               `json:"Cmd,omitempty"`
	Volumes       map[string]interface{} `json:"Volumes,omitempty"`
	WorkingDir    string                 `json:"WorkingDir,omitempty"`
	Labels        map[string]string      `json:"Labels,omitempty"`
	StopSignal    string                 `json:"StopSignal,omitempty"`
	ArgsEscaped   *bool                  `json:"ArgsEscaped,omitempty"`
}

// HistoryEntry is a single entry in the image history.
type HistoryEntry struct {
	Created    string `json:"created,omitempty"`
	Author     string `json:"author,omitempty"`
	CreatedBy  string `json:"created_by,omitempty"`
	Comment    string `json:"comment,omitempty"`
	EmptyLayer bool   `json:"empty_layer,omitempty"`
}
