package types

// DepGraphData is the JSON wire format produced by @snyk/dep-graph.
// schemaVersion is always "1.2.0".
type DepGraphData struct {
	SchemaVersion string     `json:"schemaVersion"`
	PkgManager    PkgManager `json:"pkgManager"`
	Pkgs          []Pkg      `json:"pkgs"`
	Graph         Graph      `json:"graph"`
}

type PkgManager struct {
	Name         string       `json:"name"`
	Repositories []Repository `json:"repositories,omitempty"`
}

type Repository struct {
	Alias string `json:"alias"`
}

type Graph struct {
	RootNodeID string `json:"rootNodeId"`
	Nodes      []Node `json:"nodes"`
}

type Node struct {
	NodeID string   `json:"nodeId"`
	PkgID  string   `json:"pkgId"`
	Deps   []DepRef `json:"deps"`
}

type DepRef struct {
	NodeID string `json:"nodeId"`
}

type Pkg struct {
	ID   string  `json:"id"`
	Info PkgInfo `json:"info"`
}

type PkgInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// ImageNameInfo mirrors lib/types.ts ImageNameInfo.
type ImageNameInfo struct {
	Names []string `json:"names"`
}

// ManifestFile mirrors lib/types.ts ManifestFile.
type ManifestFile struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Contents string `json:"contents"` // base64-encoded
}
