package types

// PluginOptions mirrors lib/types.ts PluginOptions.
// WARNING: The CLI may pass certain values as strings.
// Sanitise ALL input and do not assume it is the expected type.
type PluginOptions struct {
	// Path can be an image identifier or a path to an OCI / Docker archive.
	Path string `json:"path"`

	// ImageSavePath overrides the default plugin path when pulling images.
	ImageSavePath string `json:"imageSavePath,omitempty"`

	// File is the path to a Dockerfile.
	File string `json:"file,omitempty"`

	// ImageNameAndTag is used by k8s-monitor and DRA to preserve the image
	// identifier when scanning archives.
	ImageNameAndTag string `json:"imageNameAndTag,omitempty"`

	// ImageNameAndDigest is used by k8s-monitor.
	ImageNameAndDigest string `json:"imageNameAndDigest,omitempty"`

	// Digests is used by Docker Registry Agent.
	Digests *Digests `json:"digests,omitempty"`

	// GlobsToFind provides patterns for detecting package manager manifest files.
	GlobsToFind *GlobsToFind `json:"globsToFind,omitempty"`

	// Username / Password for container registry authentication.
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	// Platform e.g. "linux/amd64" or "linux/arm64/v8".
	Platform string `json:"platform,omitempty"`

	// AppVulns (deprecated as of 5.0.0).
	AppVulns interface{} `json:"app-vulns,omitempty"`

	ExcludeAppVulns         interface{} `json:"exclude-app-vulns,omitempty"`
	ExcludeNodeModules      interface{} `json:"exclude-node-modules,omitempty"`
	NestedJarsDepth         interface{} `json:"nested-jars-depth,omitempty"`
	ShadedJarsDepth         interface{} `json:"shaded-jars-depth,omitempty"`
	ExcludeBaseImageVulns   interface{} `json:"exclude-base-image-vulns,omitempty"`
	CollectApplicationFiles interface{} `json:"collect-application-files,omitempty"`
	IncludeSystemJars       interface{} `json:"include-system-jars,omitempty"`
	TargetReference         string      `json:"target-reference,omitempty"`

	ParameterWarnings []string `json:"parameterWarnings,omitempty"`
}

type Digests struct {
	Manifest string `json:"manifest,omitempty"`
	Index    string `json:"index,omitempty"`
}

type GlobsToFind struct {
	Include []string `json:"include"`
	Exclude []string `json:"exclude"`
}

// Options mirrors lib/types.ts Options (for display()).
type Options struct {
	Path          string `json:"path"`
	File          string `json:"file,omitempty"`
	Debug         bool   `json:"debug,omitempty"`
	IsDockerUser  bool   `json:"isDockerUser,omitempty"`
	Config        *OptionsConfig `json:"config,omitempty"`
	// ExcludeBaseImageVulns is needed for formatSuggestions.
	ExcludeBaseImageVulns bool `json:"exclude-base-image-vulns,omitempty"`
}

type OptionsConfig struct {
	DisableSuggestions string `json:"disableSuggestions,omitempty"`
}

// OptBool extracts a bool from an interface{} option value.
// It handles bool, string ("true"/"false"), and int (0/non-zero).
func OptBool(v interface{}) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true" || t == "1" || t == "yes"
	case int:
		return t != 0
	case float64:
		return t != 0
	}
	return false
}

// OptInt extracts an int from an interface{} option value.
func OptInt(v interface{}, defaultVal int) int {
	switch t := v.(type) {
	case int:
		return t
	case float64:
		return int(t)
	case int64:
		return int(t)
	}
	return defaultVal
}
