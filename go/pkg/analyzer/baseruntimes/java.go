// Package baseruntimes detects base runtime metadata (e.g. Java release files).
package baseruntimes

// BaseRuntime holds metadata about a detected base runtime.
type BaseRuntime struct {
	Type    string `json:"type"`
	Version string `json:"version"`
}

// DetectJavaRuntime detects Java runtime version from JAVA_RELEASE file content.
func DetectJavaRuntime(content string) (*BaseRuntime, error) {
	// TODO: full implementation
	return nil, nil
}
