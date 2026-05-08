// Package dockerfile provides Dockerfile parsing and base-image analysis.
package dockerfile

// DockerfileAnalysis holds the results of analysing a Dockerfile.
type DockerfileAnalysis struct {
	BaseImage string `json:"baseImage,omitempty"`
}
