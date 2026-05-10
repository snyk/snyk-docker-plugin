// Package dockerfile provides Dockerfile parsing and base-image analysis.
// Mirrors lib/dockerfile/.
package dockerfile

// DockerfileAnalysis holds the results of analysing a Dockerfile.
// Mirrors lib/dockerfile/types.ts DockerFileAnalysis.
type DockerfileAnalysis struct {
	BaseImage         string            `json:"baseImage,omitempty"`
	DockerfilePackages DockerfilePackages `json:"dockerfilePackages"`
	DockerfileLayers   DockerfileLayers   `json:"dockerfileLayers"`
	Error             *AnalysisError     `json:"error,omitempty"`
}

// AnalysisError mirrors DockerFileAnalysis.error.
type AnalysisError struct {
	Code string `json:"code"`
}

// Error code constants mirror DockerFileAnalysisErrorCode.
const (
	ErrBaseImageNotFound      = "BASE_IMAGE_NAME_NOT_FOUND"
	ErrBaseImageNonResolvable = "BASE_IMAGE_NON_RESOLVABLE"
)

// DockerfilePackages maps a package name to its install metadata.
// Mirrors lib/dockerfile/types.ts DockerFilePackages.
type DockerfilePackages map[string]PackageInstall

// PackageInstall carries the full RUN instruction text and the trimmed
// install sub-command for a package discovered in a Dockerfile.
type PackageInstall struct {
	Instruction    string `json:"instruction"`
	InstallCommand string `json:"installCommand"`
}

// DockerfileLayers maps a layer digest (base64 of instruction) to its
// instruction text. Mirrors lib/dockerfile/types.ts DockerFileLayers.
type DockerfileLayers map[string]LayerInstruction

// LayerInstruction holds a single instruction.
type LayerInstruction struct {
	Instruction string `json:"instruction"`
}
