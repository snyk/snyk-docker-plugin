package dockerfile

import (
	"fmt"
	"os"
	"strings"
)

// ReadDockerfileAndAnalyse reads a Dockerfile and extracts base image info.
// Returns nil, nil if dockerfilePath is empty.
func ReadDockerfileAndAnalyse(dockerfilePath string) (*DockerfileAnalysis, error) {
	if dockerfilePath == "" {
		return nil, nil
	}
	data, err := os.ReadFile(dockerfilePath)
	if err != nil {
		return nil, fmt.Errorf("reading dockerfile: %w", err)
	}
	analysis := &DockerfileAnalysis{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(line), "FROM ") {
			analysis.BaseImage = strings.TrimSpace(line[5:])
			break
		}
	}
	return analysis, nil
}
