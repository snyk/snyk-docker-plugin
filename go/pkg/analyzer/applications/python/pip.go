// Package python provides Python application dependency scanning.
package python

// PipRequirement represents a single pip requirement.
type PipRequirement struct {
	Name    string
	Version string
}

// ParseRequirements parses a requirements.txt file.
func ParseRequirements(content string) ([]PipRequirement, error) {
	// TODO: full implementation
	return nil, nil
}
