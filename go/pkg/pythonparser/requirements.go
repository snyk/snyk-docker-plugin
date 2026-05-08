// Package pythonparser provides Python lockfile parsing.
package pythonparser

import (
	"bufio"
	"strings"
)

// Requirement is a parsed pip requirement.
type Requirement struct {
	Name    string
	Version string
	Extras  []string
}

// ParseRequirementsTxt parses a requirements.txt file.
func ParseRequirementsTxt(content string) ([]Requirement, error) {
	var reqs []Requirement
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip inline comments.
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		// Handle ==version spec.
		if idx := strings.Index(line, "=="); idx >= 0 {
			reqs = append(reqs, Requirement{
				Name:    strings.TrimSpace(line[:idx]),
				Version: strings.TrimSpace(line[idx+2:]),
			})
		} else {
			reqs = append(reqs, Requirement{Name: line})
		}
	}
	return reqs, scanner.Err()
}
