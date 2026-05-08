// Package packages provides OS package manager parsers.
package packages

import (
	"bufio"
	"strings"
)

// APKPackage represents a single entry in the APK installed database.
type APKPackage struct {
	Name        string
	Version     string
	Description string
	Provides    []string
	Dependencies []string
	Origin      string
}

// ParseAPKDatabase parses /lib/apk/db/installed content.
// Mirrors lib/analyzer/package-managers/apk.ts.
func ParseAPKDatabase(content string) ([]APKPackage, error) {
	var packages []APKPackage
	var current APKPackage
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if current.Name != "" {
				packages = append(packages, current)
				current = APKPackage{}
			}
			continue
		}
		if len(line) < 3 || line[1] != ':' {
			continue
		}
		key := line[0]
		value := strings.TrimSpace(line[2:])
		switch key {
		case 'P':
			current.Name = value
		case 'V':
			current.Version = value
		case 'T':
			current.Description = value
		case 'p':
			for _, p := range strings.Fields(value) {
				current.Provides = append(current.Provides, p)
			}
		case 'D':
			for _, d := range strings.Fields(value) {
				current.Dependencies = append(current.Dependencies, d)
			}
		case 'o':
			current.Origin = value
		}
	}
	if current.Name != "" {
		packages = append(packages, current)
	}
	return packages, scanner.Err()
}
