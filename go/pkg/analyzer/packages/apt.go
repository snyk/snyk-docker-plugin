package packages

import (
	"bufio"
	"strings"
)

// DPKGPackage represents a single entry in /var/lib/dpkg/status.
type DPKGPackage struct {
	Name        string
	Version     string
	Status      string
	Depends     []string
	PreDepends  []string
	Provides    []string
	Arch        string
}

// ParseDPKGStatus parses /var/lib/dpkg/status content.
// Mirrors lib/analyzer/package-managers/apt.ts.
func ParseDPKGStatus(content string) ([]DPKGPackage, error) {
	var packages []DPKGPackage
	var current DPKGPackage
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if current.Name != "" {
				packages = append(packages, current)
				current = DPKGPackage{}
			}
			continue
		}
		if strings.HasPrefix(line, " ") {
			// continuation line
			continue
		}
		colon := strings.Index(line, ": ")
		if colon < 0 {
			continue
		}
		key := line[:colon]
		value := line[colon+2:]
		switch strings.ToLower(key) {
		case "package":
			current.Name = value
		case "version":
			current.Version = value
		case "status":
			current.Status = value
		case "architecture":
			current.Arch = value
		case "depends":
			for _, d := range strings.Split(value, ",") {
				d = strings.TrimSpace(strings.SplitN(d, "(", 2)[0])
				for _, part := range strings.Split(d, "|") {
					part = strings.TrimSpace(part)
					if part != "" {
						current.Depends = append(current.Depends, part)
					}
				}
			}
		case "pre-depends":
			for _, d := range strings.Split(value, ",") {
				d = strings.TrimSpace(strings.SplitN(d, "(", 2)[0])
				if d != "" {
					current.PreDepends = append(current.PreDepends, d)
				}
			}
		case "provides":
			for _, p := range strings.Split(value, ",") {
				p = strings.TrimSpace(strings.SplitN(p, "(", 2)[0])
				if p != "" {
					current.Provides = append(current.Provides, p)
				}
			}
		}
	}
	if current.Name != "" {
		packages = append(packages, current)
	}
	return packages, scanner.Err()
}

// IsInstalled returns true if the dpkg status line indicates the package is
// installed ("install ok installed").
func IsInstalled(status string) bool {
	parts := strings.Fields(status)
	return len(parts) >= 3 && parts[2] == "installed"
}
