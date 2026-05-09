package packages

import (
	"bufio"
	"strings"
)

// ParseAPKDatabase parses /lib/apk/db/installed content into []AnalyzedPackage.
// Mirrors lib/analyzer/package-managers/apk.ts parseFile/parseLine exactly.
func ParseAPKDatabase(content string) ([]AnalyzedPackage, error) {
	var pkgs []AnalyzedPackage
	var cur *AnalyzedPackage
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if cur != nil && cur.Name != "" {
				pkgs = append(pkgs, *cur)
				cur = nil
			}
			continue
		}
		if len(line) < 2 {
			continue
		}
		key := line[0]
		// Lines have format "K:value"; skip if not that format.
		if len(line) < 3 || line[1] != ':' {
			continue
		}
		value := strings.TrimSpace(line[2:])
		switch key {
		case 'P': // Package name
			cur = &AnalyzedPackage{
				Name: value,
				Deps: map[string]bool{},
			}
		case 'V': // Version
			if cur != nil {
				cur.Version = value
			}
		case 'p': // Provides (space-separated; strip =version suffix)
			if cur != nil {
				for _, p := range strings.Fields(value) {
					name := strings.SplitN(p, "=", 2)[0]
					cur.Provides = append(cur.Provides, name)
				}
			}
		case 'r', 'D': // Depends (r = run-time deps, D = dependencies)
			if cur != nil {
				for _, d := range strings.Fields(value) {
					if strings.HasPrefix(d, "!") {
						continue // negated dep — skip
					}
					name := strings.SplitN(d, "=", 2)[0]
					// Also strip comparison operators.
					for _, op := range []string{">=", "<=", ">", "<", "~="} {
						if idx := strings.Index(name, op); idx >= 0 {
							name = name[:idx]
						}
					}
					if name != "" {
						cur.Deps[name] = true
					}
				}
			}
		case 'o': // Origin / Source
			if cur != nil {
				cur.Source = value
			}
		}
	}
	if cur != nil && cur.Name != "" {
		pkgs = append(pkgs, *cur)
	}
	return pkgs, scanner.Err()
}
