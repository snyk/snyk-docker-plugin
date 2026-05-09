package packages

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/snyk/snyk-docker-plugin/pkg/analyzer/osrelease"
)

// debianCodenames maps Debian major version → release codename.
var debianCodenames = map[string]string{
	"8": "jessie", "9": "stretch", "10": "buster", "11": "bullseye",
	"12": "bookworm", "13": "trixie", "unstable": "sid",
}

// dpkgEntry is an internal scratchpad during parsing.
type dpkgEntry struct {
	AnalyzedPackage
	status string
}

// ParseDPKGStatus parses /var/lib/dpkg/status. Only "install ok installed"
// packages are returned. Mirrors lib/analyzer/package-managers/apt.ts.
func ParseDPKGStatus(content string, osRel *osrelease.OSRelease) ([]AnalyzedPackage, error) {
	var pkgs []AnalyzedPackage
	var cur *dpkgEntry

	flush := func() {
		if cur == nil || cur.Name == "" {
			return
		}
		if IsInstalled(cur.status) {
			cur.Purl = Purl(cur.AnalyzedPackage, osRel)
			pkgs = append(pkgs, cur.AnalyzedPackage)
		}
		cur = nil
	}

	scanner := bufio.NewScanner(strings.NewReader(content))
	buf := make([]byte, 0, 256*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue // continuation
		}
		idx := strings.Index(line, ": ")
		if idx < 0 {
			continue
		}
		key, value := line[:idx], line[idx+2:]
		switch key {
		case "Package":
			flush()
			cur = &dpkgEntry{AnalyzedPackage: AnalyzedPackage{Name: value, Deps: map[string]bool{}}}
		case "Version":
			if cur != nil {
				cur.Version = value
			}
		case "Status":
			if cur != nil {
				cur.status = value
			}
		case "Source":
			if cur != nil {
				parts := strings.SplitN(strings.TrimSpace(value), " ", 2)
				cur.Source = parts[0]
				if len(parts) == 2 {
					cur.SourceVersion = strings.Trim(parts[1], "()")
				}
			}
		case "Provides":
			if cur != nil {
				for _, p := range strings.Split(value, ",") {
					name := strings.TrimSpace(strings.SplitN(p, "(", 2)[0])
					name = strings.TrimSpace(strings.SplitN(name, " ", 2)[0])
					if name != "" {
						cur.Provides = append(cur.Provides, name)
					}
				}
			}
		case "Pre-Depends", "Depends":
			if cur != nil {
				parseDepsField(value, cur.Deps)
			}
		}
	}
	flush()
	return pkgs, scanner.Err()
}

// IsInstalled returns true if the dpkg status string means "installed".
func IsInstalled(status string) bool {
	parts := strings.Fields(status)
	return len(parts) >= 3 && parts[2] == "installed"
}

func parseDepsField(value string, deps map[string]bool) {
	for _, elem := range strings.Split(value, ",") {
		alts := strings.SplitN(elem, "|", 2)
		name := strings.TrimSpace(strings.SplitN(alts[0], "(", 2)[0])
		name = strings.TrimSpace(name)
		if name != "" {
			deps[name] = true
		}
	}
}

// SetAutoInstalled marks auto-installed packages from /var/lib/apt/extended_states.
func SetAutoInstalled(extContent string, pkgs []AnalyzedPackage) {
	autoMap := parseExtFile(extContent)
	for i := range pkgs {
		if autoMap[pkgs[i].Name] {
			pkgs[i].AutoInstalled = true
		}
	}
}

func parseExtFile(content string) map[string]bool {
	result := map[string]bool{}
	var curPkg string
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.Index(line, ": ")
		if idx < 0 {
			continue
		}
		key, value := line[:idx], line[idx+2:]
		switch key {
		case "Package":
			curPkg = value
		case "Auto-Installed":
			if value == "1" && curPkg != "" {
				result[curPkg] = true
			}
		}
	}
	return result
}

// Purl generates a deb package-URL. Mirrors apt.ts purl().
func Purl(pkg AnalyzedPackage, osRel *osrelease.OSRelease) string {
	if pkg.Name == "" || pkg.Version == "" {
		return ""
	}
	var qParts []string
	if pkg.Source != "" && pkg.SourceVersion != "" {
		qParts = append(qParts, "upstream="+pkg.Source+"@"+pkg.SourceVersion)
	} else if pkg.Source != "" {
		qParts = append(qParts, "upstream="+pkg.Source)
	}
	vendor := ""
	if osRel != nil {
		codename, ok := debianCodenames[osRel.Version]
		if !ok {
			codename = osRel.Version
		}
		qParts = append(qParts, "distro="+osRel.Name+"-"+codename)
		vendor = osRel.Name
	}
	q := ""
	if len(qParts) > 0 {
		q = "?" + strings.Join(qParts, "&")
	}
	return fmt.Sprintf("pkg:deb/%s/%s@%s%s", vendor, pkg.Name, pkg.Version, q)
}
