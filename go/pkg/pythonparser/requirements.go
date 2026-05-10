// Package pythonparser provides Python requirements.txt and dist-info METADATA parsing.
// It mirrors lib/python-parser/requirements-parser.ts and lib/python-parser/metadata-parser.ts.
package pythonparser

import (
	"bufio"
	"path/filepath"
	"regexp"
	"strings"
)

// Specifier is a comparison operator in a requirement line.
type Specifier string

const (
	SpecEq  Specifier = "=="
	SpecGte Specifier = ">="
	SpecLte Specifier = "<="
	SpecGt  Specifier = ">"
	SpecLt  Specifier = "<"
	SpecNe  Specifier = "!="
	SpecCom Specifier = "~="
	SpecAEq Specifier = "==="
)

// Requirement is a parsed pip requirement line.
type Requirement struct {
	Name      string
	Specifier Specifier
	Version   string
	Extras    []string
}

// versionParseRE mirrors the TS regex:
// /^(?<name>[\w.-]+)((\[(?<extras>.*)\])?)(((?<specifier><|<=|!=|==|>=|>|~=|===)(?<version>[\w.]*))?)/
// We allow optional whitespace before the specifier so that Metadata-style
// lines such as "Werkzeug >=2.2.0" (spaces after name) are handled.
var versionParseRE = regexp.MustCompile(
	`^(?P<name>[\w.-]+)(?:\[(?P<extras>[^\]]*)\])?\s*(?:(?P<specifier>===|~=|==|!=|<=|>=|<|>)\s*(?P<version>[\w.]*))?`,
)

// ParseRequirementsTxt parses a requirements.txt file content.
// Comments (lines starting with #) and blank lines are skipped.
// Inline comments are stripped.
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
		req := parseSingleRequirement(line)
		if req != nil {
			reqs = append(reqs, *req)
		}
	}
	return reqs, scanner.Err()
}

func parseSingleRequirement(line string) *Requirement {
	m := versionParseRE.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	names := versionParseRE.SubexpNames()
	groups := map[string]string{}
	for i, name := range names {
		if name != "" {
			groups[name] = m[i]
		}
	}
	name := strings.ToLower(groups["name"])
	if name == "" {
		return nil
	}
	var extras []string
	if groups["extras"] != "" {
		for _, e := range strings.Split(groups["extras"], ",") {
			e = strings.TrimSpace(e)
			if e != "" {
				extras = append(extras, strings.ToLower(e))
			}
		}
	}
	return &Requirement{
		Name:      name,
		Specifier: Specifier(groups["specifier"]),
		Version:   groups["version"],
		Extras:    extras,
	}
}

// --- METADATA parser (dist-info METADATA files) ---

// PythonPackage represents a Python package from a dist-info METADATA file.
type PythonPackage struct {
	Name         string
	Version      string
	Dependencies []Requirement
}

// requiresDistRE parses a Requires-Dist line.
// Example: "Requires-Dist: Werkzeug (>=2.2.0)"
var requiresDistRE = regexp.MustCompile(
	`^(?P<name>[\w.-]+)(?:\[(?P<extras>[^\]]*)\])?\s*(?:\(?(?P<specifier>===|~=|==|!=|<=|>=|<|>)\s*(?P<version>[\w.]+)\)?)?`,
)

// ParseDistInfoMetadata parses a dist-info METADATA file.
func ParseDistInfoMetadata(content string) (*PythonPackage, error) {
	const (
		pfxName    = "Name: "
		pfxVersion = "Version: "
		pfxDep     = "Requires-Dist: "
	)
	var name, version string
	var deps []Requirement

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, pfxName):
			name = strings.ToLower(strings.TrimPrefix(line, pfxName))
		case strings.HasPrefix(line, pfxVersion):
			version = normaliseVersion(strings.TrimPrefix(line, pfxVersion))
		case strings.HasPrefix(line, pfxDep):
			depLine := strings.TrimPrefix(line, pfxDep)
			// Strip environment markers (the part after ';')
			if semi := strings.Index(depLine, ";"); semi >= 0 {
				depLine = strings.TrimSpace(depLine[:semi])
			}
			// Strip parentheses around version specs like "Werkzeug (>=2.2.0)"
			depLine = strings.ReplaceAll(depLine, "(", "")
			depLine = strings.ReplaceAll(depLine, ")", "")
			if req := parseSingleRequirement(strings.TrimSpace(depLine)); req != nil {
				deps = append(deps, *req)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if name == "" {
		return nil, nil
	}
	return &PythonPackage{
		Name:         name,
		Version:      version,
		Dependencies: deps,
	}, nil
}

// normaliseVersion strips non-semver suffixes to increase parse success rates.
// E.g. "2.2.1" → "2.2.1", "3.1.0.post0" → "3.1.0".
func normaliseVersion(v string) string {
	v = strings.TrimSpace(v)
	// Strip anything after a "+" (local segment)
	if idx := strings.Index(v, "+"); idx >= 0 {
		v = v[:idx]
	}
	return v
}

// --- site-packages helper ---

// PythonMetadataFiles is a map of lowercased package name → packages.
// Multiple versions of the same package may exist (e.g. from multi-stage layers).
type PythonMetadataFiles map[string][]PythonPackage

// ParseSitePackagesMetadata parses all METADATA files from a site-packages
// directory. pathToContent maps absolute paths → file contents.
// Only files named "METADATA" inside a *.dist-info directory are processed.
func ParseSitePackagesMetadata(pathToContent map[string][]byte) PythonMetadataFiles {
	result := PythonMetadataFiles{}
	for path, content := range pathToContent {
		base := filepath.Base(path)
		dir := filepath.Dir(path)
		if base != "METADATA" {
			continue
		}
		if !strings.HasSuffix(dir, ".dist-info") {
			continue
		}
		pkg, err := ParseDistInfoMetadata(string(content))
		if err != nil || pkg == nil {
			continue
		}
		result[pkg.Name] = append(result[pkg.Name], *pkg)
	}
	return result
}
