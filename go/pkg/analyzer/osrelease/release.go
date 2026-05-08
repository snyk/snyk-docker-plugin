// Package osrelease detects the OS release from image filesystem files,
// mirroring lib/analyzer/os-release/release-analyzer.ts.
package osrelease

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// OSRelease holds the detected OS identity.
type OSRelease struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	PrettyName string `json:"prettyName"`
}

var errEmptyInput = errors.New("empty input")

// TryOSRelease parses /etc/os-release or /usr/lib/os-release content.
func TryOSRelease(text string) (*OSRelease, error) {
	if text == "" {
		return nil, nil
	}
	idMatch := regexp.MustCompile(`(?m)^ID=(.+)$`).FindStringSubmatch(text)
	if idMatch == nil {
		return nil, fmt.Errorf("failed to parse os-release: no ID field")
	}
	name := strings.ReplaceAll(idMatch[1], `"`, "")

	versionMatch := regexp.MustCompile(`(?m)^VERSION_ID=(.+)$`).FindStringSubmatch(text)
	version := "unstable"
	if versionMatch != nil {
		version = strings.ReplaceAll(versionMatch[1], `"`, "")
	}

	// Oracle Linux uses "ol" as ID but we keep major version only.
	if name == "ol" {
		version = strings.SplitN(version, ".", 2)[0]
	}

	prettyName := ""
	if m := regexp.MustCompile(`(?m)^PRETTY_NAME=(.+)$`).FindStringSubmatch(text); m != nil {
		prettyName = strings.ReplaceAll(m[1], `"`, "")
	}

	return &OSRelease{Name: name, Version: version, PrettyName: prettyName}, nil
}

// TryLsbRelease parses /etc/lsb-release content.
func TryLsbRelease(text string) (*OSRelease, error) {
	if text == "" {
		return nil, nil
	}
	idMatch := regexp.MustCompile(`(?m)^DISTRIB_ID=(.+)$`).FindStringSubmatch(text)
	verMatch := regexp.MustCompile(`(?m)^DISTRIB_RELEASE=(.+)$`).FindStringSubmatch(text)
	if idMatch == nil || verMatch == nil {
		return nil, fmt.Errorf("failed to parse lsb-release")
	}
	name := strings.ToLower(strings.ReplaceAll(idMatch[1], `"`, ""))
	version := strings.ReplaceAll(verMatch[1], `"`, "")
	return &OSRelease{Name: name, Version: version, PrettyName: ""}, nil
}

// TryDebianVersion parses /etc/debian_version content.
func TryDebianVersion(text string) (*OSRelease, error) {
	if text == "" {
		return nil, nil
	}
	text = strings.TrimSpace(text)
	if len(text) < 2 {
		return nil, fmt.Errorf("failed to parse debian_version: too short")
	}
	version := strings.SplitN(text, ".", 2)[0]
	return &OSRelease{Name: "debian", Version: version, PrettyName: ""}, nil
}

// TryAlpineRelease parses /etc/alpine-release content.
func TryAlpineRelease(text string) (*OSRelease, error) {
	if text == "" {
		return nil, nil
	}
	text = strings.TrimSpace(text)
	if len(text) < 2 {
		return nil, fmt.Errorf("failed to parse alpine-release: too short")
	}
	return &OSRelease{Name: "alpine", Version: text, PrettyName: ""}, nil
}

// TryRedHatRelease parses /etc/redhat-release content.
func TryRedHatRelease(text string) (*OSRelease, error) {
	if text == "" {
		return nil, nil
	}
	idMatch := regexp.MustCompile(`^(\S+)`).FindStringSubmatch(text)
	verMatch := regexp.MustCompile(`(\d+)\.`).FindStringSubmatch(text)
	if idMatch == nil || verMatch == nil {
		return nil, fmt.Errorf("failed to parse redhat-release")
	}
	var name string
	if strings.Contains(text, "Red Hat") {
		name = "rhel"
	} else {
		name = strings.ToLower(strings.ReplaceAll(idMatch[1], `"`, ""))
	}
	version := strings.ReplaceAll(verMatch[1], `"`, "")
	return &OSRelease{Name: name, Version: version, PrettyName: ""}, nil
}

// TryCentosRelease parses /etc/centos-release content.
func TryCentosRelease(text string) (*OSRelease, error) {
	if text == "" {
		return nil, nil
	}
	idMatch := regexp.MustCompile(`^(\S+)`).FindStringSubmatch(text)
	verMatch := regexp.MustCompile(`(\d+)\.`).FindStringSubmatch(text)
	if idMatch == nil || verMatch == nil {
		return nil, fmt.Errorf("failed to parse centos-release")
	}
	name := strings.ToLower(strings.ReplaceAll(idMatch[1], `"`, ""))
	version := strings.ReplaceAll(verMatch[1], `"`, "")
	return &OSRelease{Name: name, Version: version, PrettyName: ""}, nil
}

// TryOracleRelease parses /etc/oracle-release content.
func TryOracleRelease(text string) (*OSRelease, error) {
	if text == "" {
		return nil, nil
	}
	idMatch := regexp.MustCompile(`^(\S+)`).FindStringSubmatch(text)
	verMatch := regexp.MustCompile(`(\d+\.\d+)`).FindStringSubmatch(text)
	if idMatch == nil || verMatch == nil {
		return nil, fmt.Errorf("failed to parse oracle-release")
	}
	name := strings.ToLower(strings.ReplaceAll(idMatch[1], `"`, ""))
	raw := strings.ReplaceAll(verMatch[1], `"`, "")
	version := strings.SplitN(raw, ".", 2)[0]
	return &OSRelease{Name: name, Version: version, PrettyName: ""}, nil
}

// Detect tries each parser in priority order and returns the first success.
// fileContents maps file path → raw text content.
func Detect(fileContents map[string]string) (*OSRelease, error) {
	tryWith := func(path string, parse func(string) (*OSRelease, error)) (*OSRelease, error) {
		content, ok := fileContents[path]
		if !ok {
			return nil, nil
		}
		return parse(content)
	}

	parsers := []struct {
		path  string
		parse func(string) (*OSRelease, error)
	}{
		{"/etc/os-release", TryOSRelease},
		{"/usr/lib/os-release", TryOSRelease},
		{"/etc/lsb-release", TryLsbRelease},
		{"/etc/debian_version", TryDebianVersion},
		{"/etc/alpine-release", TryAlpineRelease},
		{"/etc/redhat-release", TryRedHatRelease},
		{"/etc/oracle-release", TryOracleRelease},
		{"/etc/centos-release", TryCentosRelease},
	}

	for _, p := range parsers {
		res, err := tryWith(p.path, p.parse)
		if err != nil {
			return nil, err
		}
		if res != nil {
			return res, nil
		}
	}
	return nil, fmt.Errorf("could not determine OS release")
}

// Ensure errEmptyInput is used.
var _ = errEmptyInput
