// Package osrelease provides ExtractActions for OS release detection files.
package osrelease

import "github.com/snyk/snyk-docker-plugin/pkg/extractor"

// Each OS release file gets its own action name so we know which path matched.
var Actions = []extractor.ExtractAction{
	{ActionName: "os-release",         FilePathMatches: func(p string) bool { return p == "/etc/os-release" }},
	{ActionName: "os-release-fallback",FilePathMatches: func(p string) bool { return p == "/usr/lib/os-release" }},
	{ActionName: "lsb-release",        FilePathMatches: func(p string) bool { return p == "/etc/lsb-release" }},
	{ActionName: "debian-version",     FilePathMatches: func(p string) bool { return p == "/etc/debian_version" }},
	{ActionName: "alpine-release",     FilePathMatches: func(p string) bool { return p == "/etc/alpine-release" }},
	{ActionName: "redhat-release",     FilePathMatches: func(p string) bool { return p == "/etc/redhat-release" }},
	{ActionName: "oracle-release",     FilePathMatches: func(p string) bool { return p == "/etc/oracle-release" }},
	{ActionName: "centos-release",     FilePathMatches: func(p string) bool { return p == "/etc/centos-release" }},
}

// ActionNameToPath maps action name back to the file path it covers,
// for use in OS release detection.
var ActionNameToPath = map[string]string{
	"os-release":          "/etc/os-release",
	"os-release-fallback": "/usr/lib/os-release",
	"lsb-release":         "/etc/lsb-release",
	"debian-version":      "/etc/debian_version",
	"alpine-release":      "/etc/alpine-release",
	"redhat-release":      "/etc/redhat-release",
	"oracle-release":      "/etc/oracle-release",
	"centos-release":      "/etc/centos-release",
}
