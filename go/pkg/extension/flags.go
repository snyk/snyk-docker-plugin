package extension

import "github.com/spf13/pflag"

// Flags returns the pflag FlagSet for the container scan workflow.
func Flags() *pflag.FlagSet {
	fs := pflag.NewFlagSet("container-scan", pflag.ContinueOnError)
	fs.String("path", "", "Image identifier or path to archive")
	fs.String("file", "", "Path to Dockerfile")
	fs.String("username", "", "Registry username")
	fs.String("password", "", "Registry password")
	fs.String("platform", "linux/amd64", "Target platform (os/arch[/variant])")
	fs.String("image-save-path", "", "Override default image save path")
	fs.String("image-name-and-tag", "", "Override image name+tag for archive scans")
	fs.String("target-reference", "", "Target reference (e.g. branch name)")
	fs.Bool("exclude-app-vulns", false, "Exclude application dependency scanning")
	fs.Bool("exclude-node-modules", false, "Exclude node_modules scanning")
	fs.Bool("exclude-base-image-vulns", false, "Exclude base image vulnerabilities")
	fs.Bool("collect-application-files", false, "Collect application files")
	fs.Bool("include-system-jars", false, "Include system JARs in scan")
	fs.Int("nested-jars-depth", 1, "Depth of nested JAR unpacking")
	fs.StringSlice("globs-include", nil, "Glob patterns to include")
	fs.StringSlice("globs-exclude", nil, "Glob patterns to exclude")
	return fs
}
