package extensionadapter

import "github.com/spf13/pflag"

// flags returns the flagset that the "container depgraph" workflow exposes.
// These match the flags defined in github.com/snyk/container-cli so the
// CLI help text and flag forwarding work identically.
func flags() *pflag.FlagSet {
	fs := pflag.NewFlagSet("container depgraph", pflag.ContinueOnError)
	fs.Bool("exclude-app-vulns", false, "Disable app-vulns scanning")
	fs.String("platform", "", "Platform for multi-architecture images (e.g. linux/amd64)")
	fs.String("username", "", "Username for private registry authentication")
	fs.String("password", "", "Password for private registry authentication")
	fs.Bool("exclude-node-modules", false, "Exclude node_modules directory from scanning")
	fs.String("nested-jars-depth", "", "Maximum depth for nested JAR scanning")
	fs.String("shaded-jars-depth", "", "Maximum depth for shaded JAR scanning")
	fs.String("file", "", "Path to Dockerfile for base image remediation advice")
	fs.Bool("include-system-jars", false, "Include system JARs in Java scanning")
	return fs
}
