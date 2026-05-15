package containertest

import "github.com/spf13/pflag"

func flags() *pflag.FlagSet {
	fs := pflag.NewFlagSet(WorkflowName, pflag.ContinueOnError)

	fs.Bool("exclude-app-vulns", false, "Disable app-vulns scanning")
	fs.String("platform", "", "Platform for multi-architecture images (e.g. linux/amd64)")
	fs.String("username", "", "Username for private registry authentication")
	fs.String("password", "", "Password for private registry authentication")
	fs.Bool("exclude-node-modules", false, "Exclude node_modules directory from scanning")
	fs.String("nested-jars-depth", "", "Maximum depth for nested JAR scanning")
	fs.String("file", "", "Path to Dockerfile for base image remediation advice")
	fs.Bool("exclude-base-image-vulns", false, "Exclude vulnerabilities introduced only by the base image")

	fs.String("org", "", "Snyk organization to test under")
	fs.String("project-name", "", "Project name override")
	fs.String("target-reference", "", "Target reference for the scan (e.g. branch, tag)")
	fs.String("severity-threshold", "", "Minimum severity to report (low|medium|high|critical)")
	fs.Bool("json", false, "Emit JSON output")
	fs.Bool("sarif", false, "Emit SARIF output")

	return fs
}
