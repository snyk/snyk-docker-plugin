// Package parser converts analysis results into dep-tree inputs.
package parser

// ParsedAnalysis holds the results of parsing OS analysis output.
type ParsedAnalysis struct {
	PackageFormat string
	TargetOS      TargetOS
}

// TargetOS identifies the target operating system.
type TargetOS struct {
	Name       string
	Version    string
	PrettyName string
}
