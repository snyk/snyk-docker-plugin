// Package display ports lib/display.ts: formats ScanResult + TestResult into
// an ANSI-coloured human-readable string.
package display

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/snyk/snyk-docker-plugin/pkg/depgraph"
	"github.com/snyk/snyk-docker-plugin/pkg/types"
)

const (
	sectionPaddingWidth = 19
	breakLine           = "\n"
	maxFromChains       = 3
)

// Display renders scan + test results into a human-readable, ANSI-coloured string.
// Mirrors: export async function display() in lib/display.ts
func Display(
	scanResults []types.ScanResult,
	testResults []types.TestResult,
	errors []string,
	opts types.Options,
) (string, error) {
	var result []string

	for i, testResult := range testResults {
		// Issues
		var formattedIssues []string
		for _, issue := range testResult.Issues {
			formattedIssues = append(formattedIssues, formatIssue(testResult, issue))
		}
		result = append(result, strings.Join(formattedIssues, breakLine))
		result = append(result, breakLine)

		// Metadata
		var scanResult types.ScanResult
		if i < len(scanResults) {
			scanResult = scanResults[i]
		}
		result = append(result, formatMetadataSection(scanResult, testResult))
		result = append(result, breakLine)

		// Summary
		result = append(result, formatSummary(testResult))
		result = append(result, breakLine)

		// Remediations
		if rem := formatRemediations(testResult); rem != "" {
			result = append(result, rem)
			result = append(result, breakLine)
		}

		// Suggestions
		if sug := formatSuggestions(opts); sug != "" {
			result = append(result, sug)
			result = append(result, breakLine)
		}

		// User CTA
		if cta := formatUserCTA(opts); cta != "" {
			result = append(result, cta)
		}
	}

	return strings.Join(result, breakLine), nil
}

func formatIssue(testResult types.TestResult, issue types.Issue) string {
	issueData := testResult.IssuesData[issue.IssueID]
	severity := capitalize(issueData.Severity)
	pkg := issue.PkgName
	colorFn := severityColor(issueData.Severity)

	header := colorFn(fmt.Sprintf("✗ %s severity vulnerability found in %s", severity, pkg))
	description := fmt.Sprintf("  Description: %s", issueData.Title)
	info := fmt.Sprintf("  Info: https://snyk.io/vuln/%s", issue.IssueID)
	introduced := fmt.Sprintf("  Introduced through: %s", formatIntroduced(issueData.From))
	fromStr := formatFrom(issueData.From)

	parts := []string{header, description, info, introduced, fromStr}
	if fixed := formatFixedIn(issue); fixed != "" {
		parts = append(parts, fixed)
	}
	parts = append(parts, "")
	return strings.Join(parts, breakLine)
}

func capitalize(word string) string {
	if len(word) == 0 {
		return word
	}
	return strings.ToUpper(word[:1]) + word[1:]
}

func formatIntroduced(fromList [][]string) string {
	var parts []string
	for _, from := range fromList {
		if len(from) > 0 {
			parts = append(parts, from[0])
		}
	}
	return strings.Join(parts, ", ")
}

func formatFrom(fromList [][]string) string {
	var parts []string
	for i, localFrom := range fromList {
		if i >= maxFromChains {
			break
		}
		parts = append(parts, fmt.Sprintf("  From: %s", strings.Join(localFrom, " > ")))
	}
	if len(fromList) > maxFromChains {
		// TS quirk: fromList.length = max (assignment, not subtraction!)
		// This sets fromList.length to max, so the count displayed is 3.
		extra := maxFromChains
		parts = append(parts, fmt.Sprintf("  and %d more...", extra))
	}
	return strings.Join(parts, breakLine)
}

func formatFixedIn(issue types.Issue) string {
	if issue.FixInfo.NearestFixedInVersion == "" {
		return ""
	}
	return color.New(color.FgGreen, color.Bold).Sprintf("  Fixed in: %s", issue.FixInfo.NearestFixedInVersion)
}

func formatMetadataSection(scanResult types.ScanResult, testResult types.TestResult) string {
	var parts []string
	parts = append(parts, formatMetadataLine("Organization:", testResult.Org))

	pkgMgr := scanResult.Identity.Type
	parts = append(parts, formatMetadataLine("Package manager:", pkgMgr))

	projectName := scanResult.Target.Image
	image := strings.ReplaceAll(projectName, "docker-image|", "")
	parts = append(parts, formatMetadataLine("Project name:", projectName))
	parts = append(parts, formatMetadataLine("Docker image:", image))

	if testResult.Docker.BaseImage != "" {
		parts = append(parts, formatMetadataLine("Base image:", testResult.Docker.BaseImage))
	}
	if testResult.LicensesPolicy != nil {
		parts = append(parts, formatMetadataLine("Licenses:", color.GreenString("enabled")))
	}
	if platform, ok := scanResult.Identity.Args["platform"]; ok && platform != "" {
		parts = append(parts, formatMetadataLine("Platform:", platform))
	}
	return strings.Join(parts, breakLine)
}

func formatMetadataLine(header, info string) string {
	padded := padding(header, sectionPaddingWidth)
	return fmt.Sprintf("%s %s", color.GreenString(padded), info)
}

func formatSummary(testResult types.TestResult) string {
	pkgCount := depgraph.PkgCount(testResult.DepGraphData)
	pathOrDepsText := fmt.Sprintf("%d dependencies", pkgCount)
	testedInfoText := fmt.Sprintf("Tested %s for known issues", pathOrDepsText)
	vulnPathsText := formatVulnSummaryText(testResult.Issues)
	summaryText := fmt.Sprintf("%s, %s", testedInfoText, vulnPathsText)
	if len(testResult.Issues) == 0 {
		summaryText = color.GreenString("✓ " + summaryText)
	}
	return summaryText
}

func formatVulnSummaryText(issues []types.Issue) string {
	if len(issues) > 0 {
		return color.New(color.FgRed, color.Bold).Sprintf("found %d issues.", len(issues))
	}
	return "no vulnerable paths found."
}

// FormatRemediations is exported for tests.
func FormatRemediations(res types.TestResult) string {
	return formatRemediations(res)
}

func formatRemediations(res types.TestResult) string {
	if res.Docker.BaseImageRemediation == nil {
		return ""
	}
	rem := res.Docker.BaseImageRemediation
	var out []string
	if len(rem.Advice) > 0 {
		for _, item := range rem.Advice {
			out = append(out, formatAdviceString(item)(item.Message))
		}
	} else if rem.Message != "" {
		out = append(out, rem.Message)
	} else {
		return ""
	}
	return strings.Join(out, breakLine)
}

func formatAdviceString(item types.BaseImageRemediationAdvice) func(string) string {
	attrs := []color.Attribute{}
	switch item.Color {
	case "red":
		attrs = append(attrs, color.FgRed)
	case "green":
		attrs = append(attrs, color.FgGreen)
	case "yellow":
		attrs = append(attrs, color.FgYellow)
	case "blue":
		attrs = append(attrs, color.FgBlue)
	case "white":
		attrs = append(attrs, color.FgWhite)
	}
	if item.Bold {
		attrs = append(attrs, color.Bold)
	}
	if len(attrs) == 0 {
		return func(s string) string { return s }
	}
	c := color.New(attrs...)
	return func(s string) string { return c.Sprint(s) }
}

func formatSuggestions(opts types.Options) string {
	if opts.IsDockerUser {
		return ""
	}
	if opts.Config != nil && opts.Config.DisableSuggestions == "true" {
		return ""
	}
	optOut := "To remove this message in the future, please run `snyk config set disableSuggestions=true`"
	whiteBold := color.New(color.FgWhite, color.Bold)
	var parts []string
	if opts.File == "" {
		parts = append(parts, whiteBold.Sprint("Pro tip: use `--file` option to get base image remediation advice."))
		parts = append(parts, whiteBold.Sprintf("Example: $ snyk container test %s --file=path/to/Dockerfile", opts.Path))
		parts = append(parts, breakLine)
		parts = append(parts, optOut)
	} else if !opts.ExcludeBaseImageVulns {
		parts = append(parts, whiteBold.Sprint("Pro tip: use `--exclude-base-image-vulns` to exclude from display Docker base image vulnerabilities."))
		parts = append(parts, breakLine)
		parts = append(parts, optOut)
	}
	return strings.Join(parts, breakLine)
}

func formatUserCTA(opts types.Options) string {
	if opts.IsDockerUser {
		return "For more free scans that keep your images secure, sign up to Snyk at https://dockr.ly/3ePqVcp"
	}
	return ""
}

func severityColor(severity string) func(string) string {
	switch severity {
	case "low":
		c := color.New(color.FgBlue, color.Bold)
		return func(s string) string { return c.Sprint(s) }
	case "medium":
		c := color.New(color.FgYellow, color.Bold)
		return func(s string) string { return c.Sprint(s) }
	case "high":
		c := color.New(color.FgRed, color.Bold)
		return func(s string) string { return c.Sprint(s) }
	default:
		c := color.New(color.FgHiWhite)
		return func(s string) string { return c.Sprint(s) }
	}
}

func padding(s string, padTo int) string {
	padLen := padTo - len(s)
	if padLen <= 0 {
		return s
	}
	return s + strings.Repeat(" ", padLen)
}
