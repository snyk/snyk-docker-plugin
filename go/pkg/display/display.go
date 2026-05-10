// Package display ports lib/display.ts: formats ScanResult + TestResult into
// an ANSI-coloured human-readable string.
//
// ANSI sequences are produced to match chalk's exact wire format so that
// golden-file tests (and downstream consumers that parse ANSI output) get
// byte-identical output. Specifically:
//   - Single attributes use per-attribute reset codes (\x1b[39m for fg,
//     \x1b[22m for bold) rather than the full-reset \x1b[0m that fatih/color emits.
//   - Chained attributes are emitted left-to-right and closed right-to-left.
//   - Multiline strings are formatted line-by-line (chalk behaviour).
package display

import (
	"fmt"
	"strings"

	"github.com/snyk/snyk-docker-plugin/pkg/depgraph"
	"github.com/snyk/snyk-docker-plugin/pkg/types"
)

const (
	sectionPaddingWidth = 19
	breakLine           = "\n"
	maxFromChains       = 3
)

// ---------------------------------------------------------------------------
// chalk-compatible ANSI helpers
// ---------------------------------------------------------------------------

// ansiAttr is an open/close pair for one ANSI attribute.
type ansiAttr struct{ open, close string }

var (
	attrBold   = ansiAttr{"\x1b[1m", "\x1b[22m"}
	attrGreen  = ansiAttr{"\x1b[32m", "\x1b[39m"}
	attrBlue   = ansiAttr{"\x1b[34m", "\x1b[39m"}
	attrYellow = ansiAttr{"\x1b[33m", "\x1b[39m"}
	attrRed    = ansiAttr{"\x1b[31m", "\x1b[39m"}
	attrWhite  = ansiAttr{"\x1b[37m", "\x1b[39m"}
)

// chalk applies attrs in order (open left-to-right, close right-to-left),
// handling multiline strings by formatting each line individually — matching
// chalk's behaviour exactly.
func chalk(text string, attrs ...ansiAttr) string {
	var open, close strings.Builder
	for _, a := range attrs {
		open.WriteString(a.open)
	}
	for i := len(attrs) - 1; i >= 0; i-- {
		close.WriteString(attrs[i].close)
	}
	openStr := open.String()
	closeStr := close.String()

	parts := strings.Split(text, "\n")
	for i, p := range parts {
		parts[i] = openStr + p + closeStr
	}
	return strings.Join(parts, "\n")
}

// colour convenience wrappers
func chalkGreen(s string) string                  { return chalk(s, attrGreen) }
func chalkBoldBlue(s string) string               { return chalk(s, attrBold, attrBlue) }
func chalkBoldYellow(s string) string             { return chalk(s, attrBold, attrYellow) }
func chalkBoldRed(s string) string                { return chalk(s, attrBold, attrRed) }
func chalkBoldGreen(s string) string              { return chalk(s, attrBold, attrGreen) }
func chalkBoldWhite(s string) string              { return chalk(s, attrBold, attrWhite) }

// chalkAdvice mirrors formatString() from display.ts:
//   formatter = chalk
//   if color: formatter = formatter[color]   // color first
//   if bold:  formatter = formatter.bold     // bold second
func chalkAdvice(color string, bold bool, s string) string {
	attrs := []ansiAttr{}
	switch color {
	case "green":
		attrs = append(attrs, attrGreen)
	case "red":
		attrs = append(attrs, attrRed)
	case "yellow":
		attrs = append(attrs, attrYellow)
	case "blue":
		attrs = append(attrs, attrBlue)
	case "white":
		attrs = append(attrs, attrWhite)
	}
	if bold {
		attrs = append(attrs, attrBold)
	}
	if len(attrs) == 0 {
		return s
	}
	return chalk(s, attrs...)
}

// ---------------------------------------------------------------------------
// Display — top-level entry point
// ---------------------------------------------------------------------------

// Display renders scan + test results into a human-readable, ANSI-coloured
// string. Mirrors: export async function display() in lib/display.ts
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
		result = append(result, includeSectionSeparator())

		// Metadata
		var scanResult types.ScanResult
		if i < len(scanResults) {
			scanResult = scanResults[i]
		}
		result = append(result, formatMetadataSection(scanResult, testResult))
		result = append(result, includeSectionSeparator())

		// Summary
		result = append(result, formatSummary(testResult))
		result = append(result, includeSectionSeparator())

		// Remediations
		if rem := formatRemediations(testResult); rem != "" {
			result = append(result, rem)
			result = append(result, includeSectionSeparator())
		}

		// Suggestions
		if sug := formatSuggestions(opts); sug != "" {
			result = append(result, sug)
			result = append(result, includeSectionSeparator())
		}

		// User CTA
		if cta := formatUserCTA(opts); cta != "" {
			result = append(result, cta)
		}
	}

	return strings.Join(result, breakLine), nil
}

func includeSectionSeparator() string { return breakLine }

// ---------------------------------------------------------------------------
// Issue formatting
// ---------------------------------------------------------------------------

func formatIssue(testResult types.TestResult, issue types.Issue) string {
	issueData := testResult.IssuesData[issue.IssueID]
	severity := capitalize(issueData.Severity)
	pkg := issue.PkgName
	header := severityColor(issueData.Severity)(fmt.Sprintf("✗ %s severity vulnerability found in %s", severity, pkg))
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
	counter := 0
	for _, localFrom := range fromList {
		if counter >= maxFromChains {
			break
		}
		counter++
		parts = append(parts, fmt.Sprintf("  From: %s", strings.Join(localFrom, " > ")))
	}
	if len(fromList) > maxFromChains {
		// Mirror the TS bug: fromList.length = max (assignment), so 'max' is displayed.
		parts = append(parts, fmt.Sprintf("  and %d more...", maxFromChains))
	}
	return strings.Join(parts, breakLine)
}

func formatFixedIn(issue types.Issue) string {
	if issue.FixInfo.NearestFixedInVersion == "" {
		return ""
	}
	return chalkBoldGreen(fmt.Sprintf("  Fixed in: %s", issue.FixInfo.NearestFixedInVersion))
}

func severityColor(severity string) func(string) string {
	switch severity {
	case "low":
		return chalkBoldBlue
	case "medium":
		return chalkBoldYellow
	case "high":
		return chalkBoldRed
	default:
		return func(s string) string { return s }
	}
}

// ---------------------------------------------------------------------------
// Metadata section
// ---------------------------------------------------------------------------

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
		parts = append(parts, formatMetadataLine("Licenses:", chalkGreen("enabled")))
	}
	if platform, ok := scanResult.Identity.Args["platform"]; ok && platform != "" {
		parts = append(parts, formatMetadataLine("Platform:", platform))
	}
	return strings.Join(parts, breakLine)
}

func formatMetadataLine(header, info string) string {
	return fmt.Sprintf("%s %s", chalkGreen(padding(header, sectionPaddingWidth)), info)
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

func formatSummary(testResult types.TestResult) string {
	pkgCount := depgraph.PkgCount(testResult.DepGraphData)
	testedInfoText := fmt.Sprintf("Tested %d dependencies for known issues", pkgCount)
	vulnPathsText := formatVulnSummaryText(testResult.Issues)
	summaryText := fmt.Sprintf("%s, %s", testedInfoText, vulnPathsText)
	if len(testResult.Issues) == 0 {
		summaryText = chalkGreen("✓ " + summaryText)
	}
	return summaryText
}

func formatVulnSummaryText(issues []types.Issue) string {
	if len(issues) > 0 {
		return chalkBoldRed(fmt.Sprintf("found %d issues.", len(issues)))
	}
	return "no vulnerable paths found."
}

// ---------------------------------------------------------------------------
// Remediations
// ---------------------------------------------------------------------------

// FormatRemediations is exported for tests.
func FormatRemediations(res types.TestResult) string { return formatRemediations(res) }

func formatRemediations(res types.TestResult) string {
	if res.Docker.BaseImageRemediation == nil {
		return ""
	}
	rem := res.Docker.BaseImageRemediation
	var out []string
	if len(rem.Advice) > 0 {
		for _, item := range rem.Advice {
			out = append(out, chalkAdvice(item.Color, item.Bold, item.Message))
		}
	} else if rem.Message != "" {
		out = append(out, rem.Message)
	} else {
		return ""
	}
	return strings.Join(out, breakLine)
}

// ---------------------------------------------------------------------------
// Suggestions
// ---------------------------------------------------------------------------

func formatSuggestions(opts types.Options) string {
	if opts.IsDockerUser {
		return ""
	}
	if opts.Config != nil && opts.Config.DisableSuggestions == "true" {
		return ""
	}
	optOut := "To remove this message in the future, please run `snyk config set disableSuggestions=true`"
	var parts []string
	if opts.File == "" {
		parts = append(parts, chalkBoldWhite("Pro tip: use `--file` option to get base image remediation advice."))
		parts = append(parts, chalkBoldWhite(fmt.Sprintf("Example: $ snyk container test %s --file=path/to/Dockerfile", opts.Path)))
		parts = append(parts, breakLine)
		parts = append(parts, optOut)
	} else if !opts.ExcludeBaseImageVulns {
		parts = append(parts, chalkBoldWhite("Pro tip: use `--exclude-base-image-vulns` to exclude from display Docker base image vulnerabilities."))
		parts = append(parts, breakLine)
		parts = append(parts, optOut)
	}
	return strings.Join(parts, breakLine)
}

// ---------------------------------------------------------------------------
// User CTA
// ---------------------------------------------------------------------------

func formatUserCTA(opts types.Options) string {
	if opts.IsDockerUser {
		return "For more free scans that keep your images secure, sign up to Snyk at https://dockr.ly/3ePqVcp"
	}
	return ""
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func padding(s string, padTo int) string {
	padLen := padTo - len(s)
	if padLen <= 0 {
		return s
	}
	return s + strings.Repeat(" ", padLen)
}
