package types

// TestResult mirrors lib/types.ts TestResult.
type TestResult struct {
	Org            string               `json:"org"`
	LicensesPolicy interface{}          `json:"licensesPolicy"`
	Docker         DockerTestInfo       `json:"docker"`
	Issues         []Issue              `json:"issues"`
	IssuesData     map[string]IssueData `json:"issuesData"`
	DepGraphData   DepGraphData         `json:"depGraphData"`
}

type DockerTestInfo struct {
	BaseImage            string                `json:"baseImage,omitempty"`
	BaseImageRemediation *BaseImageRemediation `json:"baseImageRemediation,omitempty"`
}

type BaseImageRemediation struct {
	Code    string                      `json:"code"`
	Advice  []BaseImageRemediationAdvice `json:"advice"`
	Message string                      `json:"message,omitempty"`
}

type BaseImageRemediationAdvice struct {
	Message string `json:"message"`
	Bold    bool   `json:"bold,omitempty"`
	Color   string `json:"color,omitempty"`
}

type Issue struct {
	PkgName    string  `json:"pkgName"`
	PkgVersion string  `json:"pkgVersion,omitempty"`
	IssueID    string  `json:"issueId"`
	FixInfo    FixInfo `json:"fixInfo"`
}

type FixInfo struct {
	NearestFixedInVersion string `json:"nearestFixedInVersion,omitempty"`
}

type IssueData struct {
	ID       string     `json:"id"`
	Severity string     `json:"severity"`
	From     [][]string `json:"from"`
	Title    string     `json:"title"`
}
