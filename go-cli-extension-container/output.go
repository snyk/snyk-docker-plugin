package containertest

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// renderResults turns the per-image test results into workflow.Data items:
//   - Always emits one application/json+vuln payload per image, carrying the
//     raw findings (consumed by the gaf output workflow / SARIF renderer).
//   - If --json was *not* requested, also emits a per-image human-readable
//     summary as application/json with a local-unified-summary schema.
func renderResults(cfg configuration.Configuration, results []imageTestResult) ([]workflow.Data, error) {
	wantJSON := cfg.GetBool("json")
	threshold := strings.ToLower(strings.TrimSpace(cfg.GetString("severity-threshold")))

	out := make([]workflow.Data, 0, len(results)*2)
	for _, r := range results {
		findings := filterBySeverity(r.Findings, threshold)

		findingsBytes, err := json.Marshal(findings)
		if err != nil {
			return nil, fmt.Errorf("marshaling findings for %q: %w", r.Image, err)
		}
		d := workflow.NewData(typeID, contentTypeTestJSON, findingsBytes)
		d.SetMetaData(headerContentLocation, r.Image)
		out = append(out, d)

		if wantJSON {
			continue
		}

		summary := buildSummary(r, findings)
		summaryBytes, err := json.Marshal(summary)
		if err != nil {
			return nil, fmt.Errorf("marshaling summary for %q: %w", r.Image, err)
		}
		s := workflow.NewData(summaryID, contentTypeSummary, summaryBytes)
		s.SetMetaData(headerContentLocation, r.Image)
		out = append(out, s)
	}
	return out, nil
}

// imageSummary is the JSON shape we hand to the gaf output workflow for
// human rendering when --json is not set. It mirrors the fields the
// existing CLI surfaces for container scans.
type imageSummary struct {
	Image           string         `json:"image"`
	PackageManager  string         `json:"packageManager,omitempty"`
	TargetFile      string         `json:"targetFile,omitempty"`
	Total           int            `json:"total"`
	BySeverity      map[string]int `json:"bySeverity"`
	UniqueVulnIDs   []string       `json:"uniqueVulnIds,omitempty"`
}

func buildSummary(r imageTestResult, findings []testapi.FindingData) imageSummary {
	bySev := map[string]int{}
	ids := map[string]struct{}{}

	for _, f := range findings {
		if f.Attributes == nil {
			continue
		}
		sev := strings.ToLower(string(f.Attributes.Rating.Severity))
		bySev[sev]++

		for _, p := range f.Attributes.Problems {
			disc, err := p.Discriminator()
			if err != nil {
				continue
			}
			switch disc {
			case string(testapi.SnykVuln):
				if v, err := p.AsSnykVulnProblem(); err == nil {
					ids[v.Id] = struct{}{}
				}
			case string(testapi.SnykLicense):
				if v, err := p.AsSnykLicenseProblem(); err == nil {
					ids[v.Id] = struct{}{}
				}
			}
		}
	}

	uniqueIDs := make([]string, 0, len(ids))
	for id := range ids {
		uniqueIDs = append(uniqueIDs, id)
	}
	sort.Strings(uniqueIDs)

	return imageSummary{
		Image:          r.Image,
		PackageManager: r.PackageManager,
		TargetFile:     r.TargetFile,
		Total:          len(findings),
		BySeverity:     bySev,
		UniqueVulnIDs:  uniqueIDs,
	}
}

// filterBySeverity drops findings below the given threshold. An empty
// threshold keeps everything.
func filterBySeverity(findings []testapi.FindingData, threshold string) []testapi.FindingData {
	if threshold == "" {
		return findings
	}
	min, ok := severityRank[threshold]
	if !ok {
		return findings
	}
	kept := findings[:0:0]
	for _, f := range findings {
		if f.Attributes == nil {
			continue
		}
		if severityRank[strings.ToLower(string(f.Attributes.Rating.Severity))] >= min {
			kept = append(kept, f)
		}
	}
	return kept
}

var severityRank = map[string]int{
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}
