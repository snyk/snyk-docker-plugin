// Package response assembles PluginResponse from analysis results.
// Mirrors lib/response-builder.ts, lib/scan-payload-metrics.ts, and lib/utils.ts.
package response

import (
	"encoding/json"

	"github.com/snyk/snyk-docker-plugin/pkg/types"
)

// ---------------------------------------------------------------------------
// Response construction
// ---------------------------------------------------------------------------

// BuildResponse is the passthrough used by scan.go — it is NOT the full
// response-builder pipeline (that lives in Assemble). It remains for
// backward-compat with callers that supply a pre-built facts slice.
func BuildResponse(facts []types.Fact, target types.ContainerTarget, identity types.Identity) *types.PluginResponse {
	return &types.PluginResponse{
		ScanResults: []types.ScanResult{
			{
				Target:   target,
				Identity: identity,
				Facts:    facts,
			},
		},
	}
}

// Assemble applies the full response-builder pipeline:
//  1. Truncate oversized fact fields.
//  2. Compute scan-payload analytics.
//  3. Return the final PluginResponse.
//
// scanResults must be ordered: index 0 = OS scan result, rest = app results.
func Assemble(scanResults []types.ScanResult) *types.PluginResponse {
	// Truncate each result's facts in place.
	truncated := make([]types.ScanResult, len(scanResults))
	for i, sr := range scanResults {
		sr.Facts = TruncateAdditionalFacts(sr.Facts)
		truncated[i] = sr
	}

	metrics := ComputeScanPayloadMetrics(truncated)

	return &types.PluginResponse{
		ScanResults: truncated,
		Analytics: []types.PluginAnalytics{
			{Name: "containerScanPayloadMetrics", Data: metrics},
		},
	}
}

// ---------------------------------------------------------------------------
// Scan-payload metrics  (mirrors lib/scan-payload-metrics.ts)
// ---------------------------------------------------------------------------

// ScanPayloadMetrics mirrors the TS ScanPayloadMetrics shape.
type ScanPayloadMetrics struct {
	ScanResultCount              int   `json:"scanResultCount"`
	ApplicationScanResultCount   int   `json:"applicationScanResultCount"`
	ScanResultPayloadBytes       []int `json:"scanResultPayloadBytes"`
	TotalScanResultsPayloadBytes int   `json:"totalScanResultsPayloadBytes"`
}

// ComputeScanPayloadMetrics computes byte-size analytics over scan results.
func ComputeScanPayloadMetrics(results []types.ScanResult) ScanPayloadMetrics {
	perResult := make([]int, len(results))
	for i, r := range results {
		perResult[i] = jsonBytes(r)
	}
	appCount := len(results) - 1
	if appCount < 0 {
		appCount = 0
	}
	return ScanPayloadMetrics{
		ScanResultCount:              len(results),
		ApplicationScanResultCount:   appCount,
		ScanResultPayloadBytes:       perResult,
		TotalScanResultsPayloadBytes: jsonBytes(results),
	}
}

func jsonBytes(v interface{}) int {
	b, _ := json.Marshal(v)
	return len(b)
}

// ---------------------------------------------------------------------------
// Fact truncation  (mirrors lib/utils.ts truncateAdditionalFacts)
// ---------------------------------------------------------------------------

// responseSizeLimits mirrors RESPONSE_SIZE_LIMITS from lib/utils.ts.
// Keys are "factType.path" or "factType.path[*]" for per-element limits.
var responseSizeLimits = map[string]limitConfig{
	"containerConfig.data.user":              {kind: "string", limit: 1024},
	"containerConfig.data.exposedPorts":      {kind: "array", limit: 500},
	"containerConfig.data.exposedPorts[*]":   {kind: "string", limit: 64},
	"containerConfig.data.env":               {kind: "array", limit: 500},
	"containerConfig.data.env[*]":            {kind: "string", limit: 1024},
	"containerConfig.data.entrypoint":        {kind: "array", limit: 500},
	"containerConfig.data.entrypoint[*]":     {kind: "string", limit: 1024},
	"containerConfig.data.cmd":               {kind: "array", limit: 500},
	"containerConfig.data.cmd[*]":            {kind: "string", limit: 1024},
	"containerConfig.data.volumes":           {kind: "array", limit: 500},
	"containerConfig.data.volumes[*]":        {kind: "string", limit: 1024},
	"containerConfig.data.workingDir":        {kind: "string", limit: 1024},
	"containerConfig.data.stopSignal":        {kind: "string", limit: 128},
	"history.data":                           {kind: "array", limit: 1000},
	"history.data[*].author":                {kind: "string", limit: 128},
	"history.data[*].createdBy":             {kind: "string", limit: 4096},
	"history.data[*].comment":               {kind: "string", limit: 4096},
}

type limitConfig struct {
	kind  string // "string" or "array"
	limit int
}

// TruncationInfo describes how many elements/chars were above the limit.
type TruncationInfo struct {
	Type           string `json:"type"`
	CountAboveLimit int   `json:"countAboveLimit"`
}

// TruncateAdditionalFacts applies size limits to all facts in the slice.
// If any fact was truncated a pluginWarnings fact is appended/updated.
func TruncateAdditionalFacts(facts []types.Fact) []types.Fact {
	tracker := map[string]TruncationInfo{}

	out := make([]types.Fact, len(facts))
	for i, f := range facts {
		if f.Type == types.FactDepGraph || f.Data == nil {
			out[i] = f
			continue
		}
		// Marshal data to generic map so we can traverse it.
		raw, err := json.Marshal(f.Data)
		if err != nil {
			out[i] = f
			continue
		}
		var data interface{}
		if err := json.Unmarshal(raw, &data); err != nil {
			out[i] = f
			continue
		}
		data = truncateValue(data, string(f.Type), "data", tracker)
		out[i] = types.Fact{Type: f.Type, Data: data}
	}

	if len(tracker) == 0 {
		return out
	}

	// Attach truncation info to existing pluginWarnings or append a new one.
	for i, f := range out {
		if f.Type == types.FactPluginWarnings {
			if m, ok := f.Data.(map[string]interface{}); ok {
				m["truncatedFacts"] = tracker
				out[i] = types.Fact{Type: types.FactPluginWarnings, Data: m}
			}
			return out
		}
	}
	out = append(out, types.Fact{
		Type: types.FactPluginWarnings,
		Data: map[string]interface{}{"truncatedFacts": tracker},
	})
	return out
}

func hasAnyLimitsForPath(factType, path string) bool {
	prefix := factType + "." + path
	for k := range responseSizeLimits {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

func truncateValue(value interface{}, factType, path string, tracker map[string]TruncationInfo) interface{} {
	limitKey := factType + "." + path

	// Apply direct limit if configured.
	if cfg, ok := responseSizeLimits[limitKey]; ok {
		value = applyLimit(value, cfg, limitKey, tracker)
	}

	if !hasAnyLimitsForPath(factType, path) {
		return value
	}

	switch v := value.(type) {
	case []interface{}:
		out := make([]interface{}, len(v))
		for i, item := range v {
			out[i] = truncateValue(item, factType, path+"[*]", tracker)
		}
		return out
	case map[string]interface{}:
		out := make(map[string]interface{}, len(v))
		for k, sub := range v {
			out[k] = truncateValue(sub, factType, path+"."+k, tracker)
		}
		return out
	}
	return value
}

func applyLimit(value interface{}, cfg limitConfig, key string, tracker map[string]TruncationInfo) interface{} {
	switch cfg.kind {
	case "array":
		if arr, ok := value.([]interface{}); ok && len(arr) > cfg.limit {
			count := len(arr) - cfg.limit
			tracker[key] = TruncationInfo{Type: "array", CountAboveLimit: count}
			return arr[:cfg.limit]
		}
	case "string":
		if s, ok := value.(string); ok && len(s) > cfg.limit {
			count := len(s) - cfg.limit
			if existing, has := tracker[key]; !has || count > existing.CountAboveLimit {
				tracker[key] = TruncationInfo{Type: "string", CountAboveLimit: count}
			}
			return s[:cfg.limit]
		}
	}
	return value
}
