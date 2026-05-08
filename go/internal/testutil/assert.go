package testutil

import (
	"encoding/json"
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/types"
	"github.com/stretchr/testify/assert"
)

// AssertScanResultsEqual compares two PluginResponse values, ignoring
// pluginVersion and analytics.
func AssertScanResultsEqual(t *testing.T, want, got *types.PluginResponse) {
	t.Helper()
	if want == nil && got == nil {
		return
	}
	if want == nil || got == nil {
		t.Fatalf("one of the PluginResponses is nil: want=%v got=%v", want, got)
	}
	assert.Equal(t, len(want.ScanResults), len(got.ScanResults), "scan result count")
	for i := range want.ScanResults {
		if i >= len(got.ScanResults) {
			break
		}
		wantSR := want.ScanResults[i]
		gotSR := got.ScanResults[i]
		assert.Equal(t, wantSR.Identity.Type, gotSR.Identity.Type, "identity type [%d]", i)
		assert.Equal(t, wantSR.Target, gotSR.Target, "target [%d]", i)
		assertFactsEqual(t, wantSR.Facts, gotSR.Facts, i)
	}
}

func assertFactsEqual(t *testing.T, want, got []types.Fact, scanIdx int) {
	t.Helper()
	wantByType := map[types.FactType]types.Fact{}
	for _, f := range want {
		if f.Type != types.FactPluginVersion {
			wantByType[f.Type] = f
		}
	}
	gotByType := map[types.FactType]types.Fact{}
	for _, f := range got {
		if f.Type != types.FactPluginVersion {
			gotByType[f.Type] = f
		}
	}
	for ft, wf := range wantByType {
		gf, ok := gotByType[ft]
		if !assert.True(t, ok, "fact type %q missing from Go output [scan %d]", ft, scanIdx) {
			continue
		}
		wj, _ := json.Marshal(wf.Data)
		gj, _ := json.Marshal(gf.Data)
		assert.JSONEq(t, string(wj), string(gj), "fact %q mismatch [scan %d]", ft, scanIdx)
	}
}
