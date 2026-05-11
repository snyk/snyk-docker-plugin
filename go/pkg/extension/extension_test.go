package extension_test

import (
	"context"
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/extension"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanJSON_invalidJSON(t *testing.T) {
	_, err := extension.ScanJSON(context.Background(), []byte("not-json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decoding options")
}

func TestScanJSON_emptyOptions(t *testing.T) {
	// Empty slice → zero-value options → scan will fail (no path)
	_, err := extension.ScanJSON(context.Background(), nil)
	require.Error(t, err)
}

func TestScanJSON_emptyJSON(t *testing.T) {
	// {} is valid JSON, results in empty path → scan fails
	_, err := extension.ScanJSON(context.Background(), []byte(`{}`))
	require.Error(t, err)
}

func TestWorkflowName(t *testing.T) {
	assert.Equal(t, "container depgraph", extension.WorkflowName)
}
