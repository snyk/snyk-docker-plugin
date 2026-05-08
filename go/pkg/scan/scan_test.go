package scan_test

import (
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/scan"
	"github.com/snyk/snyk-docker-plugin/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergeEnvVarsIntoCredentials(t *testing.T) {
	t.Setenv("SNYK_REGISTRY_USERNAME", "envuser")
	t.Setenv("SNYK_REGISTRY_PASSWORD", "envpass")

	opts := types.PluginOptions{}
	scan.MergeEnvVarsIntoCredentials(&opts)
	assert.Equal(t, "envuser", opts.Username)
	assert.Equal(t, "envpass", opts.Password)
}

func TestMergeEnvVarsIntoCredentials_flagsWin(t *testing.T) {
	t.Setenv("SNYK_REGISTRY_USERNAME", "envuser")
	t.Setenv("SNYK_REGISTRY_PASSWORD", "envpass")

	opts := types.PluginOptions{Username: "flaguser", Password: "flagpass"}
	scan.MergeEnvVarsIntoCredentials(&opts)
	assert.Equal(t, "flaguser", opts.Username)
	assert.Equal(t, "flagpass", opts.Password)
}

func TestScan_missingPath(t *testing.T) {
	_, err := scan.Scan(nil, types.PluginOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no image identifier")
}
