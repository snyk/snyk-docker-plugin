package gobinary_test

import (
	"os"
	"runtime"
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/gobinary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadBuildInfo_self(t *testing.T) {
	// Read build info from the test binary itself.
	exe, err := os.Executable()
	require.NoError(t, err)
	info, err := gobinary.ReadBuildInfo(exe)
	require.NoError(t, err)
	assert.NotEmpty(t, info.GoVersion)
	assert.Contains(t, info.GoVersion, runtime.Version()[:6])
}
