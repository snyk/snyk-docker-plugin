package packages_test

import (
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/analyzer/packages"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const dpkgSample = `Package: libc6
Version: 2.31-13+deb11u5
Status: install ok installed
Architecture: amd64
Depends: libgcc-s1

Package: curl
Version: 7.74.0-1.3+deb11u7
Status: install ok installed
Architecture: amd64
Depends: libc6 (>= 2.17), libssl1.1 (>= 1.1.0)
`

func TestParseDPKGStatus(t *testing.T) {
	pkgs, err := packages.ParseDPKGStatus(dpkgSample)
	require.NoError(t, err)
	require.Len(t, pkgs, 2)
	assert.Equal(t, "libc6", pkgs[0].Name)
	assert.Equal(t, "2.31-13+deb11u5", pkgs[0].Version)
	assert.Equal(t, "amd64", pkgs[0].Arch)
	assert.Equal(t, "curl", pkgs[1].Name)
}

func TestIsInstalled(t *testing.T) {
	assert.True(t, packages.IsInstalled("install ok installed"))
	assert.False(t, packages.IsInstalled("deinstall ok config-files"))
	assert.False(t, packages.IsInstalled(""))
}
