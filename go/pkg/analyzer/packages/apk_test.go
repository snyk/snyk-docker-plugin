package packages_test

import (
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/analyzer/packages"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const apkSample = `P:musl
V:1.1.24-r9
T:the musl c library (libc) implementation
p:so:libc.musl-x86_64.so.1=1
o:musl

P:busybox
V:1.31.1-r19
T:Size optimized toolbox of many common UNIX utilities
D:musl>=1.1.14
o:busybox
`

func TestParseAPKDatabase(t *testing.T) {
	pkgs, err := packages.ParseAPKDatabase(apkSample)
	require.NoError(t, err)
	require.Len(t, pkgs, 2)
	assert.Equal(t, "musl", pkgs[0].Name)
	assert.Equal(t, "1.1.24-r9", pkgs[0].Version)
	assert.Equal(t, []string{"so:libc.musl-x86_64.so.1=1"}, pkgs[0].Provides)
	assert.Equal(t, "busybox", pkgs[1].Name)
	assert.Equal(t, []string{"musl>=1.1.14"}, pkgs[1].Dependencies)
}

func TestParseAPKDatabase_empty(t *testing.T) {
	pkgs, err := packages.ParseAPKDatabase("")
	require.NoError(t, err)
	assert.Empty(t, pkgs)
}
