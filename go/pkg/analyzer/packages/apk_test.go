package packages_test

import (
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/analyzer/packages"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const apkSample = `P:musl
V:1.1.24-r9
T:the musl c library
p:so:libc.musl-x86_64.so.1=1
o:musl

P:busybox
V:1.31.1-r19
T:Size optimized toolbox
D:musl>=1.1.14
o:busybox

P:alpine-baselayout
V:3.2.0-r6
T:Alpine base dir structure
D:musl busybox
p:musl-utils
o:alpine-baselayout

`

func TestParseAPKDatabase_basic(t *testing.T) {
	pkgs, err := packages.ParseAPKDatabase(apkSample)
	require.NoError(t, err)
	require.Len(t, pkgs, 3)

	assert.Equal(t, "musl", pkgs[0].Name)
	assert.Equal(t, "1.1.24-r9", pkgs[0].Version)
	assert.Equal(t, "musl", pkgs[0].Source)
	assert.Equal(t, []string{"so:libc.musl-x86_64.so.1"}, pkgs[0].Provides)
	assert.Empty(t, pkgs[0].Deps)

	assert.Equal(t, "busybox", pkgs[1].Name)
	assert.True(t, pkgs[1].Deps["musl"])

	assert.Equal(t, "alpine-baselayout", pkgs[2].Name)
	assert.True(t, pkgs[2].Deps["musl"])
	assert.True(t, pkgs[2].Deps["busybox"])
	assert.Equal(t, []string{"musl-utils"}, pkgs[2].Provides)
}

func TestParseAPKDatabase_empty(t *testing.T) {
	pkgs, err := packages.ParseAPKDatabase("")
	require.NoError(t, err)
	assert.Empty(t, pkgs)
}

func TestParseAPKDatabase_negatedDep(t *testing.T) {
	content := "P:foo\nV:1.0\nD:!bar baz\n\n"
	pkgs, err := packages.ParseAPKDatabase(content)
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	assert.False(t, pkgs[0].Deps["bar"], "negated dep should be excluded")
	assert.True(t, pkgs[0].Deps["baz"])
}

func TestParseAPKDatabase_versionConstraintStripped(t *testing.T) {
	content := "P:foo\nV:1.0\nD:curl>=7.0 libssl>=1.1\n\n"
	pkgs, err := packages.ParseAPKDatabase(content)
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	assert.True(t, pkgs[0].Deps["curl"])
	assert.True(t, pkgs[0].Deps["libssl"])
}
