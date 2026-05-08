package osrelease_test

import (
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/analyzer/osrelease"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTryOSRelease(t *testing.T) {
	text := `NAME="Ubuntu"
VERSION_ID="20.04"
ID=ubuntu
PRETTY_NAME="Ubuntu 20.04.3 LTS"
`
	res, err := osrelease.TryOSRelease(text)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "ubuntu", res.Name)
	assert.Equal(t, "20.04", res.Version)
	assert.Equal(t, "Ubuntu 20.04.3 LTS", res.PrettyName)
}

func TestTryOSRelease_unstable(t *testing.T) {
	text := `ID=debian
`
	res, err := osrelease.TryOSRelease(text)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "unstable", res.Version)
}

func TestTryOSRelease_empty(t *testing.T) {
	res, err := osrelease.TryOSRelease("")
	require.NoError(t, err)
	assert.Nil(t, res)
}

func TestTryOSRelease_noID(t *testing.T) {
	_, err := osrelease.TryOSRelease("VERSION_ID=1.0\n")
	assert.Error(t, err)
}

func TestTryLsbRelease(t *testing.T) {
	text := `DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=18.04
`
	res, err := osrelease.TryLsbRelease(text)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "ubuntu", res.Name)
	assert.Equal(t, "18.04", res.Version)
}

func TestTryDebianVersion(t *testing.T) {
	res, err := osrelease.TryDebianVersion("10.3\n")
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "debian", res.Name)
	assert.Equal(t, "10", res.Version)
}

func TestTryDebianVersion_corrupt(t *testing.T) {
	_, err := osrelease.TryDebianVersion("x")
	assert.Error(t, err)
}

func TestTryAlpineRelease(t *testing.T) {
	res, err := osrelease.TryAlpineRelease("3.12.0\n")
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "alpine", res.Name)
	assert.Equal(t, "3.12.0", res.Version)
}

func TestTryRedHatRelease_rhel(t *testing.T) {
	res, err := osrelease.TryRedHatRelease("Red Hat Enterprise Linux Server release 7.9 (Maipo)\n")
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "rhel", res.Name)
	assert.Equal(t, "7", res.Version)
}

func TestTryCentosRelease(t *testing.T) {
	res, err := osrelease.TryCentosRelease("CentOS Linux release 7.9.2009 (Core)\n")
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "centos", res.Name)
	assert.Equal(t, "7", res.Version)
}

func TestDetect_osRelease(t *testing.T) {
	files := map[string]string{
		"/etc/os-release": "ID=alpine\nVERSION_ID=3.12.0\nPRETTY_NAME=\"Alpine Linux v3.12\"\n",
	}
	res, err := osrelease.Detect(files)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "alpine", res.Name)
	assert.Equal(t, "3.12.0", res.Version)
}

func TestDetect_noFiles(t *testing.T) {
	_, err := osrelease.Detect(map[string]string{})
	assert.Error(t, err)
}
