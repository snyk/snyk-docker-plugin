package packages_test

import (
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/analyzer/packages"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRPMPackage_FullVersion_noEpoch(t *testing.T) {
	p := packages.RPMPackage{Name: "bash", Version: "5.1.8", Release: "6.el9"}
	assert.Equal(t, "5.1.8-6.el9", p.FullVersion())
}

func TestRPMPackage_FullVersion_withEpoch(t *testing.T) {
	epoch := 2
	p := packages.RPMPackage{Name: "bash", Version: "5.1.8", Release: "6.el9", Epoch: &epoch}
	assert.Equal(t, "2:5.1.8-6.el9", p.FullVersion())
}

func TestRPMPackage_FullVersion_zeroEpoch(t *testing.T) {
	epoch := 0
	p := packages.RPMPackage{Name: "bash", Version: "5.1.8", Release: "6.el9", Epoch: &epoch}
	// Zero epoch is not emitted
	assert.Equal(t, "5.1.8-6.el9", p.FullVersion())
}

func TestParseRPMBDB_empty(t *testing.T) {
	pkgs, err := packages.ParseRPMBDB(nil)
	require.NoError(t, err)
	assert.Empty(t, pkgs)
}

func TestParseRPMBDB_invalidData(t *testing.T) {
	// Invalid data should return an error (not panic).
	_, err := packages.ParseRPMBDB([]byte("not an rpm database"))
	assert.Error(t, err)
}

func TestRPMPurl_basic(t *testing.T) {
	p := packages.RPMPackage{Name: "curl", Version: "7.76.1", Release: "14.el9"}
	purl := packages.RPMPurl(p, nil, nil)
	assert.Equal(t, "pkg:rpm//curl@7.76.1-14.el9", purl)
}

func TestRPMPurl_withOSRelease(t *testing.T) {
	p := packages.RPMPackage{Name: "bash", Version: "5.1.8", Release: "6.el9"}
	purl := packages.RPMPurl(p, nil, nil)
	assert.Contains(t, purl, "bash")
}
