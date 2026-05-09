package packages_test

import (
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/analyzer/osrelease"
	"github.com/snyk/snyk-docker-plugin/pkg/analyzer/packages"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const dpkgSample = `Package: libc6
Version: 2.31-13+deb11u5
Status: install ok installed
Architecture: amd64
Depends: libgcc-s1
Provides: libc

Package: curl
Version: 7.74.0-1.3+deb11u7
Status: install ok installed
Architecture: amd64
Source: curl (1.2.3)
Depends: libc6 (>= 2.17), libssl1.1 (>= 1.1.0) | libssl3
Pre-Depends: libc6

Package: deinstalled-pkg
Version: 1.0
Status: deinstall ok config-files
Architecture: amd64

`

func TestParseDPKGStatus_basic(t *testing.T) {
	pkgs, err := packages.ParseDPKGStatus(dpkgSample, nil)
	require.NoError(t, err)
	// deinstalled-pkg should be excluded
	require.Len(t, pkgs, 2)

	assert.Equal(t, "libc6", pkgs[0].Name)
	assert.Equal(t, "2.31-13+deb11u5", pkgs[0].Version)
	assert.Equal(t, []string{"libc"}, pkgs[0].Provides)
	assert.True(t, pkgs[0].Deps["libgcc-s1"])

	assert.Equal(t, "curl", pkgs[1].Name)
	assert.Equal(t, "curl", pkgs[1].Source)
	assert.Equal(t, "1.2.3", pkgs[1].SourceVersion)
	// Depends: libc6 (first alternative of each comma-element)
	assert.True(t, pkgs[1].Deps["libc6"])
	assert.True(t, pkgs[1].Deps["libssl1.1"])
	// Pre-Depends
	assert.True(t, pkgs[1].Deps["libc6"])
}

func TestParseDPKGStatus_purl(t *testing.T) {
	pkgs, err := packages.ParseDPKGStatus(dpkgSample, &osrelease.OSRelease{
		Name: "debian", Version: "11",
	})
	require.NoError(t, err)
	require.Len(t, pkgs, 2)
	assert.Contains(t, pkgs[0].Purl, "pkg:deb/debian/libc6@")
	assert.Contains(t, pkgs[0].Purl, "distro=debian-bullseye")
}

func TestSetAutoInstalled(t *testing.T) {
	pkgs := []packages.AnalyzedPackage{
		{Name: "curl"},
		{Name: "libc6"},
	}
	ext := "Package: libc6\nAuto-Installed: 1\n\nPackage: curl\nAuto-Installed: 0\n\n"
	packages.SetAutoInstalled(ext, pkgs)
	assert.False(t, pkgs[0].AutoInstalled)
	assert.True(t, pkgs[1].AutoInstalled)
}

func TestIsInstalled(t *testing.T) {
	assert.True(t, packages.IsInstalled("install ok installed"))
	assert.False(t, packages.IsInstalled("deinstall ok config-files"))
	assert.False(t, packages.IsInstalled(""))
}

func TestPurl_noOSRelease(t *testing.T) {
	pkg := packages.AnalyzedPackage{Name: "curl", Version: "7.74.0"}
	p := packages.Purl(pkg, nil)
	assert.Equal(t, "pkg:deb//curl@7.74.0", p)
}

func TestPurl_debianCodenames(t *testing.T) {
	cases := []struct{ version, codename string }{
		{"10", "buster"}, {"11", "bullseye"}, {"12", "bookworm"},
	}
	for _, c := range cases {
		p := packages.Purl(packages.AnalyzedPackage{Name: "x", Version: "1"},
			&osrelease.OSRelease{Name: "debian", Version: c.version})
		assert.Contains(t, p, "debian-"+c.codename, "version %s", c.version)
	}
}
