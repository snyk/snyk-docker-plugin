package packages_test

import (
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/analyzer/packages"
	"github.com/stretchr/testify/assert"
)

func TestRPMPackage_FullVersion(t *testing.T) {
	p := packages.RPMPackage{Name: "bash", Version: "5.1.8", Release: "6.el9", Epoch: 0}
	assert.Equal(t, "5.1.8-6.el9", p.FullVersion())

	p2 := packages.RPMPackage{Name: "bash", Version: "5.1.8", Release: "6.el9", Epoch: 2}
	assert.Equal(t, "2:5.1.8-6.el9", p2.FullVersion())
}
