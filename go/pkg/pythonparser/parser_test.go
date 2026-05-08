package pythonparser_test

import (
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/pythonparser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRequirementsTxt(t *testing.T) {
	content := `
# comment
requests==2.28.0
flask==2.2.3  # inline comment
numpy
`
	reqs, err := pythonparser.ParseRequirementsTxt(content)
	require.NoError(t, err)
	require.Len(t, reqs, 3)
	assert.Equal(t, "requests", reqs[0].Name)
	assert.Equal(t, "2.28.0", reqs[0].Version)
	assert.Equal(t, "flask", reqs[1].Name)
	assert.Equal(t, "2.2.3", reqs[1].Version)
	assert.Equal(t, "numpy", reqs[2].Name)
	assert.Equal(t, "", reqs[2].Version)
}
