package dockerfile_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/dockerfile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadDockerfileAndAnalyse_empty(t *testing.T) {
	result, err := dockerfile.ReadDockerfileAndAnalyse("")
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestReadDockerfileAndAnalyse(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "Dockerfile*")
	require.NoError(t, err)
	_, _ = f.WriteString("FROM ubuntu:20.04\nRUN apt-get update\n")
	_ = f.Close()

	result, err := dockerfile.ReadDockerfileAndAnalyse(filepath.Join(filepath.Dir(f.Name()), filepath.Base(f.Name())))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "ubuntu:20.04", result.BaseImage)
}
