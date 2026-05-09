package registry_test

import (
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/registry"
	"github.com/stretchr/testify/assert"
)

func TestExtractImageDetails_officialImage(t *testing.T) {
	host, img, tag := registry.ExtractImageDetails("nginx:1.21")
	assert.Equal(t, "index.docker.io", host)
	assert.Equal(t, "library/nginx", img)
	assert.Equal(t, "1.21", tag)
}

func TestExtractImageDetails_withRegistry(t *testing.T) {
	host, img, tag := registry.ExtractImageDetails("gcr.io/distroless/base:latest")
	assert.Equal(t, "gcr.io", host)
	assert.Equal(t, "distroless/base", img)
	assert.Equal(t, "latest", tag)
}

func TestExtractImageDetails_noTag(t *testing.T) {
	_, img, tag := registry.ExtractImageDetails("ubuntu")
	assert.Equal(t, "library/ubuntu", img)
	assert.Equal(t, "latest", tag)
}

func TestExtractImageDetails_withDigest(t *testing.T) {
	// A properly formatted digest reference
	digest := "sha256:45b23dee08af5e43a7fea6c4cf9c25ccf269ee113168c19722f87876677c5cb2"
	host, img, d := registry.ExtractImageDetails("ubuntu@" + digest)
	assert.Equal(t, "index.docker.io", host)
	assert.Equal(t, "library/ubuntu", img)
	assert.Equal(t, digest, d)
}

func TestIsLocalImageSameArchitecture(t *testing.T) {
	assert.True(t, registry.IsLocalImageSameArchitecture("linux/amd64", "amd64"))
	assert.False(t, registry.IsLocalImageSameArchitecture("linux/arm64", "amd64"))
	assert.False(t, registry.IsLocalImageSameArchitecture("invalid", "amd64"))
}
