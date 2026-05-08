package image_test

import (
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/image"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetImageType(t *testing.T) {
	cases := []struct {
		input    string
		want     image.ImageType
	}{
		{"docker-archive:/tmp/foo.tar", image.DockerArchive},
		{"oci-archive:/tmp/foo.tar", image.OciArchive},
		{"kaniko-archive:/tmp/foo.tar", image.KanikoArchive},
		{"/path/to/image.tar", image.UnspecifiedArchiveType},
		{"nginx:latest", image.Identifier},
		{"nginx", image.Identifier},
		{"ubuntu@sha256:abc", image.Identifier},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := image.GetImageType(tc.input)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestGetArchivePath(t *testing.T) {
	got, err := image.GetArchivePath("docker-archive:/tmp/foo.tar")
	require.NoError(t, err)
	assert.Equal(t, "/tmp/foo.tar", got)

	got, err = image.GetArchivePath("oci-archive:/tmp/bar.tar")
	require.NoError(t, err)
	assert.Equal(t, "/tmp/bar.tar", got)

	_, err = image.GetArchivePath("nginx:latest")
	assert.Error(t, err)
}

func TestAppendLatestTagIfMissing(t *testing.T) {
	assert.Equal(t, "nginx:latest", image.AppendLatestTagIfMissing("nginx"))
	assert.Equal(t, "nginx:1.21", image.AppendLatestTagIfMissing("nginx:1.21"))
	assert.Equal(t, "docker-archive:/tmp/foo.tar", image.AppendLatestTagIfMissing("docker-archive:/tmp/foo.tar"))
	assert.Equal(t, "ubuntu@sha256:abc", image.AppendLatestTagIfMissing("ubuntu@sha256:abc"))
}
