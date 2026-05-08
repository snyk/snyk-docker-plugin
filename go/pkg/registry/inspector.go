// Package registry handles image pulling from registries and the Docker daemon.
package registry

import (
	"context"
	"fmt"

	"github.com/snyk/snyk-docker-plugin/pkg/types"
)

// GetImageArchive pulls an image and saves it as a docker-archive tar.
// Returns the path to the tar file and a cleanup function.
// TODO: full implementation using go-containerregistry.
func GetImageArchive(ctx context.Context, targetImage string, opts types.PluginOptions) (string, func(), error) {
	return "", func() {}, fmt.Errorf("live image pull not yet implemented")
}
