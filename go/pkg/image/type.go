// Package image provides image-type detection and archive-path parsing,
// mirroring lib/image-type.ts.
package image

import (
	"fmt"
	"path/filepath"
	"strings"
)

// ImageType mirrors the lib/types.ts ImageType enum.
type ImageType int

const (
	// UnspecifiedArchiveType is a bare .tar path with no prefix.
	UnspecifiedArchiveType ImageType = iota
	// Identifier is a normal image reference like "nginx:latest".
	Identifier
	// DockerArchive is a docker-archive:<path> reference.
	DockerArchive
	// OciArchive is an oci-archive:<path> reference.
	OciArchive
	// KanikoArchive is a kaniko-archive:<path> reference.
	KanikoArchive
)

const (
	prefixDockerArchive = "docker-archive"
	prefixOciArchive    = "oci-archive"
	prefixKanikoArchive = "kaniko-archive"
)

// GetImageType detects the ImageType from a target image string.
func GetImageType(targetImage string) ImageType {
	identifier := strings.SplitN(targetImage, ":", 2)[0]
	switch identifier {
	case prefixDockerArchive:
		return DockerArchive
	case prefixOciArchive:
		return OciArchive
	case prefixKanikoArchive:
		return KanikoArchive
	default:
		if strings.HasSuffix(identifier, ".tar") {
			return UnspecifiedArchiveType
		}
		return Identifier
	}
}

// GetArchivePath strips the prefix and returns the filesystem path.
// Returns an error if the target image is not an archive reference.
func GetArchivePath(targetImage string) (string, error) {
	for _, prefix := range []string{prefixDockerArchive, prefixOciArchive, prefixKanikoArchive} {
		if strings.HasPrefix(targetImage, prefix+":") {
			raw := strings.TrimPrefix(targetImage, prefix+":")
			return filepath.Clean(raw), nil
		}
	}
	if strings.HasSuffix(targetImage, ".tar") {
		return filepath.Clean(targetImage), nil
	}
	return "", fmt.Errorf(
		"the provided archive path is missing a prefix, for example \"docker-archive:\", \"oci-archive:\" or \"kaniko-archive\": %q",
		targetImage,
	)
}

// AppendLatestTagIfMissing appends ":latest" when no tag or digest is present.
func AppendLatestTagIfMissing(image string) string {
	// Archive prefixes are not image references — skip.
	if GetImageType(image) != Identifier {
		return image
	}
	// Already has a tag or digest.
	if strings.Contains(image, ":") || strings.Contains(image, "@") {
		return image
	}
	return image + ":latest"
}
