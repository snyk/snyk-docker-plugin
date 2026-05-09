// Package registry handles pulling images from registries and the Docker daemon,
// mirroring lib/analyzer/image-inspector.ts and lib/docker.ts.
package registry

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/snyk/snyk-docker-plugin/pkg/types"
)

// ArchiveResult holds the path to a pulled docker-archive tar and a cleanup function.
type ArchiveResult struct {
	// Path is the filesystem path to the saved docker-archive tar.
	Path string
	// ImageName is the resolved image name (may include digest).
	ImageName string
	// Cleanup removes the temporary archive. Always call it when done.
	Cleanup func()
}

// GetImageArchive returns a local docker-archive for targetImage.
//
// Strategy (mirrors TS image-inspector.ts):
//  1. Try `docker inspect` — if the image is already in the local daemon, save it.
//  2. Try `docker pull` + `docker save` — if the docker binary is available.
//  3. Fall back to direct OCI registry pull via go-containerregistry.
//
// The caller is responsible for calling ArchiveResult.Cleanup() when done.
func GetImageArchive(
	ctx context.Context,
	targetImage string,
	opts types.PluginOptions,
) (*ArchiveResult, error) {
	savePath := opts.ImageSavePath
	if savePath == "" {
		savePath = os.TempDir()
	}
	if err := os.MkdirAll(savePath, 0o700); err != nil {
		return nil, fmt.Errorf("creating image save path: %w", err)
	}

	archivePath := filepath.Join(savePath, sanitiseImageName(targetImage)+".tar")
	cleanup := func() {
		os.Remove(archivePath)
	}

	// 1. Try local Docker daemon.
	if dockerBinaryExists() {
		ok, err := saveViaDockerBinary(ctx, targetImage, archivePath, opts.Platform)
		if err != nil {
			return nil, err
		}
		if ok {
			return &ArchiveResult{Path: archivePath, ImageName: targetImage, Cleanup: cleanup}, nil
		}
	}

	// 2. Pull directly from registry via go-containerregistry.
	if err := pullFromRegistry(ctx, targetImage, archivePath, opts); err != nil {
		return nil, fmt.Errorf("pulling %s from registry: %w", targetImage, err)
	}
	return &ArchiveResult{Path: archivePath, ImageName: targetImage, Cleanup: cleanup}, nil
}

// dockerBinaryExists returns true if `docker` is on PATH.
func dockerBinaryExists() bool {
	_, err := exec.LookPath("docker")
	return err == nil
}

// saveViaDockerBinary attempts `docker inspect` + `docker save`.
// Returns (true, nil) if successful, (false, nil) if docker binary can't handle it.
func saveViaDockerBinary(ctx context.Context, targetImage, archivePath string, platform string) (bool, error) {
	// Check if image exists locally.
	inspectCmd := exec.CommandContext(ctx, "docker", "inspect", "--type=image", "--format={{.Architecture}}", targetImage)
	out, err := inspectCmd.Output()
	if err != nil {
		// Image not local — try pull.
		pullArgs := []string{"pull"}
		if platform != "" {
			pullArgs = append(pullArgs, "--platform", platform)
		}
		pullArgs = append(pullArgs, targetImage)
		if pullErr := exec.CommandContext(ctx, "docker", pullArgs...).Run(); pullErr != nil {
			// Docker can't pull it either — fall through to registry client.
			return false, nil
		}
	} else {
		// Image is local. Check architecture matches requested platform.
		if platform != "" {
			localArch := strings.TrimSpace(string(out))
			parts := strings.Split(platform, "/")
			if len(parts) >= 2 && parts[1] != localArch {
				// Architecture mismatch — need to pull the right one.
				pullArgs := []string{"pull", "--platform", platform, targetImage}
				if pullErr := exec.CommandContext(ctx, "docker", pullArgs...).Run(); pullErr != nil {
					return false, nil
				}
			}
		}
	}

	// Save image as docker-archive.
	saveCmd := exec.CommandContext(ctx, "docker", "save", "-o", archivePath, targetImage)
	if err := saveCmd.Run(); err != nil {
		return false, nil
	}
	return true, nil
}

// pullFromRegistry pulls targetImage directly from its registry using
// go-containerregistry and saves it as a docker-archive tar.
func pullFromRegistry(ctx context.Context, targetImage, archivePath string, opts types.PluginOptions) error {
	craneOpts := buildCraneOptions(ctx, opts)

	// Resolve platform.
	if opts.Platform != "" {
		p, err := parsePlatform(opts.Platform)
		if err != nil {
			return fmt.Errorf("invalid platform %q: %w", opts.Platform, err)
		}
		craneOpts = append(craneOpts, crane.WithPlatform(p))
	}

	img, err := crane.Pull(targetImage, craneOpts...)
	if err != nil {
		return fmt.Errorf("crane.Pull: %w", err)
	}

	if err := crane.Save(img, targetImage, archivePath); err != nil {
		return fmt.Errorf("crane.Save: %w", err)
	}
	return nil
}

// buildCraneOptions constructs crane.Options from plugin options.
// Credentials fall back to env vars (SNYK_REGISTRY_USERNAME / PASSWORD).
func buildCraneOptions(ctx context.Context, opts types.PluginOptions) []crane.Option {
	username := opts.Username
	password := opts.Password
	if username == "" {
		username = os.Getenv("SNYK_REGISTRY_USERNAME")
	}
	if password == "" {
		password = os.Getenv("SNYK_REGISTRY_PASSWORD")
	}

	craneOpts := []crane.Option{crane.WithContext(ctx)}

	if username != "" || password != "" {
		auth := authn.FromConfig(authn.AuthConfig{
			Username: username,
			Password: password,
		})
		craneOpts = append(craneOpts, crane.WithAuth(auth))
	} else {
		// Use the default keychain (Docker config file, env vars, etc.)
		craneOpts = append(craneOpts, crane.WithAuthFromKeychain(authn.DefaultKeychain))
	}

	return craneOpts
}

// parsePlatform converts "os/arch[/variant]" → v1.Platform.
func parsePlatform(platform string) (*v1.Platform, error) {
	parts := strings.Split(platform, "/")
	if len(parts) < 2 {
		return nil, fmt.Errorf("platform must be os/arch[/variant], got %q", platform)
	}
	p := &v1.Platform{OS: parts[0], Architecture: parts[1]}
	if len(parts) >= 3 {
		p.Variant = parts[2]
	}
	return p, nil
}

// sanitiseImageName converts an image reference to a safe filename component.
func sanitiseImageName(image string) string {
	r := strings.NewReplacer("/", "_", ":", "_", "@", "_")
	return r.Replace(image)
}

// ExtractImageDetails mirrors TS extractImageDetails():
// parses "[[registry/]repo/]image[:tag]" into hostname, imageName, tag.
func ExtractImageDetails(targetImage string) (hostname, imageName, tag string) {
	ref, err := name.ParseReference(targetImage)
	if err != nil {
		// Fallback: return as-is.
		return "registry-1.docker.io", targetImage, "latest"
	}
	switch r := ref.(type) {
	case name.Tag:
		return r.RegistryStr(), r.RepositoryStr(), r.TagStr()
	case name.Digest:
		return r.RegistryStr(), r.RepositoryStr(), r.DigestStr()
	}
	return "registry-1.docker.io", targetImage, "latest"
}

// IsLocalImageSameArchitecture returns true when the platform architecture
// matches the image's local architecture string from docker inspect.
func IsLocalImageSameArchitecture(platform, inspectArch string) bool {
	parts := strings.Split(platform, "/")
	if len(parts) < 2 {
		return false
	}
	return parts[1] == inspectArch
}

// PullIfNotLocal ensures an image is in the local Docker daemon.
// Mirrors TS pullIfNotLocal().
func PullIfNotLocal(ctx context.Context, targetImage string) error {
	if !dockerBinaryExists() {
		return fmt.Errorf("docker binary not found")
	}
	inspectCmd := exec.CommandContext(ctx, "docker", "inspect", "--type=image", targetImage)
	if inspectCmd.Run() == nil {
		return nil // already local
	}
	return exec.CommandContext(ctx, "docker", "pull", targetImage).Run()
}

// RemoteDigest returns the manifest digest for an image reference without pulling it.
// Useful for obtaining the digest of a remote image before pulling.
func RemoteDigest(ctx context.Context, targetImage string, opts types.PluginOptions) (string, error) {
	craneOpts := buildCraneOptions(ctx, opts)
	ref, err := name.ParseReference(targetImage)
	if err != nil {
		return "", fmt.Errorf("parsing reference: %w", err)
	}
	remoteOpts := []remote.Option{remote.WithContext(ctx)}
	if opts.Username != "" || opts.Password != "" {
		remoteOpts = append(remoteOpts, remote.WithAuth(authn.FromConfig(authn.AuthConfig{
			Username: opts.Username,
			Password: opts.Password,
		})))
	} else {
		remoteOpts = append(remoteOpts, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	}
	_ = craneOpts

	desc, err := remote.Head(ref, remoteOpts...)
	if err != nil {
		return "", err
	}
	return desc.Digest.String(), nil
}
