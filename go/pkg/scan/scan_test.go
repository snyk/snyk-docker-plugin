package scan_test

import (
	"compress/gzip"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/snyk/snyk-docker-plugin/pkg/scan"
	"github.com/snyk/snyk-docker-plugin/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Archive builder helpers
// ---------------------------------------------------------------------------

// fileEntry is a single file to include in a layer.
type fileEntry struct {
	path    string
	content string
	mode    int64
}

// buildLayer creates a gzip-compressed tar layer from a slice of fileEntry.
// The layer content is gzip-compressed so that go-containerregistry correctly
// detects it and embeds it in the docker-archive tar.
func buildLayer(t *testing.T, files []fileEntry) v1.Layer {
	t.Helper()

	// Build the raw (uncompressed) tar in memory.
	rawBuf := &bytes.Buffer{}
	tw := tar.NewWriter(rawBuf)
	for _, f := range files {
		mode := f.mode
		if mode == 0 {
			mode = 0o644
		}
		name := strings.TrimPrefix(f.path, "/")
		hdr := &tar.Header{
			Name:     name,
			Typeflag: tar.TypeReg,
			Size:     int64(len(f.content)),
			Mode:     mode,
			ModTime:  time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		}
		require.NoError(t, tw.WriteHeader(hdr))
		_, err := tw.Write([]byte(f.content))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())

	// gzip-compress the tar so LayerFromOpener detects GZip compression.
	gzBuf := &bytes.Buffer{}
	gw := gzip.NewWriter(gzBuf)
	_, err := io.Copy(gw, rawBuf)
	require.NoError(t, err)
	require.NoError(t, gw.Close())

	compressed := gzBuf.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(compressed)), nil
	})
	require.NoError(t, err)
	return layer
}

// imageConfig holds the extra metadata baked into the image config JSON.
type imageConfig struct {
	os           string
	arch         string
	env          []string
	cmd          []string
	entrypoint   []string
	workingDir   string
	user         string
	labels       map[string]string
	created      time.Time
}

// buildArchive creates a docker-archive tar from a set of layers and config,
// saves it to t.TempDir(), and returns the path.
//
// Layer order matters: use mutate.Append with Addendum so that layers are
// correctly embedded in the archive. mutate.ConfigFile is called AFTER
// layers are appended, re-using the existing RootFS from the image.
func buildArchive(t *testing.T, tag string, layers []v1.Layer, cfg imageConfig) string {
	t.Helper()

	os_ := cfg.os
	if os_ == "" {
		os_ = "linux"
	}
	arch := cfg.arch
	if arch == "" {
		arch = "amd64"
	}
	created := cfg.created
	if created.IsZero() {
		created = time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	}
	gcrCreated := v1.Time{Time: created}

	img := empty.Image
	var err error

	// Append each layer with a history entry so the layer is embedded.
	for i, l := range layers {
		img, err = mutate.Append(img, mutate.Addendum{
			Layer: l,
			History: v1.History{
				CreatedBy: fmt.Sprintf("/bin/sh -c #(nop) layer %d", i),
				Created:   gcrCreated,
			},
		})
		require.NoError(t, err)
	}

	// Set runtime config (does not touch RootFS / layers).
	img, err = mutate.Config(img, v1.Config{
		Env:        cfg.env,
		Cmd:        cfg.cmd,
		Entrypoint: cfg.entrypoint,
		WorkingDir: cfg.workingDir,
		User:       cfg.user,
		Labels:     cfg.labels,
	})
	require.NoError(t, err)

	// Override OS / arch / created — fetch the existing ConfigFile so RootFS
	// is preserved, then overwrite only the fields we care about.
	cfgFile, err := img.ConfigFile()
	require.NoError(t, err)
	cfgFile.OS = os_
	cfgFile.Architecture = arch
	cfgFile.Created = gcrCreated
	img, err = mutate.ConfigFile(img, cfgFile)
	require.NoError(t, err)

	ref, err := name.ParseReference(tag)
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "image.tar")
	require.NoError(t, tarball.WriteToFile(path, ref, img))
	return path
}

// factData extracts the Data field for a given FactType from a scan result.
// Returns (data_as_json, found).
func factData(t *testing.T, sr types.ScanResult, ft types.FactType) (json.RawMessage, bool) {
	t.Helper()
	for _, f := range sr.Facts {
		if f.Type == ft {
			b, err := json.Marshal(f.Data)
			require.NoError(t, err)
			return b, true
		}
	}
	return nil, false
}

func mustFactString(t *testing.T, sr types.ScanResult, ft types.FactType) string {
	t.Helper()
	raw, ok := factData(t, sr, ft)
	require.True(t, ok, "fact %q not found", ft)
	var s string
	require.NoError(t, json.Unmarshal(raw, &s))
	return s
}

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

func TestScan_missingPath(t *testing.T) {
	_, err := scan.Scan(context.Background(), types.PluginOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no image identifier")
}

func TestScan_invalidArchivePath(t *testing.T) {
	_, err := scan.Scan(context.Background(), types.PluginOptions{
		Path: "docker-archive:/nonexistent/path/image.tar",
	})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// Env var credential merging
// ---------------------------------------------------------------------------

func TestMergeEnvVarsIntoCredentials(t *testing.T) {
	t.Setenv("SNYK_REGISTRY_USERNAME", "envuser")
	t.Setenv("SNYK_REGISTRY_PASSWORD", "envpass")
	opts := types.PluginOptions{}
	scan.MergeEnvVarsIntoCredentials(&opts)
	assert.Equal(t, "envuser", opts.Username)
	assert.Equal(t, "envpass", opts.Password)
}

func TestMergeEnvVarsIntoCredentials_flagsWin(t *testing.T) {
	t.Setenv("SNYK_REGISTRY_USERNAME", "envuser")
	t.Setenv("SNYK_REGISTRY_PASSWORD", "envpass")
	opts := types.PluginOptions{Username: "flaguser", Password: "flagpass"}
	scan.MergeEnvVarsIntoCredentials(&opts)
	assert.Equal(t, "flaguser", opts.Username)
	assert.Equal(t, "flagpass", opts.Password)
}

// ---------------------------------------------------------------------------
// Alpine / APK
// ---------------------------------------------------------------------------

const apkDB = `P:musl
V:1.2.4-r2
o:musl

P:busybox
V:1.36.1-r15
D:musl
o:busybox

P:alpine-baselayout
V:3.4.3-r2
D:musl busybox
o:alpine-baselayout

`

const alpineOSRelease = `ID=alpine
VERSION_ID=3.18.4
PRETTY_NAME="Alpine Linux v3.18"
`

func TestScan_Alpine_APK(t *testing.T) {
	layer := buildLayer(t, []fileEntry{
		{path: "/etc/os-release", content: alpineOSRelease},
		{path: "/lib/apk/db/installed", content: apkDB},
	})
	archivePath := buildArchive(t, "alpine:3.18", []v1.Layer{layer}, imageConfig{
		arch: "amd64",
		cmd:  []string{"/bin/sh"},
	})

	resp, err := scan.Scan(context.Background(), types.PluginOptions{
		Path: "docker-archive:" + archivePath,
	})
	require.NoError(t, err)
	require.Len(t, resp.ScanResults, 1)
	sr := resp.ScanResults[0]

	// identity
	assert.Equal(t, "apk", sr.Identity.Type)
	assert.Equal(t, "linux/amd64", sr.Identity.Args["platform"])

	// target
	assert.Equal(t, "docker-archive:"+archivePath, sr.Target.Image)

	// OS pretty name
	assert.Equal(t, "Alpine Linux v3.18", mustFactString(t, sr, types.FactImageOsReleasePrettyName))

	// platform
	assert.Equal(t, "linux/amd64", mustFactString(t, sr, types.FactPlatform))

	// depGraph — 3 packages parsed
	raw, ok := factData(t, sr, types.FactDepGraph)
	require.True(t, ok)
	var dg types.DepGraphData
	require.NoError(t, json.Unmarshal(raw, &dg))
	assert.Equal(t, "apk", dg.PkgManager.Name)
	// root + 3 packages
	assert.GreaterOrEqual(t, len(dg.Pkgs), 3)

	// imageId present and has sha256: prefix
	imageID := mustFactString(t, sr, types.FactImageID)
	assert.True(t, strings.HasPrefix(imageID, "sha256:"), "imageId should have sha256: prefix, got %s", imageID)

	// imageLayers non-empty
	layersRaw, ok := factData(t, sr, types.FactImageLayers)
	require.True(t, ok)
	var layers []string
	require.NoError(t, json.Unmarshal(layersRaw, &layers))
	assert.NotEmpty(t, layers)

	// rootFs non-empty
	_, ok = factData(t, sr, types.FactRootFs)
	assert.True(t, ok)

	// imageCreationTime
	_, ok = factData(t, sr, types.FactImageCreationTime)
	assert.True(t, ok)

	// pluginVersion
	pv := mustFactString(t, sr, types.FactPluginVersion)
	assert.NotEmpty(t, pv)
}

func TestScan_Alpine_arm64(t *testing.T) {
	layer := buildLayer(t, []fileEntry{
		{path: "/etc/os-release", content: alpineOSRelease},
		{path: "/lib/apk/db/installed", content: apkDB},
	})
	archivePath := buildArchive(t, "alpine:3.18", []v1.Layer{layer}, imageConfig{
		os:   "linux",
		arch: "arm64",
	})

	resp, err := scan.Scan(context.Background(), types.PluginOptions{
		Path: "docker-archive:" + archivePath,
	})
	require.NoError(t, err)
	sr := resp.ScanResults[0]
	assert.Equal(t, "linux/arm64", sr.Identity.Args["platform"])
	assert.Equal(t, "linux/arm64", mustFactString(t, sr, types.FactPlatform))
}

// Platform override in options takes precedence over image config.
func TestScan_PlatformOptionOverridesConfig(t *testing.T) {
	layer := buildLayer(t, []fileEntry{
		{path: "/etc/os-release", content: alpineOSRelease},
	})
	archivePath := buildArchive(t, "alpine:3.18", []v1.Layer{layer}, imageConfig{arch: "amd64"})

	resp, err := scan.Scan(context.Background(), types.PluginOptions{
		Path:     "docker-archive:" + archivePath,
		Platform: "linux/arm64/v8",
	})
	require.NoError(t, err)
	assert.Equal(t, "linux/arm64/v8", resp.ScanResults[0].Identity.Args["platform"])
}

// ---------------------------------------------------------------------------
// Debian / DEB
// ---------------------------------------------------------------------------

const dpkgStatus = `Package: libc6
Version: 2.36-9+deb12u3
Status: install ok installed
Architecture: amd64
Depends: libgcc-s1

Package: curl
Version: 7.88.1-10+deb12u5
Status: install ok installed
Architecture: amd64
Source: curl (7.88.1)
Depends: libc6

Package: wget
Version: 1.21.3-1+b1
Status: deinstall ok config-files
Architecture: amd64

`

const debianOSRelease = `ID=debian
VERSION_ID="12"
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
`

func TestScan_Debian_DEB(t *testing.T) {
	layer := buildLayer(t, []fileEntry{
		{path: "/etc/os-release", content: debianOSRelease},
		{path: "/var/lib/dpkg/status", content: dpkgStatus},
	})
	archivePath := buildArchive(t, "debian:12", []v1.Layer{layer}, imageConfig{
		cmd: []string{"bash"},
	})

	resp, err := scan.Scan(context.Background(), types.PluginOptions{
		Path: "docker-archive:" + archivePath,
	})
	require.NoError(t, err)
	sr := resp.ScanResults[0]

	assert.Equal(t, "deb", sr.Identity.Type)
	assert.Equal(t, "Debian GNU/Linux 12 (bookworm)", mustFactString(t, sr, types.FactImageOsReleasePrettyName))

	raw, ok := factData(t, sr, types.FactDepGraph)
	require.True(t, ok)
	var dg types.DepGraphData
	require.NoError(t, json.Unmarshal(raw, &dg))
	assert.Equal(t, "deb", dg.PkgManager.Name)
	// libc6 + curl installed (wget deinstalled → excluded)
	assert.GreaterOrEqual(t, len(dg.Pkgs), 2)
}

func TestScan_Debian_DpkgExtendedStates(t *testing.T) {
	extStates := "Package: curl\nAuto-Installed: 1\n\n"
	layer := buildLayer(t, []fileEntry{
		{path: "/etc/os-release", content: debianOSRelease},
		{path: "/var/lib/dpkg/status", content: dpkgStatus},
		{path: "/var/lib/apt/extended_states", content: extStates},
	})
	archivePath := buildArchive(t, "debian:12", []v1.Layer{layer}, imageConfig{})

	resp, err := scan.Scan(context.Background(), types.PluginOptions{
		Path: "docker-archive:" + archivePath,
	})
	require.NoError(t, err)
	// Scan should succeed; auto-installed marking is internal
	assert.Equal(t, "deb", resp.ScanResults[0].Identity.Type)
}

// ---------------------------------------------------------------------------
// No OS / scratch
// ---------------------------------------------------------------------------

func TestScan_Scratch_NoPackageManager(t *testing.T) {
	layer := buildLayer(t, []fileEntry{
		{path: "/hello", content: "hello world\n"},
	})
	archivePath := buildArchive(t, "scratch:latest", []v1.Layer{layer}, imageConfig{})

	resp, err := scan.Scan(context.Background(), types.PluginOptions{
		Path: "docker-archive:" + archivePath,
	})
	require.NoError(t, err)
	sr := resp.ScanResults[0]

	// Falls back to "linux" when no PM detected
	assert.Equal(t, "linux", sr.Identity.Type)

	// depGraph root only — no packages
	raw, ok := factData(t, sr, types.FactDepGraph)
	require.True(t, ok)
	var dg types.DepGraphData
	require.NoError(t, json.Unmarshal(raw, &dg))
	assert.Equal(t, "linux", dg.PkgManager.Name)
	assert.Equal(t, 1, len(dg.Pkgs)) // root only
}

// ---------------------------------------------------------------------------
// ContainerConfig fact
// ---------------------------------------------------------------------------

func TestScan_ContainerConfig(t *testing.T) {
	layer := buildLayer(t, []fileEntry{
		{path: "/etc/os-release", content: alpineOSRelease},
	})
	archivePath := buildArchive(t, "myapp:latest", []v1.Layer{layer}, imageConfig{
		env:        []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "MYVAR=hello"},
		cmd:        []string{"/app/server"},
		entrypoint: []string{"/entrypoint.sh"},
		workingDir: "/app",
		user:       "1000:1000",
	})

	resp, err := scan.Scan(context.Background(), types.PluginOptions{
		Path: "docker-archive:" + archivePath,
	})
	require.NoError(t, err)
	sr := resp.ScanResults[0]

	raw, ok := factData(t, sr, types.FactContainerConfig)
	require.True(t, ok, "containerConfig fact should be present")

	var cc map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &cc))
	assert.Equal(t, "/app", cc["workingDir"])
	assert.Equal(t, "1000:1000", cc["user"])
	assert.NotNil(t, cc["env"])
	assert.NotNil(t, cc["cmd"])
	assert.NotNil(t, cc["entrypoint"])
}

// ---------------------------------------------------------------------------
// ImageLabels fact
// ---------------------------------------------------------------------------

func TestScan_ImageLabels(t *testing.T) {
	layer := buildLayer(t, []fileEntry{
		{path: "/etc/os-release", content: alpineOSRelease},
	})
	archivePath := buildArchive(t, "labeled:latest", []v1.Layer{layer}, imageConfig{
		labels: map[string]string{
			"maintainer":   "test@example.com",
			"version":      "1.2.3",
			"custom.label": "value",
		},
	})

	resp, err := scan.Scan(context.Background(), types.PluginOptions{
		Path: "docker-archive:" + archivePath,
	})
	require.NoError(t, err)

	raw, ok := factData(t, resp.ScanResults[0], types.FactImageLabels)
	require.True(t, ok, "imageLabels fact should be present")
	var labels map[string]string
	require.NoError(t, json.Unmarshal(raw, &labels))
	assert.Equal(t, "test@example.com", labels["maintainer"])
	assert.Equal(t, "1.2.3", labels["version"])
}

// ---------------------------------------------------------------------------
// History fact
// ---------------------------------------------------------------------------

func TestScan_History(t *testing.T) {
	layer := buildLayer(t, []fileEntry{
		{path: "/etc/os-release", content: alpineOSRelease},
	})
	archivePath := buildArchive(t, "histtest:latest", []v1.Layer{layer}, imageConfig{})

	resp, err := scan.Scan(context.Background(), types.PluginOptions{
		Path: "docker-archive:" + archivePath,
	})
	require.NoError(t, err)

	raw, ok := factData(t, resp.ScanResults[0], types.FactHistory)
	require.True(t, ok, "history fact should be present")
	var history []map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &history))
	assert.NotEmpty(t, history)
}

// ---------------------------------------------------------------------------
// Multi-layer image (whiteout / layer merging)
// ---------------------------------------------------------------------------

func TestScan_MultiLayer(t *testing.T) {
	// Layer 1: base OS
	layer1 := buildLayer(t, []fileEntry{
		{path: "/etc/os-release", content: alpineOSRelease},
		{path: "/lib/apk/db/installed", content: apkDB},
	})
	// Layer 2: application files (no package changes)
	layer2 := buildLayer(t, []fileEntry{
		{path: "/app/main", content: "binary"},
	})
	archivePath := buildArchive(t, "myapp:1.0", []v1.Layer{layer1, layer2}, imageConfig{
		cmd: []string{"/app/main"},
	})

	resp, err := scan.Scan(context.Background(), types.PluginOptions{
		Path: "docker-archive:" + archivePath,
	})
	require.NoError(t, err)
	sr := resp.ScanResults[0]

	assert.Equal(t, "apk", sr.Identity.Type)

	// Should have 2 layers
	raw, ok := factData(t, sr, types.FactImageLayers)
	require.True(t, ok)
	var layers []string
	require.NoError(t, json.Unmarshal(raw, &layers))
	assert.Len(t, layers, 2)

	// Packages still detected from layer 1
	dgRaw, ok := factData(t, sr, types.FactDepGraph)
	require.True(t, ok)
	var dg types.DepGraphData
	require.NoError(t, json.Unmarshal(dgRaw, &dg))
	assert.GreaterOrEqual(t, len(dg.Pkgs), 3)
}

// ---------------------------------------------------------------------------
// OS release variants
// ---------------------------------------------------------------------------

func TestScan_Ubuntu_LsbRelease(t *testing.T) {
	lsbContent := "DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=22.04\nDISTRIB_CODENAME=jammy\n"
	dpkgContent := `Package: base-files
Version: 12ubuntu4
Status: install ok installed
Architecture: amd64

`
	layer := buildLayer(t, []fileEntry{
		{path: "/etc/lsb-release", content: lsbContent},
		{path: "/var/lib/dpkg/status", content: dpkgContent},
	})
	archivePath := buildArchive(t, "ubuntu:22.04", []v1.Layer{layer}, imageConfig{})

	resp, err := scan.Scan(context.Background(), types.PluginOptions{
		Path: "docker-archive:" + archivePath,
	})
	require.NoError(t, err)
	assert.Equal(t, "deb", resp.ScanResults[0].Identity.Type)
}

func TestScan_DebianVersion_FallbackOSRelease(t *testing.T) {
	// No /etc/os-release, only /etc/debian_version
	layer := buildLayer(t, []fileEntry{
		{path: "/etc/debian_version", content: "12.4\n"},
		{path: "/var/lib/dpkg/status", content: `Package: dpkg
Version: 1.21.22
Status: install ok installed
Architecture: amd64

`},
	})
	archivePath := buildArchive(t, "debian:12", []v1.Layer{layer}, imageConfig{})

	resp, err := scan.Scan(context.Background(), types.PluginOptions{
		Path: "docker-archive:" + archivePath,
	})
	require.NoError(t, err)
	assert.Equal(t, "deb", resp.ScanResults[0].Identity.Type)
}

func TestScan_RedHat_OSRelease(t *testing.T) {
	osRelease := `ID=rhel
VERSION_ID="9.3"
PRETTY_NAME="Red Hat Enterprise Linux 9.3 (Plow)"
`
	layer := buildLayer(t, []fileEntry{
		{path: "/etc/os-release", content: osRelease},
	})
	archivePath := buildArchive(t, "ubi9:latest", []v1.Layer{layer}, imageConfig{})

	resp, err := scan.Scan(context.Background(), types.PluginOptions{
		Path: "docker-archive:" + archivePath,
	})
	require.NoError(t, err)
	sr := resp.ScanResults[0]
	// rpm PM, no actual db → falls through to linux identity? No — identity is set from pm name
	assert.Equal(t, "Red Hat Enterprise Linux 9.3 (Plow)", mustFactString(t, sr, types.FactImageOsReleasePrettyName))
}

func TestScan_AlpineRelease_FallbackFile(t *testing.T) {
	// Only /etc/alpine-release present, no /etc/os-release
	layer := buildLayer(t, []fileEntry{
		{path: "/etc/alpine-release", content: "3.18.4\n"},
		{path: "/lib/apk/db/installed", content: apkDB},
	})
	archivePath := buildArchive(t, "alpine:custom", []v1.Layer{layer}, imageConfig{})

	resp, err := scan.Scan(context.Background(), types.PluginOptions{
		Path: "docker-archive:" + archivePath,
	})
	require.NoError(t, err)
	assert.Equal(t, "apk", resp.ScanResults[0].Identity.Type)
}

// ---------------------------------------------------------------------------
// Image root name / version
// ---------------------------------------------------------------------------

func TestScan_TargetContainsImagePath(t *testing.T) {
	layer := buildLayer(t, []fileEntry{
		{path: "/etc/os-release", content: alpineOSRelease},
	})
	archivePath := buildArchive(t, "myregistry.io/myteam/myapp:v1.2.3", []v1.Layer{layer}, imageConfig{})

	resp, err := scan.Scan(context.Background(), types.PluginOptions{
		Path: "docker-archive:" + archivePath,
	})
	require.NoError(t, err)
	assert.Equal(t, "docker-archive:"+archivePath, resp.ScanResults[0].Target.Image)
}

// ---------------------------------------------------------------------------
// APK: provides / dependency graph shape
// ---------------------------------------------------------------------------

func TestScan_APK_DependencyResolution(t *testing.T) {
	apkWithDeps := `P:musl
V:1.2.4-r2
p:so:libc.musl-x86_64.so.1=1
o:musl

P:busybox
V:1.36.1-r15
D:so:libc.musl-x86_64.so.1
o:busybox

P:curl
V:8.5.0-r0
D:musl
o:curl

`
	layer := buildLayer(t, []fileEntry{
		{path: "/etc/os-release", content: "ID=alpine\nVERSION_ID=3.18.4\n"},
		{path: "/lib/apk/db/installed", content: apkWithDeps},
	})
	archivePath := buildArchive(t, "alpine:test", []v1.Layer{layer}, imageConfig{})

	resp, err := scan.Scan(context.Background(), types.PluginOptions{
		Path: "docker-archive:" + archivePath,
	})
	require.NoError(t, err)
	sr := resp.ScanResults[0]
	assert.Equal(t, "apk", sr.Identity.Type)

	raw, _ := factData(t, sr, types.FactDepGraph)
	var dg types.DepGraphData
	require.NoError(t, json.Unmarshal(raw, &dg))
	// Should have root + musl + busybox + curl
	assert.GreaterOrEqual(t, len(dg.Pkgs), 4)
}

// ---------------------------------------------------------------------------
// DepGraph schema version and structure
// ---------------------------------------------------------------------------

func TestScan_DepGraph_SchemaVersion(t *testing.T) {
	layer := buildLayer(t, []fileEntry{
		{path: "/etc/os-release", content: alpineOSRelease},
		{path: "/lib/apk/db/installed", content: apkDB},
	})
	archivePath := buildArchive(t, "alpine:3.18", []v1.Layer{layer}, imageConfig{})

	resp, err := scan.Scan(context.Background(), types.PluginOptions{
		Path: "docker-archive:" + archivePath,
	})
	require.NoError(t, err)
	raw, ok := factData(t, resp.ScanResults[0], types.FactDepGraph)
	require.True(t, ok)
	var dg types.DepGraphData
	require.NoError(t, json.Unmarshal(raw, &dg))
	assert.Equal(t, "1.2.0", dg.SchemaVersion)
	assert.Equal(t, "root-node", dg.Graph.RootNodeID)
	assert.NotEmpty(t, dg.Graph.Nodes)
}

// ---------------------------------------------------------------------------
// Gzip-compressed outer archive (same format as java.tar in fixtures)
// ---------------------------------------------------------------------------

func TestScan_GzipCompressedArchive(t *testing.T) {
	layer := buildLayer(t, []fileEntry{
		{path: "/etc/os-release", content: alpineOSRelease},
		{path: "/lib/apk/db/installed", content: apkDB},
	})

	// Write a normal docker-archive, then gzip it.
	ref, err := name.ParseReference("alpine:gzip-test")
	require.NoError(t, err)

	img := empty.Image
	img, err = mutate.AppendLayers(img, layer)
	require.NoError(t, err)

	dir := t.TempDir()
	plainPath := filepath.Join(dir, "image.tar")
	require.NoError(t, tarball.WriteToFile(plainPath, ref, img))

	// Gzip the archive.
	gzPath := filepath.Join(dir, "image.tar.gz")
	{
		in, err := os.Open(plainPath)
		require.NoError(t, err)
		defer in.Close()
		out, err := os.Create(gzPath)
		require.NoError(t, err)
		defer out.Close()
		gw := gzip.NewWriter(out)
		_, err = io.Copy(gw, in)
		require.NoError(t, err)
		require.NoError(t, gw.Close())
	}

	resp, err := scan.Scan(context.Background(), types.PluginOptions{
		Path: "docker-archive:" + gzPath,
	})
	require.NoError(t, err)
	assert.Equal(t, "apk", resp.ScanResults[0].Identity.Type)
}

// ---------------------------------------------------------------------------
// UsrLib APK path variant
// ---------------------------------------------------------------------------

func TestScan_APK_UsrLibPath(t *testing.T) {
	layer := buildLayer(t, []fileEntry{
		{path: "/etc/os-release", content: alpineOSRelease},
		{path: "/usr/lib/apk/db/installed", content: apkDB}, // alternate path
	})
	archivePath := buildArchive(t, "alpine:usrlib", []v1.Layer{layer}, imageConfig{})

	resp, err := scan.Scan(context.Background(), types.PluginOptions{
		Path: "docker-archive:" + archivePath,
	})
	require.NoError(t, err)
	assert.Equal(t, "apk", resp.ScanResults[0].Identity.Type)

	raw, _ := factData(t, resp.ScanResults[0], types.FactDepGraph)
	var dg types.DepGraphData
	require.NoError(t, json.Unmarshal(raw, &dg))
	assert.GreaterOrEqual(t, len(dg.Pkgs), 3)
}

// ---------------------------------------------------------------------------
// Duplicate package manager files (later layer wins)
// ---------------------------------------------------------------------------

func TestScan_LayerMerge_LaterLayerWins(t *testing.T) {
	// Layer 1 has a small APK db, layer 2 overrides with a larger one
	smallAPK := "P:musl\nV:1.0.0\no:musl\n\n"
	bigAPK := apkDB // has 3 packages

	layer1 := buildLayer(t, []fileEntry{
		{path: "/etc/os-release", content: alpineOSRelease},
		{path: "/lib/apk/db/installed", content: smallAPK},
	})
	layer2 := buildLayer(t, []fileEntry{
		{path: "/lib/apk/db/installed", content: bigAPK},
	})
	archivePath := buildArchive(t, "alpine:merged", []v1.Layer{layer1, layer2}, imageConfig{})

	resp, err := scan.Scan(context.Background(), types.PluginOptions{
		Path: "docker-archive:" + archivePath,
	})
	require.NoError(t, err)
	raw, _ := factData(t, resp.ScanResults[0], types.FactDepGraph)
	var dg types.DepGraphData
	require.NoError(t, json.Unmarshal(raw, &dg))
	// Should use the bigger APK db from layer 2
	assert.GreaterOrEqual(t, len(dg.Pkgs), 3)
}

// ---------------------------------------------------------------------------
// buildExtractActions smoke test (via Scan exercising all action types)
// ---------------------------------------------------------------------------

func TestScan_AllPackageManagerActionsRegistered(t *testing.T) {
	// An image with no package files should still scan without error.
	layer := buildLayer(t, []fileEntry{
		{path: "/app/readme.txt", content: "hello"},
	})
	archivePath := buildArchive(t, "empty:latest", []v1.Layer{layer}, imageConfig{})

	resp, err := scan.Scan(context.Background(), types.PluginOptions{
		Path: "docker-archive:" + archivePath,
	})
	require.NoError(t, err)
	assert.Len(t, resp.ScanResults, 1)
	// All expected fact types present
	factTypes := map[types.FactType]bool{}
	for _, f := range resp.ScanResults[0].Facts {
		factTypes[f.Type] = true
	}
	assert.True(t, factTypes[types.FactDepGraph])
	assert.True(t, factTypes[types.FactImageID])
	assert.True(t, factTypes[types.FactImageLayers])
	assert.True(t, factTypes[types.FactPlatform])
	assert.True(t, factTypes[types.FactPluginVersion])
}
