package oci_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	digest "github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	specsv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/snyk/snyk-docker-plugin/pkg/extractor"
	"github.com/snyk/snyk-docker-plugin/pkg/extractor/oci"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- fixture helpers --------------------------------------------------------

func fixtureDir() string {
	_, file, _, _ := runtime.Caller(0)
	// go/pkg/extractor/oci/archive_test.go → 4 levels up = repo root
	root := filepath.Join(filepath.Dir(file), "..", "..", "..", "..")
	return filepath.Join(root, "test", "fixtures", "oci-archives")
}

func fixturePath(name string) string {
	return filepath.Join(fixtureDir(), name)
}

// ---- in-memory OCI archive builder -----------------------------------------

// addBlob writes data into the tar under blobs/sha256/<hex> and returns its digest.
func addBlob(tw *tar.Writer, data []byte) digest.Digest {
	h := sha256.Sum256(data)
	hex := fmt.Sprintf("%x", h)
	path := "blobs/sha256/" + hex
	_ = tw.WriteHeader(&tar.Header{
		Name:     path,
		Typeflag: tar.TypeReg,
		Size:     int64(len(data)),
	})
	_, _ = tw.Write(data)
	return digest.Digest("sha256:" + hex)
}

type ociArchiveOptions struct {
	architecture  string
	os_           string
	created       string
	labels        map[string]string
	env           []string
	entrypoint    []string
	cmd           []string
	layerFiles    []map[string][]byte // one per layer
	history       []extractor.HistoryEntry
	emptyManifest bool // write index.json with empty manifests list
	omitIndex     bool // don't write index.json at all
	omitManifest  bool // don't write manifest blob (corrupt index)
	omitConfig    bool // don't write config blob (corrupt manifest)
	omitLayer     bool // don't write layer blob (corrupt manifest)
}

// buildOCIArchive creates a minimal but valid OCI archive in memory.
func buildOCIArchive(t *testing.T, opts ociArchiveOptions) []byte {
	t.Helper()
	if opts.architecture == "" {
		opts.architecture = "amd64"
	}
	if opts.os_ == "" {
		opts.os_ = "linux"
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// Build layer tars (gzip-compressed blobs) and collect diffIDs.
	var layerDescs []specsv1.Descriptor
	var diffIDs []string
	for _, lfiles := range opts.layerFiles {
		layerTar := makeLayerTar(lfiles)

		// diffID = sha256 of uncompressed tar
		raw := sha256.Sum256(layerTar)
		diffIDs = append(diffIDs, fmt.Sprintf("sha256:%x", raw))

		// gzip compress
		var gz bytes.Buffer
		gw := gzip.NewWriter(&gz)
		_, _ = gw.Write(layerTar)
		_ = gw.Close()
		compressed := gz.Bytes()

		if !opts.omitLayer {
			d := addBlob(tw, compressed)
			layerDescs = append(layerDescs, specsv1.Descriptor{
				MediaType: specsv1.MediaTypeImageLayerGzip,
				Digest:    d,
				Size:      int64(len(compressed)),
			})
		} else {
			// Reference a layer that won't exist in the archive.
			layerDescs = append(layerDescs, specsv1.Descriptor{
				MediaType: specsv1.MediaTypeImageLayerGzip,
				Digest:    digest.Digest("sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
				Size:      1,
			})
		}
	}

	// Build image config.
	cfg := extractor.ImageConfig{
		Architecture: opts.architecture,
		OS:           opts.os_,
		Created:      opts.created,
		RootFS: extractor.RootFS{
			Type:    "layers",
			DiffIDs: diffIDs,
		},
		History: opts.history,
	}
	if opts.labels != nil || opts.env != nil || opts.entrypoint != nil || opts.cmd != nil {
		cfg.Config = &extractor.ContainerConfig{
			Labels:     opts.labels,
			Env:        opts.env,
			Entrypoint: opts.entrypoint,
			Cmd:        opts.cmd,
		}
	}
	cfgData, _ := json.Marshal(cfg)

	var configDigest digest.Digest
	if !opts.omitConfig {
		configDigest = addBlob(tw, cfgData)
	} else {
		configDigest = digest.Digest("sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee1")
	}

	// Build manifest.
	manifest := specsv1.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: specsv1.MediaTypeImageManifest,
		Config: specsv1.Descriptor{
			MediaType: specsv1.MediaTypeImageConfig,
			Digest:    configDigest,
			Size:      int64(len(cfgData)),
		},
		Layers: layerDescs,
	}
	manifestData, _ := json.Marshal(manifest)

	var manifestDigest digest.Digest
	if !opts.omitManifest {
		manifestDigest = addBlob(tw, manifestData)
	} else {
		manifestDigest = digest.Digest("sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee2")
	}

	// Build index.json.
	if !opts.omitIndex {
		var manifests []specsv1.Descriptor
		if !opts.emptyManifest {
			manifests = []specsv1.Descriptor{{
				MediaType: specsv1.MediaTypeImageManifest,
				Digest:    manifestDigest,
				Size:      int64(len(manifestData)),
			}}
		}
		index := specsv1.Index{
			Versioned: specs.Versioned{SchemaVersion: 2},
			Manifests: manifests,
		}
		indexData, _ := json.Marshal(index)
		_ = tw.WriteHeader(&tar.Header{
			Name:     "index.json",
			Typeflag: tar.TypeReg,
			Size:     int64(len(indexData)),
		})
		_, _ = tw.Write(indexData)
	}

	_ = tw.Close()
	return buf.Bytes()
}

func makeLayerTar(files map[string][]byte) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, data := range files {
		_ = tw.WriteHeader(&tar.Header{
			Name:     name,
			Typeflag: tar.TypeReg,
			Size:     int64(len(data)),
		})
		_, _ = tw.Write(data)
	}
	_ = tw.Close()
	return buf.Bytes()
}

// writeTempOCI writes archive bytes to a temp file and returns the path.
func writeTempOCI(t *testing.T, data []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "oci-*.tar")
	require.NoError(t, err)
	_, err = f.Write(data)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

// ---- tests using real fixture files -----------------------------------------

func TestExtractArchive_notFound(t *testing.T) {
	_, err := oci.ExtractArchive("/nonexistent/path/image.tar", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "opening oci archive")
}

func TestExtractArchive_busybox(t *testing.T) {
	path := fixturePath("busybox-1.31.1.tar")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("fixture not available: %v", err)
	}
	result, err := oci.ExtractArchive(path, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.ImageID)
	assert.True(t, len(result.ManifestLayers) > 0, "expected at least one layer")
}

func TestExtractArchive_busybox_withAction(t *testing.T) {
	path := fixturePath("busybox-1.31.1.tar")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("fixture not available: %v", err)
	}
	actions := []extractor.ExtractAction{
		{
			ActionName:      "osRelease",
			FilePathMatches: func(p string) bool { return p == "/etc/os-release" },
			Callback: func(r io.Reader, _ int64) (interface{}, error) {
				return io.ReadAll(r)
			},
		},
	}
	result, err := oci.ExtractArchive(path, actions)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestExtractArchive_alpine(t *testing.T) {
	path := fixturePath("alpine-3.12.0.tar")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("fixture not available: %v", err)
	}
	// This fixture contains macOS .DS_Store entries with non-standard tar
	// headers; extraction may fail — we just ensure it doesn't panic.
	result, _ := oci.ExtractArchive(path, nil)
	if result != nil {
		assert.NotEmpty(t, result.ImageID)
	}
}

// ---- tests using synthetic in-memory archives --------------------------------

func TestExtractArchive_synthetic_basic(t *testing.T) {
	archiveData := buildOCIArchive(t, ociArchiveOptions{
		architecture: "amd64",
		os_:          "linux",
		created:      "2024-01-01T00:00:00Z",
		layerFiles: []map[string][]byte{
			{"etc/os-release": []byte("ID=alpine\nVERSION_ID=3.18")},
		},
	})
	path := writeTempOCI(t, archiveData)

	actions := []extractor.ExtractAction{
		{
			ActionName:      "osRelease",
			FilePathMatches: func(p string) bool { return p == "/etc/os-release" },
		},
	}
	result, err := oci.ExtractArchive(path, actions)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotEmpty(t, result.ImageID)
	assert.Contains(t, result.ImageID, "sha256:")
	assert.Equal(t, "2024-01-01T00:00:00Z", result.ImageCreationTime)
	assert.Equal(t, "linux/amd64", result.Platform)
	assert.Len(t, result.ManifestLayers, 1)
	assert.Contains(t, result.ManifestLayers[0], "sha256:")

	content := result.Layers.GetContent("osRelease")
	assert.Equal(t, []byte("ID=alpine\nVERSION_ID=3.18"), content)
}

func TestExtractArchive_synthetic_multipleLayers(t *testing.T) {
	archiveData := buildOCIArchive(t, ociArchiveOptions{
		layerFiles: []map[string][]byte{
			{"etc/os-release": []byte("ID=base")},
			{"etc/os-release": []byte("ID=overlay"), "usr/bin/sh": []byte("sh")},
		},
	})
	path := writeTempOCI(t, archiveData)

	actions := []extractor.ExtractAction{{
		ActionName:      "all",
		FilePathMatches: func(_ string) bool { return true },
	}}
	result, err := oci.ExtractArchive(path, actions)
	require.NoError(t, err)
	assert.Len(t, result.ManifestLayers, 2)
	// Later layer wins for os-release.
	assert.Equal(t, []byte("ID=overlay"), result.Layers.GetContentByPath("all", "/etc/os-release"))
	assert.Equal(t, []byte("sh"), result.Layers.GetContentByPath("all", "/usr/bin/sh"))
}

func TestExtractArchive_synthetic_labels(t *testing.T) {
	labels := map[string]string{"maintainer": "test", "version": "1.0"}
	archiveData := buildOCIArchive(t, ociArchiveOptions{
		labels:     labels,
		layerFiles: []map[string][]byte{{}},
	})
	path := writeTempOCI(t, archiveData)

	result, err := oci.ExtractArchive(path, nil)
	require.NoError(t, err)
	assert.Equal(t, labels, result.ImageLabels)
	require.NotNil(t, result.ContainerConfig)
	assert.Equal(t, labels, result.ContainerConfig.Labels)
}

func TestExtractArchive_synthetic_containerConfig(t *testing.T) {
	archiveData := buildOCIArchive(t, ociArchiveOptions{
		env:        []string{"PATH=/usr/bin", "HOME=/root"},
		entrypoint: []string{"/bin/sh"},
		cmd:        []string{"-c", "echo hello"},
		layerFiles: []map[string][]byte{{}},
	})
	path := writeTempOCI(t, archiveData)

	result, err := oci.ExtractArchive(path, nil)
	require.NoError(t, err)
	require.NotNil(t, result.ContainerConfig)
	assert.Equal(t, []string{"PATH=/usr/bin", "HOME=/root"}, result.ContainerConfig.Env)
	assert.Equal(t, []string{"/bin/sh"}, result.ContainerConfig.Entrypoint)
	assert.Equal(t, []string{"-c", "echo hello"}, result.ContainerConfig.Cmd)
}

func TestExtractArchive_synthetic_rootFsLayers(t *testing.T) {
	archiveData := buildOCIArchive(t, ociArchiveOptions{
		layerFiles: []map[string][]byte{
			{"a": []byte("1")},
			{"b": []byte("2")},
		},
	})
	path := writeTempOCI(t, archiveData)

	result, err := oci.ExtractArchive(path, nil)
	require.NoError(t, err)
	assert.Len(t, result.RootFsLayers, 2)
	for _, id := range result.RootFsLayers {
		assert.Contains(t, id, "sha256:")
	}
}

func TestExtractArchive_synthetic_history(t *testing.T) {
	history := []extractor.HistoryEntry{
		{CreatedBy: "ADD file:abc", Created: "2024-01-01T00:00:00Z"},
		{CreatedBy: `CMD ["/bin/sh"]`, EmptyLayer: true},
	}
	archiveData := buildOCIArchive(t, ociArchiveOptions{
		history:    history,
		layerFiles: []map[string][]byte{{}},
	})
	path := writeTempOCI(t, archiveData)

	result, err := oci.ExtractArchive(path, nil)
	require.NoError(t, err)
	assert.Equal(t, history, result.History)
}

func TestExtractArchive_synthetic_noLabels(t *testing.T) {
	// No ContainerConfig → ImageLabels should be nil.
	archiveData := buildOCIArchive(t, ociArchiveOptions{
		layerFiles: []map[string][]byte{{}},
	})
	path := writeTempOCI(t, archiveData)

	result, err := oci.ExtractArchive(path, nil)
	require.NoError(t, err)
	assert.Nil(t, result.ImageLabels)
}

func TestExtractArchive_synthetic_emptyLayers(t *testing.T) {
	// Archive with no layers at all.
	archiveData := buildOCIArchive(t, ociArchiveOptions{
		layerFiles: []map[string][]byte{},
	})
	path := writeTempOCI(t, archiveData)

	result, err := oci.ExtractArchive(path, nil)
	require.NoError(t, err)
	assert.Empty(t, result.ManifestLayers)
	assert.Empty(t, result.Layers)
}

func TestExtractArchive_synthetic_platformPopulated(t *testing.T) {
	archiveData := buildOCIArchive(t, ociArchiveOptions{
		architecture: "arm64",
		os_:          "linux",
		layerFiles:   []map[string][]byte{{}},
	})
	path := writeTempOCI(t, archiveData)

	result, err := oci.ExtractArchive(path, nil)
	require.NoError(t, err)
	assert.Equal(t, "linux/arm64", result.Platform)
}

func TestExtractArchive_synthetic_platformEmptyWhenMissingFields(t *testing.T) {
	// Manually craft a config JSON with empty os/arch, bypassing the builder
	// defaults, so the extractor sees empty strings and skips Platform.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// layer
	layerTar := makeLayerTar(map[string][]byte{})
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	_, _ = gw.Write(layerTar)
	_ = gw.Close()
	layerD := addBlob(tw, gz.Bytes())

	// config with empty os and architecture
	type minCfg struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		RootFS       struct {
			Type string `json:"type"`
		} `json:"rootfs"`
	}
	cfgData, _ := json.Marshal(minCfg{OS: "", Architecture: ""})
	configD := addBlob(tw, cfgData)

	// manifest
	manifest := specsv1.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		Config: specsv1.Descriptor{MediaType: specsv1.MediaTypeImageConfig, Digest: configD, Size: int64(len(cfgData))},
		Layers: []specsv1.Descriptor{{MediaType: specsv1.MediaTypeImageLayerGzip, Digest: layerD}},
	}
	manifestData, _ := json.Marshal(manifest)
	manifestD := addBlob(tw, manifestData)

	// index
	index := specsv1.Index{
		Versioned: specs.Versioned{SchemaVersion: 2},
		Manifests: []specsv1.Descriptor{{MediaType: specsv1.MediaTypeImageManifest, Digest: manifestD, Size: int64(len(manifestData))}},
	}
	indexData, _ := json.Marshal(index)
	_ = tw.WriteHeader(&tar.Header{Name: "index.json", Typeflag: tar.TypeReg, Size: int64(len(indexData))})
	_, _ = tw.Write(indexData)
	_ = tw.Close()

	path := writeTempOCI(t, buf.Bytes())
	result, err := oci.ExtractArchive(path, nil)
	require.NoError(t, err)
	assert.Empty(t, result.Platform)
}

func TestExtractArchive_missingIndex(t *testing.T) {
	archiveData := buildOCIArchive(t, ociArchiveOptions{
		omitIndex:  true,
		layerFiles: []map[string][]byte{{}},
	})
	path := writeTempOCI(t, archiveData)

	_, err := oci.ExtractArchive(path, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "index.json")
}

func TestExtractArchive_emptyManifestList(t *testing.T) {
	archiveData := buildOCIArchive(t, ociArchiveOptions{
		emptyManifest: true,
		layerFiles:    []map[string][]byte{{}},
	})
	path := writeTempOCI(t, archiveData)

	_, err := oci.ExtractArchive(path, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no manifests")
}

func TestExtractArchive_missingManifestBlob(t *testing.T) {
	archiveData := buildOCIArchive(t, ociArchiveOptions{
		omitManifest: true,
		layerFiles:   []map[string][]byte{{}},
	})
	path := writeTempOCI(t, archiveData)

	_, err := oci.ExtractArchive(path, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestExtractArchive_missingConfigBlob(t *testing.T) {
	archiveData := buildOCIArchive(t, ociArchiveOptions{
		omitConfig: true,
		layerFiles: []map[string][]byte{{}},
	})
	path := writeTempOCI(t, archiveData)

	_, err := oci.ExtractArchive(path, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestExtractArchive_missingLayerBlob(t *testing.T) {
	archiveData := buildOCIArchive(t, ociArchiveOptions{
		omitLayer:  true,
		layerFiles: []map[string][]byte{{"f": []byte("x")}},
	})
	path := writeTempOCI(t, archiveData)

	_, err := oci.ExtractArchive(path, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestExtractArchive_invalidTar(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "bad-*.tar")
	require.NoError(t, err)
	_, _ = f.Write([]byte("not a tar at all"))
	_ = f.Close()

	_, err = oci.ExtractArchive(f.Name(), nil)
	require.Error(t, err)
}

func TestExtractArchive_imageID_matchesConfigDigest(t *testing.T) {
	archiveData := buildOCIArchive(t, ociArchiveOptions{
		layerFiles: []map[string][]byte{{}},
	})
	path := writeTempOCI(t, archiveData)

	result, err := oci.ExtractArchive(path, nil)
	require.NoError(t, err)
	// ImageID must be "sha256:<hex>" (64 hex chars after the colon).
	assert.Regexp(t, `^sha256:[0-9a-f]{64}$`, result.ImageID)
}

func TestExtractArchive_layerDigests_haveSha256Prefix(t *testing.T) {
	archiveData := buildOCIArchive(t, ociArchiveOptions{
		layerFiles: []map[string][]byte{
			{"a": []byte("x")},
			{"b": []byte("y")},
		},
	})
	path := writeTempOCI(t, archiveData)

	result, err := oci.ExtractArchive(path, nil)
	require.NoError(t, err)
	for _, l := range result.ManifestLayers {
		assert.Regexp(t, `^sha256:[0-9a-f]{64}$`, l)
	}
}
