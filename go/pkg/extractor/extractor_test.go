package extractor_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/snyk/snyk-docker-plugin/pkg/extractor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- helpers ----------------------------------------------------------------

// makeTar builds an uncompressed in-memory tar with the given files.
func makeTar(files map[string][]byte) []byte {
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

// makeGzipTar wraps makeTar output in gzip.
func makeGzipTar(files map[string][]byte) []byte {
	raw := makeTar(files)
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write(raw)
	_ = gw.Close()
	return buf.Bytes()
}

// makeZstdTar wraps makeTar output in zstd.
func makeZstdTar(files map[string][]byte) []byte {
	raw := makeTar(files)
	var buf bytes.Buffer
	zw, _ := zstd.NewWriter(&buf)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	return buf.Bytes()
}

func matchAll(_ string) bool { return true }
func matchNone(_ string) bool { return false }

func readAction(name string) extractor.ExtractAction {
	return extractor.ExtractAction{
		ActionName:      name,
		FilePathMatches: matchAll,
		Callback:        nil, // raw bytes
	}
}

// ---- IsWhitedOutFile --------------------------------------------------------

func TestIsWhitedOutFile_positive(t *testing.T) {
	assert.True(t, extractor.IsWhitedOutFile("/etc/.wh.passwd"))
	assert.True(t, extractor.IsWhitedOutFile(".wh.foo"))
	assert.True(t, extractor.IsWhitedOutFile("/a/b/.wh..wh..opq"))
}

func TestIsWhitedOutFile_negative(t *testing.T) {
	assert.False(t, extractor.IsWhitedOutFile("/etc/passwd"))
	assert.False(t, extractor.IsWhitedOutFile("/etc/os-release"))
	assert.False(t, extractor.IsWhitedOutFile(""))
}

// ---- ExtractImageContent ----------------------------------------------------

func TestExtractImageContent_nilExtractor(t *testing.T) {
	_, err := extractor.ExtractImageContent(context.Background(), nil, "/any", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no extractor provided")
}

func TestExtractImageContent_delegatesToExtractor(t *testing.T) {
	want := &extractor.ExtractionResult{ImageID: "sha256:abc"}
	extractFn := func(path string, actions []extractor.ExtractAction) (*extractor.ExtractionResult, error) {
		assert.Equal(t, "/my/archive.tar", path)
		return want, nil
	}
	got, err := extractor.ExtractImageContent(context.Background(), extractFn, "/my/archive.tar", nil)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestExtractImageContent_propagatesExtractorError(t *testing.T) {
	extractFn := func(_ string, _ []extractor.ExtractAction) (*extractor.ExtractionResult, error) {
		return nil, errors.New("boom")
	}
	_, err := extractor.ExtractImageContent(context.Background(), extractFn, "/x", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "boom")
}

// ---- ExtractLayer -----------------------------------------------------------

func TestExtractLayer_uncompressed_matchAll(t *testing.T) {
	files := map[string][]byte{
		"etc/os-release": []byte("ID=alpine"),
		"usr/bin/sh":     []byte("binary"),
	}
	data := makeTar(files)
	actions := []extractor.ExtractAction{readAction("all")}

	lf, err := extractor.ExtractLayer(bytes.NewReader(data), actions)
	require.NoError(t, err)
	assert.Len(t, lf["all"], 2)
	assert.Equal(t, []byte("ID=alpine"), lf["all"]["/etc/os-release"])
	assert.Equal(t, []byte("binary"), lf["all"]["/usr/bin/sh"])
}

func TestExtractLayer_gzip(t *testing.T) {
	files := map[string][]byte{"etc/alpine-release": []byte("3.12.0")}
	data := makeGzipTar(files)
	actions := []extractor.ExtractAction{readAction("alpineRelease")}

	lf, err := extractor.ExtractLayer(bytes.NewReader(data), actions)
	require.NoError(t, err)
	assert.Equal(t, []byte("3.12.0"), lf["alpineRelease"]["/etc/alpine-release"])
}

func TestExtractLayer_zstd(t *testing.T) {
	files := map[string][]byte{"etc/hostname": []byte("mybox")}
	data := makeZstdTar(files)
	actions := []extractor.ExtractAction{readAction("hostname")}

	lf, err := extractor.ExtractLayer(bytes.NewReader(data), actions)
	require.NoError(t, err)
	assert.Equal(t, []byte("mybox"), lf["hostname"]["/etc/hostname"])
}

func TestExtractLayer_noActions(t *testing.T) {
	data := makeTar(map[string][]byte{"etc/passwd": []byte("root")})
	lf, err := extractor.ExtractLayer(bytes.NewReader(data), nil)
	require.NoError(t, err)
	assert.Empty(t, lf)
}

func TestExtractLayer_noMatchingActions(t *testing.T) {
	data := makeTar(map[string][]byte{"etc/passwd": []byte("root")})
	actions := []extractor.ExtractAction{
		{ActionName: "never", FilePathMatches: matchNone},
	}
	lf, err := extractor.ExtractLayer(bytes.NewReader(data), actions)
	require.NoError(t, err)
	assert.Empty(t, lf["never"])
}

func TestExtractLayer_emptyTar(t *testing.T) {
	data := makeTar(map[string][]byte{})
	lf, err := extractor.ExtractLayer(bytes.NewReader(data), []extractor.ExtractAction{readAction("x")})
	require.NoError(t, err)
	assert.Empty(t, lf)
}

func TestExtractLayer_callbackInvoked(t *testing.T) {
	files := map[string][]byte{"etc/issue": []byte("Alpine")}
	data := makeTar(files)

	var capturedSize int64
	action := extractor.ExtractAction{
		ActionName:      "issue",
		FilePathMatches: matchAll,
		Callback: func(r io.Reader, size int64) (interface{}, error) {
			capturedSize = size
			b, err := io.ReadAll(r)
			return string(b), err
		},
	}

	lf, err := extractor.ExtractLayer(bytes.NewReader(data), []extractor.ExtractAction{action})
	require.NoError(t, err)
	assert.Equal(t, int64(6), capturedSize)
	assert.Equal(t, "Alpine", lf["issue"]["/etc/issue"])
}

func TestExtractLayer_callbackErrorSkipsFile(t *testing.T) {
	files := map[string][]byte{
		"etc/bad":  []byte("bad"),
		"etc/good": []byte("good"),
	}
	data := makeTar(files)

	action := extractor.ExtractAction{
		ActionName:      "result",
		FilePathMatches: matchAll,
		Callback: func(r io.Reader, _ int64) (interface{}, error) {
			b, _ := io.ReadAll(r)
			if string(b) == "bad" {
				return nil, errors.New("bad file")
			}
			return b, nil
		},
	}

	lf, err := extractor.ExtractLayer(bytes.NewReader(data), []extractor.ExtractAction{action})
	require.NoError(t, err)
	// Only the "good" file should be present.
	assert.Len(t, lf["result"], 1)
	assert.Contains(t, lf["result"], "/etc/good")
}

func TestExtractLayer_multipleActions_sameFile(t *testing.T) {
	// When two actions match the same file the underlying tar reader is shared:
	// the first action consumes the stream; the second gets empty bytes.
	// This documents the current single-pass behaviour.
	files := map[string][]byte{"etc/os-release": []byte("ID=debian")}
	data := makeTar(files)
	actions := []extractor.ExtractAction{
		readAction("actionA"),
		readAction("actionB"),
	}
	lf, err := extractor.ExtractLayer(bytes.NewReader(data), actions)
	require.NoError(t, err)
	// First action gets the real content.
	assert.Equal(t, []byte("ID=debian"), lf["actionA"]["/etc/os-release"])
	// Second action gets an exhausted reader — empty bytes, not missing key.
	_, secondPresent := lf["actionB"]["/etc/os-release"]
	assert.True(t, secondPresent, "second action entry should be recorded")
}

func TestExtractLayer_pathNormalisedWithLeadingSlash(t *testing.T) {
	// Tar entries without a leading slash should be normalised.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{
		Name:     "etc/os-release", // no leading slash
		Typeflag: tar.TypeReg,
		Size:     2,
	})
	_, _ = tw.Write([]byte("ok"))
	_ = tw.Close()

	lf, err := extractor.ExtractLayer(&buf, []extractor.ExtractAction{readAction("r")})
	require.NoError(t, err)
	_, hasSlash := lf["r"]["/etc/os-release"]
	assert.True(t, hasSlash, "path should be normalised to /etc/os-release")
}

func TestExtractLayer_nonRegularFilesSkipped(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{
		Name:     "etc/",
		Typeflag: tar.TypeDir,
	})
	_ = tw.Close()

	lf, err := extractor.ExtractLayer(&buf, []extractor.ExtractAction{readAction("r")})
	require.NoError(t, err)
	assert.Empty(t, lf)
}

func TestExtractLayer_invalidTar(t *testing.T) {
	_, err := extractor.ExtractLayer(bytes.NewReader([]byte("not a tar")), []extractor.ExtractAction{readAction("r")})
	require.Error(t, err)
}

// ---- MergeLayers ------------------------------------------------------------

func TestMergeLayers_empty(t *testing.T) {
	m := extractor.MergeLayers(nil)
	assert.Empty(t, m)
}

func TestMergeLayers_singleLayer(t *testing.T) {
	lf := extractor.LayerFiles{
		"osRelease": {"/etc/os-release": []byte("ID=alpine")},
	}
	m := extractor.MergeLayers([]extractor.LayerFiles{lf})
	assert.Equal(t, []byte("ID=alpine"), m.GetContent("osRelease"))
}

func TestMergeLayers_laterLayerWins(t *testing.T) {
	base := extractor.LayerFiles{
		"osRelease": {"/etc/os-release": []byte("ID=base")},
	}
	over := extractor.LayerFiles{
		"osRelease": {"/etc/os-release": []byte("ID=overlay")},
	}
	m := extractor.MergeLayers([]extractor.LayerFiles{base, over})
	assert.Equal(t, []byte("ID=overlay"), m.GetContent("osRelease"))
}

func TestMergeLayers_multiplePaths(t *testing.T) {
	lf := extractor.LayerFiles{
		"osRelease": {
			"/etc/os-release":  []byte("A"),
			"/usr/lib/os-release": []byte("B"),
		},
	}
	m := extractor.MergeLayers([]extractor.LayerFiles{lf})
	paths := m.AllPathContents("osRelease")
	assert.Len(t, paths, 2)
}

func TestMergeLayers_multipleActions(t *testing.T) {
	lf := extractor.LayerFiles{
		"a": {"/a": []byte("aval")},
		"b": {"/b": []byte("bval")},
	}
	m := extractor.MergeLayers([]extractor.LayerFiles{lf})
	assert.Equal(t, []byte("aval"), m.GetContent("a"))
	assert.Equal(t, []byte("bval"), m.GetContent("b"))
}

// ---- MergedLayers methods ---------------------------------------------------

func TestGetContent_missing(t *testing.T) {
	var m extractor.MergedLayers
	assert.Nil(t, m.GetContent("nonexistent"))
}

func TestGetContent_nonBytesValue(t *testing.T) {
	// Callback can store arbitrary interface{}; GetContent should return nil.
	m := extractor.MergedLayers{
		"action": {"/x": "a string, not []byte"},
	}
	assert.Nil(t, m.GetContent("action"))
}

func TestGetContentByPath_hit(t *testing.T) {
	m := extractor.MergedLayers{
		"r": {"/etc/os-release": []byte("ID=alpine")},
	}
	assert.Equal(t, []byte("ID=alpine"), m.GetContentByPath("r", "/etc/os-release"))
}

func TestGetContentByPath_miss(t *testing.T) {
	m := extractor.MergedLayers{
		"r": {"/etc/os-release": []byte("ID=alpine")},
	}
	assert.Nil(t, m.GetContentByPath("r", "/nonexistent"))
	assert.Nil(t, m.GetContentByPath("missing", "/etc/os-release"))
}

func TestAllPathContents_filtersNonBytes(t *testing.T) {
	m := extractor.MergedLayers{
		"r": {
			"/a": []byte("bytes"),
			"/b": 42, // non-bytes
		},
	}
	paths := m.AllPathContents("r")
	assert.Len(t, paths, 1)
	assert.Contains(t, paths, "/a")
}

func TestAllPathContents_emptyAction(t *testing.T) {
	var m extractor.MergedLayers
	paths := m.AllPathContents("missing")
	assert.Empty(t, paths)
}

// ---- integration: ExtractLayer → MergeLayers pipeline ----------------------

func TestExtractThenMerge_roundtrip(t *testing.T) {
	layer1 := makeTar(map[string][]byte{
		"etc/os-release": []byte("ID=base"),
		"usr/bin/sh":     []byte("sh-v1"),
	})
	layer2 := makeTar(map[string][]byte{
		"etc/os-release": []byte("ID=overlay"),
	})

	actions := []extractor.ExtractAction{readAction("files")}

	lf1, err := extractor.ExtractLayer(bytes.NewReader(layer1), actions)
	require.NoError(t, err)
	lf2, err := extractor.ExtractLayer(bytes.NewReader(layer2), actions)
	require.NoError(t, err)

	merged := extractor.MergeLayers([]extractor.LayerFiles{lf1, lf2})
	assert.Equal(t, []byte("ID=overlay"), merged.GetContentByPath("files", "/etc/os-release"))
	assert.Equal(t, []byte("sh-v1"), merged.GetContentByPath("files", "/usr/bin/sh"))
}
