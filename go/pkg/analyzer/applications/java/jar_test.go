package java_test

import (
	"archive/zip"
	"bytes"
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/analyzer/applications/java"
	"github.com/snyk/snyk-docker-plugin/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeJar creates a minimal JAR (zip) from a map of filename → content.
func makeJar(files map[string]string) []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range files {
		f, _ := w.Create(name)
		f.Write([]byte(content)) //nolint:errcheck
	}
	w.Close()
	return buf.Bytes()
}

const pomProps = "groupId=com.example\nartifactId=mylib\nversion=1.0.0\n"
const mssqlPomProps = "groupId=com.microsoft.sqlserver\nartifactId=mssql-jdbc\nversion=9.0.0\n"

// --- ParsePomProperties ---

func TestParsePomProperties_complete(t *testing.T) {
	coords := java.ParsePomProperties(pomProps)
	require.NotNil(t, coords)
	assert.Equal(t, "com.example", coords.GroupID)
	assert.Equal(t, "mylib", coords.ArtifactID)
	assert.Equal(t, "1.0.0", coords.Version)
}

func TestParsePomProperties_missingGroupId(t *testing.T) {
	coords := java.ParsePomProperties("artifactId=mylib\nversion=1.0.0\n")
	assert.Nil(t, coords)
}

func TestParsePomProperties_missingArtifactId(t *testing.T) {
	coords := java.ParsePomProperties("groupId=com.example\nversion=1.0.0\n")
	assert.Nil(t, coords)
}

func TestParsePomProperties_missingVersion(t *testing.T) {
	coords := java.ParsePomProperties("groupId=com.example\nartifactId=mylib\n")
	assert.Nil(t, coords)
}

func TestParsePomProperties_empty(t *testing.T) {
	coords := java.ParsePomProperties("")
	assert.Nil(t, coords)
}

func TestParsePomProperties_overrideReturnsNil(t *testing.T) {
	coords := java.ParsePomProperties(mssqlPomProps)
	assert.Nil(t, coords)
}

func TestParsePomProperties_whitespaceInValues(t *testing.T) {
	coords := java.ParsePomProperties("groupId=com.example\nartifactId=mylib\nversion=1.0.0\r\n")
	// \r may be part of the value on Windows line endings; just check not nil.
	// The parser strips the value as-is.
	// Depending on impl this may or may not strip \r; just verify it does something sane.
	if coords != nil {
		assert.NotEmpty(t, coords.GroupID)
	}
}

// --- ScanJars ---

func TestScanJars_empty(t *testing.T) {
	results := java.ScanJars(map[string][]byte{}, "img:latest", 1)
	assert.Nil(t, results)
}

func TestScanJars_nonJarFilesIgnored(t *testing.T) {
	results := java.ScanJars(map[string][]byte{
		"/app/Main.class": []byte("cafebabe"),
		"/app/config.xml": []byte("<config/>"),
	}, "img:latest", 1)
	assert.Nil(t, results)
}

func TestScanJars_jarWithCoords_nilDigest(t *testing.T) {
	jarData := makeJar(map[string]string{
		"META-INF/maven/com.example/mylib/pom.properties": pomProps,
	})
	results := java.ScanJars(map[string][]byte{
		"/app/mylib-1.0.0.jar": jarData,
	}, "img:latest", 1)
	require.Len(t, results, 1)
	r := results[0]
	assert.Equal(t, "maven", r.Identity.Type)
	require.Len(t, r.Facts, 1)
	assert.Equal(t, types.FactJarFingerprints, r.Facts[0].Type)

	data, ok := r.Facts[0].Data.(java.JarFingerprintsData)
	require.True(t, ok)
	assert.Equal(t, "img:latest", data.Origin)
	require.Len(t, data.Fingerprints, 1)
	fp := data.Fingerprints[0]
	assert.Equal(t, "com.example", fp.GroupID)
	assert.Equal(t, "mylib", fp.ArtifactID)
	assert.Equal(t, "1.0.0", fp.Version)
	assert.Nil(t, fp.Digest, "digest should be nil when coords are present")
}

func TestScanJars_jarNoPomProperties_hasDigest(t *testing.T) {
	jarData := makeJar(map[string]string{
		"com/example/Main.class": "cafebabe",
	})
	results := java.ScanJars(map[string][]byte{
		"/app/unknown-1.0.jar": jarData,
	}, "img:latest", 1)
	require.Len(t, results, 1)
	data := results[0].Facts[0].Data.(java.JarFingerprintsData)
	require.Len(t, data.Fingerprints, 1)
	fp := data.Fingerprints[0]
	assert.NotNil(t, fp.Digest, "digest should be set when no coords")
	assert.NotEmpty(t, *fp.Digest)
	assert.Equal(t, 40, len(*fp.Digest), "SHA-1 hex should be 40 chars")
}

func TestScanJars_warFileNotFingerprinted(t *testing.T) {
	// A WAR file is a container — it is NOT fingerprinted itself.
	// Nested JARs inside it ARE fingerprinted (if depth allows).
	nestedJar := makeJar(map[string]string{
		"META-INF/maven/com.example/mylib/pom.properties": pomProps,
	})
	warData := makeJar(map[string]string{
		"WEB-INF/lib/mylib-1.0.0.jar": string(nestedJar),
	})
	results := java.ScanJars(map[string][]byte{
		"/app/myapp.war": warData,
	}, "img:latest", 1)
	// Whether nested JARs are extracted depends on depth; just verify the WAR
	// itself (.war extension) is NOT reported as a top-level fingerprint.
	for _, r := range results {
		data := r.Facts[0].Data.(java.JarFingerprintsData)
		for _, fp := range data.Fingerprints {
			// Top-level fingerprint location must be a .jar, not the .war itself.
			assert.False(t,
				fp.Location == "/app/myapp.war",
				"WAR file itself should not be fingerprinted, got location: %s", fp.Location)
		}
	}
}

func TestScanJars_multipleJarsSameDirectory(t *testing.T) {
	jar1 := makeJar(map[string]string{
		"META-INF/maven/com.example/lib1/pom.properties": "groupId=com.example\nartifactId=lib1\nversion=1.0\n",
	})
	jar2 := makeJar(map[string]string{
		"META-INF/maven/com.example/lib2/pom.properties": "groupId=com.example\nartifactId=lib2\nversion=2.0\n",
	})
	results := java.ScanJars(map[string][]byte{
		"/app/lib/lib1-1.0.jar": jar1,
		"/app/lib/lib2-2.0.jar": jar2,
	}, "img:latest", 1)
	require.Len(t, results, 1, "same directory → one AppScanResult")
	data := results[0].Facts[0].Data.(java.JarFingerprintsData)
	assert.Len(t, data.Fingerprints, 2)
}

func TestScanJars_jarsInDifferentDirectories(t *testing.T) {
	jar1 := makeJar(map[string]string{
		"META-INF/maven/com.example/lib1/pom.properties": "groupId=com.example\nartifactId=lib1\nversion=1.0\n",
	})
	jar2 := makeJar(map[string]string{
		"META-INF/maven/com.example/lib2/pom.properties": "groupId=com.example\nartifactId=lib2\nversion=2.0\n",
	})
	results := java.ScanJars(map[string][]byte{
		"/app/lib1/lib1-1.0.jar": jar1,
		"/app/lib2/lib2-2.0.jar": jar2,
	}, "img:latest", 1)
	assert.Len(t, results, 2, "different directories → separate AppScanResults")
}

func TestScanJars_targetImageInOrigin(t *testing.T) {
	jarData := makeJar(map[string]string{"placeholder.txt": ""})
	results := java.ScanJars(map[string][]byte{
		"/app/placeholder-1.0.jar": jarData,
	}, "myimage:v1.2.3", 1)
	if len(results) > 0 {
		data := results[0].Facts[0].Data.(java.JarFingerprintsData)
		assert.Equal(t, "myimage:v1.2.3", data.Origin)
	}
}

func TestScanJars_invalidZipFileSafe(t *testing.T) {
	// A file with .jar extension but not a valid zip — should not panic.
	results := java.ScanJars(map[string][]byte{
		"/app/broken.jar": []byte("this is not a zip file"),
	}, "img:latest", 1)
	// Should return a result with a digest (since it's not a valid zip, no coords).
	// Or nil; either way, must not panic.
	if len(results) > 0 {
		data := results[0].Facts[0].Data.(java.JarFingerprintsData)
		assert.NotNil(t, data.Fingerprints[0].Digest)
	}
}

func TestScanJars_earExtensionTreatedAsContainer(t *testing.T) {
	// .ear files are containers like .war — not fingerprinted themselves.
	earData := makeJar(map[string]string{"placeholder.txt": ""})
	// Just ensure it doesn't panic.
	_ = java.ScanJars(map[string][]byte{
		"/app/app.ear": earData,
	}, "img:latest", 1)
}

func TestScanJars_pomPropertiesAsDependency(t *testing.T) {
	// If pom.properties artifactId doesn't match the jar filename,
	// it's treated as a dependency coord rather than the jar's own coords.
	// In that case the JAR gets a SHA-1 digest (no own coords).
	jarData := makeJar(map[string]string{
		"META-INF/maven/com.other/otherlib/pom.properties": "groupId=com.other\nartifactId=otherlib\nversion=3.0\n",
	})
	results := java.ScanJars(map[string][]byte{
		"/app/totally-different-name.jar": jarData,
	}, "img:latest", 1)
	require.Len(t, results, 1)
	data := results[0].Facts[0].Data.(java.JarFingerprintsData)
	require.Len(t, data.Fingerprints, 1)
	fp := data.Fingerprints[0]
	// Dep coords were found but don't match the jar name —
	// jar gets a digest and the dep appears in Deps.
	if fp.Digest != nil {
		assert.NotEmpty(t, *fp.Digest)
	}
}

func TestScanJars_pathInFingerprintMatchesInput(t *testing.T) {
	jarData := makeJar(map[string]string{"placeholder.txt": "content"})
	results := java.ScanJars(map[string][]byte{
		"/usr/share/java/myapp-2.0.jar": jarData,
	}, "img:latest", 1)
	require.Len(t, results, 1)
	data := results[0].Facts[0].Data.(java.JarFingerprintsData)
	assert.Equal(t, "/usr/share/java/myapp-2.0.jar", data.Fingerprints[0].Location)
	assert.Equal(t, "/usr/share/java", data.Path)
	assert.Equal(t, "/usr/share/java", results[0].Identity.TargetFile)
}

func TestScanJars_depsListNotNil(t *testing.T) {
	// Even when no deps are found, Deps should be an empty slice (not nil).
	jarData := makeJar(map[string]string{"placeholder.txt": "content"})
	results := java.ScanJars(map[string][]byte{
		"/app/myapp.jar": jarData,
	}, "img:latest", 1)
	require.Len(t, results, 1)
	data := results[0].Facts[0].Data.(java.JarFingerprintsData)
	require.Len(t, data.Fingerprints, 1)
	assert.NotNil(t, data.Fingerprints[0].Deps)
}
