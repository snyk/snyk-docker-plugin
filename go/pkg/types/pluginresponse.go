package types

// PluginResponse is the top-level response returned by Scan().
// The first ScanResult is always the OS dependencies scan result.
type PluginResponse struct {
	ScanResults []ScanResult    `json:"scanResults"`
	Analytics   []PluginAnalytics `json:"analytics,omitempty"`
}

type PluginAnalytics struct {
	Name string      `json:"name"`
	Data interface{} `json:"data"`
}

type ScanResult struct {
	Name            string          `json:"name,omitempty"`
	Policy          string          `json:"policy,omitempty"`
	Target          ContainerTarget `json:"target"`
	Identity        Identity        `json:"identity"`
	Facts           []Fact          `json:"facts"`
	TargetReference string          `json:"targetReference,omitempty"`
}

type ContainerTarget struct {
	Image string `json:"image"`
}

type Identity struct {
	Type       string            `json:"type"`
	TargetFile string            `json:"targetFile,omitempty"`
	Args       map[string]string `json:"args,omitempty"`
}

type Fact struct {
	Type FactType    `json:"type"`
	Data interface{} `json:"data"`
}

// FactType enumerates the known fact types (mirrors lib/types.ts FactType union).
type FactType string

const (
	FactAutoDetectedUserInstructions FactType = "autoDetectedUserInstructions"
	FactDepGraph                     FactType = "depGraph"
	FactDockerfileAnalysis           FactType = "dockerfileAnalysis"
	FactHistory                      FactType = "history"
	FactImageCreationTime            FactType = "imageCreationTime"
	FactImageID                      FactType = "imageId"
	FactImageLabels                  FactType = "imageLabels"
	FactImageLayers                  FactType = "imageLayers"
	FactImageManifestFiles           FactType = "imageManifestFiles"
	FactImageNames                   FactType = "imageNames"
	FactImageOsReleasePrettyName     FactType = "imageOsReleasePrettyName"
	FactImageSizeBytes               FactType = "imageSizeBytes"
	FactJarFingerprints              FactType = "jarFingerprints"
	FactKeyBinariesHashes            FactType = "keyBinariesHashes"
	FactBaseRuntimes                 FactType = "baseRuntimes"
	FactLoadedPackages               FactType = "loadedPackages"
	FactOCIDistributionMetadata      FactType = "ociDistributionMetadata"
	FactContainerConfig              FactType = "containerConfig"
	FactPlatform                     FactType = "platform"
	FactPluginVersion                FactType = "pluginVersion"
	FactPluginWarnings               FactType = "pluginWarnings"
	FactRootFs                       FactType = "rootFs"
	FactTestedFiles                  FactType = "testedFiles"
	FactApplicationFiles             FactType = "applicationFiles"
)
