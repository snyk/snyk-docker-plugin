import { facts } from "../../lib/index";
import { Fact, FactType } from "../../lib/types";

describe("Facts", () => {
  it("correctly compiles and exports all the supported facts", () => {
    const depGraphFact: facts.DepGraphFact = {
      type: "depGraph",
      data: {} as any,
    };
    const dockerfileAnalysisFact: facts.DockerfileAnalysisFact = {
      type: "dockerfileAnalysis",
      data: {} as any,
    };
    const imageIdFact: facts.ImageIdFact = {
      type: "imageId",
      data: "",
    };
    const imageLayersFact: facts.ImageLayersFact = {
      type: "imageLayers",
      data: [],
    };
    const imageManifestFilesFact: facts.ImageManifestFilesFact = {
      type: "imageManifestFiles",
      data: [],
    };
    const imageOsReleasePrettyNameFact: facts.ImageOsReleasePrettyNameFact = {
      type: "imageOsReleasePrettyName",
      data: "",
    };
    const jarFingerprintsFact: facts.JarFingerprintsFact = {
      type: "jarFingerprints",
      data: {} as any,
    };
    const keyBinariesHashesFact: facts.KeyBinariesHashesFact = {
      type: "keyBinariesHashes",
      data: [],
    };
    const rootFsFact: facts.RootFsFact = {
      type: "rootFs",
      data: [],
    };
    const testedFilesFact: facts.TestedFilesFact = {
      type: "testedFiles",
      data: [],
    };
    const applicationFilesFact: facts.ApplicationFilesFact = {
      type: "applicationFiles",
      data: [],
    };
    const autoDetectedUserInstructionsFact: facts.AutoDetectedUserInstructionsFact =
      {
        type: "autoDetectedUserInstructions",
        data: {} as any,
      };
    const loadedPackagesFact: facts.LoadedPackagesFact = {
      type: "loadedPackages",
      data: {} as any,
    };
    const imageCreationTimeFact: facts.ImageCreationTimeFact = {
      type: "imageCreationTime",
      data: "",
    };
    const imageNamesFact: facts.ImageNamesFact = {
      type: "imageNames",
      data: {} as any,
    };
    const imageLabels: facts.ImageLabels = {
      type: "imageLabels",
      data: {},
    };
    const imageSizeBytesFact: facts.ImageSizeBytesFact = {
      type: "imageSizeBytes",
      data: 0,
    };
    const ociDistributionMetadataFact: facts.OCIDistributionMetadataFact = {
      type: "ociDistributionMetadata",
      data: {} as any,
    };
    const platformFact: facts.PlatformFact = {
      type: "platform",
      data: "",
    };
    const pluginVersionFact: facts.PluginVersionFact = {
      type: "pluginVersion",
      data: "",
    };
    const containerConfigFact: facts.ContainerConfigFact = {
      type: "containerConfig",
      data: {},
    };
    const historyFact: facts.HistoryFact = {
      type: "history",
      data: [],
    };
    const pluginWarningsFact: facts.PluginWarningsFact = {
      type: "pluginWarnings",
      data: {
        truncatedFacts: {},
      },
    };

    // This would catch compilation errors.
    const allFacts: Fact[] = [
      depGraphFact,
      dockerfileAnalysisFact,
      imageIdFact,
      imageLayersFact,
      imageManifestFilesFact,
      imageOsReleasePrettyNameFact,
      jarFingerprintsFact,
      keyBinariesHashesFact,
      rootFsFact,
      testedFilesFact,
      applicationFilesFact,
      autoDetectedUserInstructionsFact,
      imageCreationTimeFact,
      loadedPackagesFact,
      imageNamesFact,
      imageLabels,
      imageSizeBytesFact,
      ociDistributionMetadataFact,
      platformFact,
      pluginVersionFact,
      containerConfigFact,
      historyFact,
      pluginWarningsFact,
    ];
    expect(allFacts).toBeDefined();

    const allFactsTypes: FactType[] = allFacts.map((fact) => fact.type);
    expect(allFactsTypes).toBeDefined();
  });
});
