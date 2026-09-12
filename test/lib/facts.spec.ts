import { facts } from "../../lib/index";
import { Fact, FactType } from "../../lib/types";
import { readFileSync } from "fs";

const allFactTypes = [
  "autoDetectedUserInstructions",
  "depGraph",
  "dockerfileAnalysis",
  "history",
  "imageCreationTime",
  "imageId",
  "imageLabels",
  "imageLayers",
  "imageManifestFiles",
  "imageNames",
  "imageOsReleasePrettyName",
  "imageSizeBytes",
  "jarFingerprints",
  "keyBinariesHashes",
  "baseRuntimes",
  "loadedPackages",
  "ociDistributionMetadata",
  "provenanceMetadata",
  "containerConfig",
  "platform",
  "pluginVersion",
  "pluginWarnings",
  "rootFs",
  "binaries",
  "dockerLayers",
  "hashes",
  "redHatRepositories",
  "testedFiles",
  "applicationFiles",
  "apkPackageOwnership",
] as const;

type MissingFactTypes = Exclude<FactType, (typeof allFactTypes)[number]>;
const exhaustiveFactTypes: MissingFactTypes extends never ? true : never = true;

function getOpenApiFactTypes(): string[] {
  const commonSchema = readFileSync("components/common.yaml", "utf8");
  const factTypeEnum = commonSchema.match(
    /^ {2}FactType:\n(?: {4}.+\n)*? {4}enum:\n((?: {6}- .+\n)+)/m,
  );

  if (!factTypeEnum) {
    throw new Error("could not find FactType enum in components/common.yaml");
  }

  return factTypeEnum[1]
    .trim()
    .split("\n")
    .map((line) => line.trim().slice(2));
}

describe("Facts", () => {
  it("correctly compiles and exports all the supported facts", () => {
    expect(exhaustiveFactTypes).toBe(true);
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
    const apkPackageOwnershipFact: facts.ApkPackageOwnershipFact = {
      type: "apkPackageOwnership",
      data: {
        distroId: "wolfi",
        ownedPackages: [],
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
      apkPackageOwnershipFact,
    ];
    expect(allFacts).toBeDefined();

    const allFactsTypes: FactType[] = allFacts.map((fact) => fact.type);
    expect(allFactsTypes).toBeDefined();
  });

  it("keeps the OpenAPI fact type enum aligned with exported facts", () => {
    expect(getOpenApiFactTypes()).toEqual(expect.arrayContaining(allFactTypes));
  });
});
