import * as fs from "fs";
import * as path from "path";

import { facts } from "../../lib/index";
import { Fact, FactType } from "../../lib/types";

const publicFactTypes = [
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
  "testedFiles",
  "applicationFiles",
  "apkPackageOwnership",
] as const satisfies readonly FactType[];

type MissingPublicFactTypes = Exclude<
  FactType,
  (typeof publicFactTypes)[number]
>;
const allPublicFactTypesAreListed: MissingPublicFactTypes extends never
  ? true
  : MissingPublicFactTypes = true;

function getFactTypesFromCommonSchema(): string[] {
  const commonSchema = fs.readFileSync(
    path.join(__dirname, "../../components/common.yaml"),
    "utf8",
  );
  const factTypeBlock = commonSchema.match(
    /  FactType:\n(?:    .+\n)*    enum:\n((?:      - .+\n)+)/,
  );

  if (!factTypeBlock) {
    throw new Error("FactType enum not found in components/common.yaml");
  }

  return factTypeBlock[1]
    .trim()
    .split("\n")
    .map((line) => line.trim().replace("- ", ""));
}

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
    const baseRuntimesFact: facts.BaseRuntimesFact = {
      type: "baseRuntimes",
      data: [],
    };
    const provenanceMetadataFact: facts.ProvenanceMetadataFact = {
      type: "provenanceMetadata",
      data: [],
    };
    const apkPackageOwnershipFact: facts.ApkPackageOwnershipFact = {
      type: "apkPackageOwnership",
      data: {},
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
      baseRuntimesFact,
      provenanceMetadataFact,
      apkPackageOwnershipFact,
    ];
    expect(allFacts).toBeDefined();

    const allFactsTypes: FactType[] = allFacts.map((fact) => fact.type);
    expect(allFactsTypes).toBeDefined();
    expect(allPublicFactTypesAreListed).toBe(true);
  });

  it("lists all public fact types in the shared OpenAPI schema", () => {
    const commonSchemaFactTypes = getFactTypesFromCommonSchema();

    expect(commonSchemaFactTypes).toEqual(
      expect.arrayContaining(publicFactTypes),
    );
  });
});
