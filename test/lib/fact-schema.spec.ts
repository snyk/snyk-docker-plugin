import { readFileSync } from "fs";

import { FactType } from "../../lib/types";

const expectedFactTypes = {
  apkPackageOwnership: true,
  applicationFiles: true,
  autoDetectedUserInstructions: true,
  baseRuntimes: true,
  binaries: true,
  containerConfig: true,
  depGraph: true,
  dockerfileAnalysis: true,
  dockerLayers: true,
  hashes: true,
  history: true,
  imageCreationTime: true,
  imageId: true,
  imageLabels: true,
  imageLayers: true,
  imageManifestFiles: true,
  imageNames: true,
  imageOsReleasePrettyName: true,
  imageSizeBytes: true,
  jarFingerprints: true,
  keyBinariesHashes: true,
  loadedPackages: true,
  ociDistributionMetadata: true,
  platform: true,
  pluginVersion: true,
  pluginWarnings: true,
  provenanceMetadata: true,
  redHatRepositories: true,
  rootFs: true,
  testedFiles: true,
  workloadMetadata: true,
} satisfies Record<FactType, true>;

describe("common OpenAPI schema", () => {
  it("keeps the FactType enum aligned with exported TypeScript types", () => {
    const schema = readFileSync("components/common.yaml", "utf8");

    expect(extractFactTypeEnum(schema)).toEqual(
      Object.keys(expectedFactTypes).sort(),
    );
  });
});

function extractFactTypeEnum(schema: string): string[] {
  const lines = schema.split("\n");
  const factTypeIndex = lines.findIndex((line) => line === "  FactType:");
  expect(factTypeIndex).toBeGreaterThanOrEqual(0);

  const enumIndex = lines.findIndex(
    (line, index) => index > factTypeIndex && line === "    enum:",
  );
  expect(enumIndex).toBeGreaterThanOrEqual(0);

  const factTypes: string[] = [];
  for (const line of lines.slice(enumIndex + 1)) {
    const enumValue = line.match(/^ {6}- (.+)$/);
    if (enumValue) {
      factTypes.push(enumValue[1]);
      continue;
    }

    if (factTypes.length > 0) {
      break;
    }
  }

  return factTypes.sort();
}
