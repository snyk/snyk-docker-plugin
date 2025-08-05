import { normalize as normalizePath } from "path";
import { ExtractAction, ExtractedLayers } from "../../extractor/types";
import { streamToString } from "../../stream-utils";

/**
 * Matches common SBOM file patterns
 */
function sbomFilePathMatches(filePath: string): boolean {
  const normalizedPath = normalizePath(filePath).toLowerCase();

  return (
    // SPDX formats
    normalizedPath.endsWith(".spdx") ||
    normalizedPath.endsWith(".spdx.json") ||
    normalizedPath.endsWith(".spdx.xml") ||
    normalizedPath.endsWith(".spdx.rdf") ||
    normalizedPath.endsWith(".spdx.yaml") ||
    normalizedPath.endsWith(".spdx.yml") ||
    // CycloneDX formats
    normalizedPath.endsWith(".cyclonedx.json") ||
    normalizedPath.endsWith(".cyclonedx.xml") ||
    // Generic SBOM patterns
    normalizedPath.includes("sbom.json") ||
    normalizedPath.includes("sbom.xml") ||
    normalizedPath.includes("bom.json") ||
    normalizedPath.includes("bom.xml") ||
    normalizedPath.includes("software-bill-of-materials") ||
    // Common locations
    normalizedPath.includes("/opt/sbom/") ||
    normalizedPath.includes("/usr/share/sbom/") ||
    normalizedPath.includes("/etc/sbom/") ||
    normalizedPath.includes("/.sbom/") ||
    // Distroless/Google patterns
    (normalizedPath.includes("/var/lib/dpkg/info/") &&
      normalizedPath.includes("sbom"))
  );
}

export const getSBOMFileContentAction: ExtractAction = {
  actionName: "sbom-files",
  filePathMatches: sbomFilePathMatches,
  callback: streamToString,
};

export function getSBOMFileContent(extractedLayers: ExtractedLayers): {
  [filePath: string]: string;
} {
  const sbomFiles: { [filePath: string]: string } = {};

  for (const filePath of Object.keys(extractedLayers)) {
    const actionContent = extractedLayers[filePath]["sbom-files"];
    if (actionContent && typeof actionContent === "string") {
      sbomFiles[filePath] = actionContent;
    }
  }

  return sbomFiles;
}
