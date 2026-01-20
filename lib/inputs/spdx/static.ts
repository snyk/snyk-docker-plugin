import { normalize as normalizePath } from "path";
import { ExtractAction, ExtractedLayers } from "../../extractor/types";
import { streamToString } from "../../stream-utils";

export const getSpdxFileContentAction: ExtractAction = {
  actionName: "spdx-files",
  filePathMatches: (filePath) => {
    const normalized = normalizePath(filePath);
    return normalized.includes("/docker/sbom/") && 
           normalized.includes("spdx.") &&
           normalized.endsWith(".json");
  },
  callback: streamToString,
};

export function getSpdxFileContents(extractedLayers: ExtractedLayers): string[] {
  const files: string[] = [];

  for (const fileName of Object.keys(extractedLayers)) {
    if (!("spdx-files" in extractedLayers[fileName])) {
      continue;
    }
    
    const content = extractedLayers[fileName]["spdx-files"];
    if (typeof content === "string") {
      files.push(content);
    }
  }

  return files;
}

