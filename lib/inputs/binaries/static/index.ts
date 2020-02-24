import { ExtractAction, ExtractedLayers } from "../../../extractor/types";
import { streamToHash } from "../../../stream-utils";

export const getNodeBinariesFileContentAction: ExtractAction = {
  actionName: "node",
  fileNamePattern: "**/node",
  callback: streamToHash,
};

export function getBinariesHashes(extractedLayers: ExtractedLayers): string[] {
  const hashes: Set<string> = new Set<string>();
  for (const fileName of Object.keys(extractedLayers)) {
    for (const actionName of Object.keys(extractedLayers[fileName])) {
      if (actionName !== getNodeBinariesFileContentAction.actionName) {
        continue;
      }
      if (!(typeof extractedLayers[fileName][actionName] === "string")) {
        throw new Error("expected string");
      }
      hashes.add(extractedLayers[fileName][actionName] as string);
    }
  }
  return [...hashes];
}
