import { ExtractAction, ExtractedLayers } from "../../../extractor/types";
import { streamToSha256 } from "../../../stream-utils";

export const getOpenJDKBinariesFileContentAction: ExtractAction = {
  actionName: "java",
  filePathMatches: (filePath) => filePath.endsWith("java"),
  callback: streamToSha256,
};

export const getNodeBinariesFileContentAction: ExtractAction = {
  actionName: "node",
  filePathMatches: (filePath) => filePath.endsWith("node"),
  callback: streamToSha256,
};
// const filePattern = /\/usr(\/.*)?\/bin\/.*$/
// const filePattern = /.*/
export const getAllBinariesFileContentAction: ExtractAction = {
  actionName: "everything",
  filePathMatches: (filePath) => true,
  callback: streamToSha256,
};

const binariesExtractActions = [
  // getNodeBinariesFileContentAction,
  // getOpenJDKBinariesFileContentAction,
  getAllBinariesFileContentAction,
];

export function getBinariesHashes(extractedLayers: ExtractedLayers): string[] {
  const hashes: Set<string> = new Set<string>();

  for (const fileName of Object.keys(extractedLayers)) {
    for (const actionName of Object.keys(extractedLayers[fileName])) {
      for (const action of binariesExtractActions) {
        if (actionName !== action.actionName) {
          continue;
        }

        if (!(typeof extractedLayers[fileName][actionName] === "string")) {
          throw new Error("expected string");
        }
        hashes.add(extractedLayers[fileName][actionName] as string);
      }
    }
  }
  return [...hashes];
}
