import { ExtractedLayers } from "../extractor/types";

export function getFileContent(
  extractedLayers: ExtractedLayers,
  searchedAction: string,
): { [fileName: string]: string } {
  const foundAppFiles = {};

  for (const filePath of Object.keys(extractedLayers)) {
    for (const actionName of Object.keys(extractedLayers[filePath])) {
      if (actionName !== searchedAction) {
        continue;
      }
      if (!(typeof extractedLayers[filePath][actionName] === "string")) {
        throw new Error("expected string");
      }
      foundAppFiles[filePath] = extractedLayers[filePath][actionName];
    }
  }

  return foundAppFiles;
}
