import { basename } from "path";

import { ExtractAction, ExtractedLayers } from "../../extractor/types";
import { streamToString } from "../../stream-utils";

const nodeAppFiles = ["package.json", "package-lock.json", "yarn.lock"];

function filePathMatches(filePath: string): boolean {
  const fileName = basename(filePath);
  return (
    filePath.indexOf("node_modules") === -1 && nodeAppFiles.includes(fileName)
  );
}

export const getNodeAppFileContentAction: ExtractAction = {
  actionName: "node-app-files",
  filePathMatches,
  callback: streamToString,
};

export function getNodeAppFileContent(
  extractedLayers: ExtractedLayers,
): { [fileName: string]: string } {
  const foundAppFiles = {};

  for (const filePath of Object.keys(extractedLayers)) {
    for (const actionName of Object.keys(extractedLayers[filePath])) {
      if (actionName !== getNodeAppFileContentAction.actionName) {
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
