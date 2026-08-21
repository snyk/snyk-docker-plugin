import { basename } from "path";

import { ExtractAction } from "../../extractor/types";
import { streamToString } from "../../stream-utils";

const swiftAppFiles = ["Package.resolved"];
const deletedAppFiles = swiftAppFiles.map((file) => ".wh." + file);

function filePathMatches(filePath: string): boolean {
  if (filePath.includes("/.build/checkouts/")) {
    return false;
  }
  const fileName = basename(filePath);
  return swiftAppFiles.includes(fileName) || deletedAppFiles.includes(fileName);
}

export const getSwiftAppFileContentAction: ExtractAction = {
  actionName: "swift-app-files",
  filePathMatches,
  callback: streamToString,
};
