import { basename } from "path";

import * as path from "path";
import { ExtractAction } from "../../extractor/types";
import { streamToString } from "../../stream-utils";

const ignoredPaths = ["/usr", "/bin", "/opt", "C:\\"];
const nodeAppFiles = ["package.json", "package-lock.json", "yarn.lock"];
const deletedAppFiles = nodeAppFiles.map((file) => ".wh." + file);

function filePathMatches(filePath: string): boolean {
  const fileName = basename(filePath);
  const dirName = path.dirname(filePath);

  return (
    !ignoredPaths.some((ignorePath) => dirName.includes(ignorePath)) &&
    (nodeAppFiles.includes(fileName) || deletedAppFiles.includes(fileName))
  );
}

export const getNodeAppFileContentAction: ExtractAction = {
  actionName: "node-app-files",
  filePathMatches,
  callback: streamToString,
};
