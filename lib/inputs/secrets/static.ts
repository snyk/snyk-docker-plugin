import * as path from "path";

import { ExtractAction } from "../../extractor/types";
import { streamToString } from "../../stream-utils";

// const nodeAppFiles = ["angularjs-crypto.js"];
const ignoredPaths = [path.normalize("/usr/lib")];

function filePathMatches(filePath: string): boolean {
  // const fileName = path.basename(filePath);
  const dirName = path.dirname(filePath);
  return (
    filePath.endsWith(".js") &&
    !ignoredPaths.some((ignorePath) => dirName.startsWith(ignorePath)) &&
    !filePath.endsWith("/index.js")
  );
}

export const getSecretsContentAction: ExtractAction = {
  actionName: "secrets",
  filePathMatches,
  callback: streamToString,
};
