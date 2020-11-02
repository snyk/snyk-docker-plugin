import * as path from "path";
import { ExtractAction } from "../../extractor/types";
import { streamToSha1 } from "../../stream-utils";

const ignoredPaths = [path.normalize("/usr/lib")];

function filePathMatches(filePath: string): boolean {
  const dirName = path.dirname(filePath);
  return (
    filePath.endsWith(".jar") &&
    !ignoredPaths.some((ignorePath) => dirName.startsWith(ignorePath))
  );
}

export const getJarFileContentAction: ExtractAction = {
  actionName: "jar",
  filePathMatches,
  callback: streamToSha1,
};
