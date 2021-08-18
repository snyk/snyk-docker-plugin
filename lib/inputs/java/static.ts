import * as path from "path";
import { ExtractAction } from "../../extractor/types";
import { streamToBuffer } from "../../stream-utils";

const ignoredPaths = ["/usr/lib", "gradle/cache"];

function filePathMatches(filePath: string): boolean {
  const dirName = path.dirname(filePath);
  return (
    filePath.endsWith(".jar") &&
    !ignoredPaths.some((ignorePath) =>
      dirName.includes(path.normalize(ignorePath)),
    )
  );
}

export const getJarFileContentAction: ExtractAction = {
  actionName: "jar",
  filePathMatches,
  callback: streamToBuffer,
};
