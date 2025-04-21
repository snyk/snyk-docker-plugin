import * as path from "path";
import { ExtractAction } from "../../extractor/types";
import { streamToBuffer, streamToSha1 } from "../../stream-utils";

const ignoredPaths = ["/usr/lib", "gradle/cache", ".m2"];
const javaArchiveFileFormats = [".jar", ".war"];
const javaClassFileFormats = [".class"];

function jarFilePathMatches(filePath: string): boolean {
  const dirName = path.dirname(filePath);
  const fileExtension = filePath.slice(filePath.lastIndexOf("."));
  return (
    javaArchiveFileFormats.includes(fileExtension) &&
    !ignoredPaths.some((ignorePath) =>
      dirName.includes(path.normalize(ignorePath)),
    )
  );
}

export const getJarFileContentAction: ExtractAction = {
  actionName: "jar",
  filePathMatches: jarFilePathMatches,
  callback: streamToBuffer,
};

function classFilePathMatches(filePath: string): boolean {
  const dirName = path.dirname(filePath);
  const fileExtension = filePath.slice(filePath.lastIndexOf("."));
  return (
    javaClassFileFormats.includes(fileExtension) &&
    !ignoredPaths.some((ignorePath) =>
      dirName.includes(path.normalize(ignorePath)),
    )
  );
}

export const getClassFileContentAction: ExtractAction = {
  actionName: "class",
  filePathMatches: classFilePathMatches,
  callback: streamToSha1,
};
