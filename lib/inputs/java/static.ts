import * as path from "path";
import { ExtractAction } from "../../extractor/types";
import { streamToBuffer } from "../../stream-utils";

const usrLibPath = "/usr/lib";
const ignoredPaths = [usrLibPath, "gradle/cache"];
const javaArchiveFileFormats = [".jar", ".war"];

function filePathMatches(filePath: string): boolean {
  const dirName = path.dirname(filePath);
  const fileExtension = filePath.slice(-4);
  return (
    javaArchiveFileFormats.includes(fileExtension) &&
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

function usrLibFilePathMatches(filePath: string): boolean {
  const dirName = path.dirname(filePath);
  const fileExtension = filePath.slice(-4);
  return (
    javaArchiveFileFormats.includes(fileExtension) &&
    dirName.includes(path.normalize(usrLibPath))
  );
}

export const getUsrLibJarFileContentAction: ExtractAction = {
  actionName: "jar",
  filePathMatches: usrLibFilePathMatches,
  callback: streamToBuffer,
};
