import { basename } from "path";
import { ExtractAction } from "../../extractor/types";
import { streamToString } from "../../stream-utils";

const nodeManifestFiles = ["package.json", "package-lock.json", "yarn.lock"];
const deletedNodeManifestFiles = nodeManifestFiles.map((file) => ".wh." + file);

export const jsMapExtension = ".js.map";
const jsAndJsMapExtensions = [".js", jsMapExtension];

const nodeJsTsAppFileSuffixes = [
  ...jsAndJsMapExtensions,
  ".ts",
  "package.json",
  "package-lock.json",
];
const excludedNodeJsTsAppFileSuffixes = [".d.ts"];

function filePathMatches(filePath: string): boolean {
  const fileName = basename(filePath);
  return (
    nodeManifestFiles.includes(fileName) ||
    deletedNodeManifestFiles.includes(fileName)
  );
}

export const getNodeAppFileContentAction: ExtractAction = {
  actionName: "node-app-files",
  filePathMatches,
  callback: streamToString,
};

function nodeJsTsAppFilePathMatches(filePath: string): boolean {
  return (
    !filePath.includes("node_modules/") &&
    // "/usr/" should not include 1st party code
    !filePath.startsWith("/usr/") &&
    nodeJsTsAppFileSuffixes.some((suffix) => filePath.endsWith(suffix)) &&
    !excludedNodeJsTsAppFileSuffixes.some((excludedSuffix) =>
      filePath.endsWith(excludedSuffix),
    )
  );
}

export const getNodeJsTsAppFileContentAction: ExtractAction = {
  actionName: "node-js-ts-app-files",
  filePathMatches: nodeJsTsAppFilePathMatches,
  callback: streamToString,
};
