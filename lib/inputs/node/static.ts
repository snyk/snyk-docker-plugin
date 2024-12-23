import { basename } from "path";
import { ExtractAction } from "../../extractor/types";
import { streamToString } from "../../stream-utils";

const nodeAppFiles = ["package.json", "package-lock.json", "yarn.lock"];
const deletedAppFiles = nodeAppFiles.map((file) => ".wh." + file);

const nodeJsTsAppFileSuffixes = [
  ".js",
  ".ts",
  "package.json",
  "package-lock.json",
];
const excludedNodeJsTsAppFileSuffixes = [".d.ts"];

function filePathMatches(filePath: string): boolean {
  const fileName = basename(filePath);
  return nodeAppFiles.includes(fileName) || deletedAppFiles.includes(fileName);
}

export const getNodeAppFileContentAction: ExtractAction = {
  actionName: "node-app-files",
  filePathMatches,
  callback: streamToString,
};

function nodeJsTsAppFilePathMatches(filePath: string): boolean {
  return (
    !filePath.includes("node_modules/") &&
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
