import { basename } from "path";
import { ExtractAction } from "../../extractor/types";
import { streamToString } from "../../stream-utils";

const nodeAppFilePatterns = [
  "package.json",
  "package-lock.json",
  "yarn.lock",
  /\.js$/,
  /^(?!.*\.d\.ts$).*\.ts$/,
];
const deletedAppFiles = [
  ".wh.package.json",
  ".wh.package-lock.json",
  ".wh.yarn.lock",
];

function filePathMatches(filePath: string): boolean {
  const fileName = basename(filePath);
  return (
    nodeAppFilePatterns.some((pattern) => new RegExp(pattern).test(fileName)) ||
    deletedAppFiles.some((pattern) => new RegExp(pattern).test(fileName))
  );
}

export const getNodeAppFileContentAction: ExtractAction = {
  actionName: "node-app-files",
  filePathMatches,
  callback: streamToString,
};
