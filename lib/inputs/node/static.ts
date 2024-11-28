import { basename } from "path";
import { ExtractAction } from "../../extractor/types";
import { streamToString } from "../../stream-utils";

const nodeAppFilePatterns = [
  /^package\.json$/,
  /^package-lock\.json$/,
  /^yarn\.lock$/,
  /\.js$/,
  /^(?!.*\.d\.ts$).*\.ts$/,
];
const deletedAppFiles = nodeAppFilePatterns.map((file) => ".wh." + file);

function filePathMatches(filePath: string): boolean {
  const fileName = basename(filePath);
  return nodeAppFilePatterns.some(
    (pattern) =>
      new RegExp(pattern).test(fileName) || deletedAppFiles.includes(fileName),
  );
}

export const getNodeAppFileContentAction: ExtractAction = {
  actionName: "node-app-files",
  filePathMatches,
  callback: streamToString,
};
