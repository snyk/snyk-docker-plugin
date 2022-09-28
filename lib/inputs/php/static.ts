import { basename } from "path";

import { ExtractAction } from "../../extractor/types";
import { streamToString } from "../../stream-utils";

const phpAppFiles = ["composer.json", "composer.lock"];
const deletedAppFiles = phpAppFiles.map((file) => ".wh." + file);

function filePathMatches(filePath: string): boolean {
  const fileName = basename(filePath);
  return phpAppFiles.includes(fileName) || deletedAppFiles.includes(fileName);
}

export const getPhpAppFileContentAction: ExtractAction = {
  actionName: "php-app-files",
  filePathMatches,
  callback: streamToString,
};
