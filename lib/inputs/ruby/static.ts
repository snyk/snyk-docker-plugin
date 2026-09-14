import { basename } from "path";

import { ExtractAction } from "../../extractor/types";
import { streamToString } from "../../stream-utils";

const rubyAppFiles = ["Gemfile", "Gemfile.lock"];
const deletedAppFiles = rubyAppFiles.map((file) => ".wh." + file);

function filePathMatches(filePath: string): boolean {
  const fileName = basename(filePath);
  return rubyAppFiles.includes(fileName) || deletedAppFiles.includes(fileName);
}

export const getRubyAppFileContentAction: ExtractAction = {
  actionName: "ruby-app-files",
  filePathMatches,
  callback: streamToString,
};
