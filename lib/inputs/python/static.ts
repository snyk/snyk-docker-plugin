import { basename } from "path";

import { ExtractAction } from "../../extractor/types";
import { streamToString } from "../../stream-utils";

const pythonAppFiles = ["pyproject.toml", "poetry.lock"];

function filePathMatches(filePath: string): boolean {
  const fileName = basename(filePath);
  return pythonAppFiles.includes(fileName);
}

export const getPythonAppFileContentAction: ExtractAction = {
  actionName: "python-app-files",
  filePathMatches,
  callback: streamToString,
};
