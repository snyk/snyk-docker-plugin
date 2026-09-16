import { basename } from "path";

import { ExtractAction } from "../../extractor/types";
import { streamToString } from "../../stream-utils";

const rustAppFiles = ["Cargo.lock"];
const deletedAppFiles = rustAppFiles.map((file) => ".wh." + file);

const excludedPathSubstrings = [
  ".cargo/registry/",
  ".cargo/git/",
  "/registry/src/",
  "/target/package/",
];

function filePathMatches(filePath: string): boolean {
  const normalizedPath = filePath.replace(/\\/g, "/");

  if (
    excludedPathSubstrings.some((substring) =>
      normalizedPath.includes(substring),
    )
  ) {
    return false;
  }

  const fileName = basename(normalizedPath);
  return rustAppFiles.includes(fileName) || deletedAppFiles.includes(fileName);
}

export const getRustAppFileContentAction: ExtractAction = {
  actionName: "rust-app-files",
  filePathMatches,
  callback: streamToString,
};
