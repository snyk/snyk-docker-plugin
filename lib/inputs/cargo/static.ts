import { basename } from "path";

import { ExtractAction } from "../../extractor/types";
import { streamToString } from "../../stream-utils";

export const CARGO_IGNORED_PATH_PATTERNS = [
  ".cargo/registry/",
  ".cargo/git/",
  "vendor/",
] as const;

const CARGO_APP_FILES = ["Cargo.lock", "Cargo.toml"];

function isIgnoredPath(normalizedPath: string): boolean {
  return CARGO_IGNORED_PATH_PATTERNS.some((pattern) =>
    normalizedPath.includes(pattern),
  );
}

function filePathMatches(filePath: string): boolean {
  const normalizedPath = filePath.replace(/\\/g, "/");
  const fileName = basename(normalizedPath);

  if (fileName.startsWith(".wh.")) {
    return false;
  }

  if (isIgnoredPath(normalizedPath)) {
    return false;
  }

  return CARGO_APP_FILES.includes(fileName);
}

export const getCargoAppFileContentAction: ExtractAction = {
  actionName: "cargo-app-files",
  filePathMatches,
  callback: streamToString,
};
