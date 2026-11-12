import { basename } from "path";

import { ExtractAction } from "../../extractor/types";
import { streamToString } from "../../stream-utils";

const rustAppFiles = ["Cargo.lock"];
const deletedAppFiles = rustAppFiles.map((file) => ".wh." + file);

const excludedPathSubstrings = [
  // Registry cache: anchored on ".cargo/registry/" (the default CARGO_HOME
  // layout); CARGO_HOME roots like "/usr/local/cargo/registry/src/..." are
  // still caught below by "/registry/src/".
  ".cargo/registry/",
  // Git checkouts: anchored on "cargo/git/" (no leading dot) so this matches
  // both "~/.cargo/git/checkouts/..." and CARGO_HOME roots such as
  // "/usr/local/cargo/git/checkouts/...", which the official rust images use.
  "cargo/git/",
  // Extracted registry sources regardless of CARGO_HOME prefix.
  "/registry/src/",
  // "cargo package"/"cargo publish" staging output.
  "/target/package/",
  // "cargo vendor" output: anchored on the "/vendor/" directory segment
  // rather than a CARGO_HOME prefix, since vendored crates are checked into
  // the app tree. An app lockfile at ".../vendor/Cargo.lock" itself would
  // not match since the exclusion requires a trailing "/vendor/<crate>/...".
  "/vendor/",
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
