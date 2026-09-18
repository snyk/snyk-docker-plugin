import { basename } from "path";

import { ExtractAction } from "../../extractor/types";
import { streamToString } from "../../stream-utils";

// Cargo.toml is collected alongside Cargo.lock purely so both live under the
// same "manifest + lock" extraction pattern used by other ecosystems (e.g.
// php's composer.json/composer.lock). Cargo.toml is not required to build a
// dep graph -- only Cargo.lock is parsed by
// `lib/analyzer/applications/rust.ts` -- but keeping the pair mirrors the
// established convention and leaves room for future manifest-only signals
// (e.g. detecting Rust projects that haven't committed a lock file).
const rustAppFiles = ["Cargo.toml", "Cargo.lock"];
const deletedAppFiles = rustAppFiles.map((file) => ".wh." + file);

function filePathMatches(filePath: string): boolean {
  const fileName = basename(filePath);
  return rustAppFiles.includes(fileName) || deletedAppFiles.includes(fileName);
}

export const getRustAppFileContentAction: ExtractAction = {
  actionName: "rust-app-files",
  filePathMatches,
  callback: streamToString,
};
