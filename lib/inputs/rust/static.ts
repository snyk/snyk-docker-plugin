import { basename } from "path";
import { ExtractAction } from "../../extractor/types";
import { streamToString } from "../../stream-utils";

const rustAppFiles = ["Cargo.lock", "Cargo.toml"];
// Match .wh.-prefixed names for consistency with sibling inputs (node, php, python).
// Whiteout suppression does not depend on this: lib/extractor/layer.ts records an
// unmatched whiteout entry regardless, and lib/extractor/index.ts strips it.
const deletedRustAppFiles = rustAppFiles.map((file) => ".wh." + file);

// Compiled-binary fingerprinting (the Go analogue) is deliberately deferred:
// standard Rust release binaries carry no equivalent of Go's .go.buildinfo /
// .gopclntab embedded manifest. That would depend on the optional
// cargo-auditable convention and on new binary fixtures.
function filePathMatches(filePath: string): boolean {
  const fileName = basename(filePath);
  if (
    !rustAppFiles.includes(fileName) &&
    !deletedRustAppFiles.includes(fileName)
  ) {
    return false;
  }

  const forwardSlashed = filePath.replace(/\\/g, "/");

  if (forwardSlashed.includes("/.cargo/registry/")) {
    return false;
  }
  if (forwardSlashed.includes("/.cargo/git/checkouts/")) {
    return false;
  }
  if (forwardSlashed.includes("/cargo/registry/")) {
    return false;
  }
  if (forwardSlashed.includes("/rustlib/src/rust/library/")) {
    return false;
  }

  return true;
}

export const getRustAppFileContentAction: ExtractAction = {
  actionName: "rust-app-files",
  filePathMatches,
  callback: streamToString,
};
