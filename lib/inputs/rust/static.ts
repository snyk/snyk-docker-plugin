import { basename } from "path";

import { ExtractAction } from "../../extractor/types";
import { streamToString } from "../../stream-utils";

const cargoManifestFiles = ["Cargo.lock", "Cargo.toml"];
const deletedCargoAppFiles = cargoManifestFiles.map((file) => ".wh." + file);

// Exclude vendored manifests from the cargo registry cache and rustup toolchain
// source trees. Rust toolchain images ship thousands of these; matching them
// would extract far too much into memory for no application-level signal.
const cargoRegistryPathRegex =
  /[\/\\]\.cargo[\/\\]registry[\/\\]src[\/\\]index\.crates\.io-/;
const rustToolchainPathRegex =
  /[\/\\]rustup[\/\\]toolchains[\/\\][^\/\\]+[\/\\]lib[\/\\]rustlib[\/\\]src[\/\\]/;

function cargoFilePathMatches(filePath: string): boolean {
  const fileName = basename(filePath);
  if (
    cargoManifestFiles.includes(fileName) ||
    deletedCargoAppFiles.includes(fileName)
  ) {
    if (cargoRegistryPathRegex.test(filePath)) {
      return false;
    }
    if (rustToolchainPathRegex.test(filePath)) {
      return false;
    }
    return true;
  }
  return false;
}

export const getCargoAppFileContentAction: ExtractAction = {
  actionName: "cargo-app-files",
  filePathMatches: cargoFilePathMatches,
  callback: streamToString,
};
