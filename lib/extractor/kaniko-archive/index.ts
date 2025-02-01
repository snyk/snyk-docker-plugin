import { normalize as normalizePath } from "path";
import { HashAlgorithm } from "../../types";

import { KanikoArchiveManifest } from "../types";
export { extractArchive } from "./layer";

export function getManifestLayers(manifest: KanikoArchiveManifest) {
  return manifest.Layers.map((layer) => normalizePath(layer));
}

export function getImageIdFromManifest(
  manifest: KanikoArchiveManifest,
): string {
  try {
    const imageId = manifest.Config;
    if (imageId.includes(":")) {
      // imageId includes the algorithm prefix
      return imageId;
    }
    return `${HashAlgorithm.Sha256}:${imageId}`;
  } catch (err) {
    throw new Error("Failed to extract image ID from archive manifest");
  }
}
