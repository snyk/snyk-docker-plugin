import { normalize as normalizePath } from "path";
import { DockerArchiveManifest } from "../types";

export { extractArchive } from "./layer";

export function getManifestLayers(manifest: DockerArchiveManifest) {
  return manifest.Layers.map((layer) => normalizePath(layer));
}

export function getImageIdFromManifest(
  manifest: DockerArchiveManifest,
): string {
  try {
    return manifest.Config.split(".")[0];
  } catch (err) {
    throw new Error("Failed to extract image ID from archive manifest");
  }
}
