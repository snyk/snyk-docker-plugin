import {
  createGetImageIdFromManifest,
  dockerArchiveConfig,
  getManifestLayers,
} from "../generic-archive-extractor";

export { extractArchive } from "./layer";

export { getManifestLayers };

export const getImageIdFromManifest =
  createGetImageIdFromManifest(dockerArchiveConfig);
