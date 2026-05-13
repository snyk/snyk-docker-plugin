import {
  createGetImageIdFromManifest,
  getManifestLayers,
  kanikoArchiveConfig,
} from "../generic-archive-extractor";

export { extractArchive } from "./layer";

export { getManifestLayers };

export const getImageIdFromManifest =
  createGetImageIdFromManifest(kanikoArchiveConfig);
