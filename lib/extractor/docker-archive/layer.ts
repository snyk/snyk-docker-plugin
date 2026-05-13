import {
  createExtractArchive,
  dockerArchiveConfig,
} from "../generic-archive-extractor";

export const extractArchive = createExtractArchive(dockerArchiveConfig);
