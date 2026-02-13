import * as Debug from "debug";
import { createReadStream } from "fs";
import { normalize as normalizePath, sep as pathSeparator } from "path";
import { Readable } from "stream";
import { extract, Extract } from "tar-stream";
import { getPlatformFromConfig, InvalidArchiveError } from "..";
import { streamToJson } from "../../stream-utils";
import { PluginOptions } from "../../types";
import { decompressMaybe } from "../decompress-maybe";
import { extractImageLayer } from "../layer";
import {
  ExtractAction,
  ExtractedLayers,
  ExtractedLayersAndManifest,
  ImageConfig,
  OciArchiveManifest,
  OciImageIndex,
  OciManifestInfo,
  OciPlatformInfo,
} from "../types";

const debug = Debug("snyk");
const MEDIATYPE_DOCKER_MANIFEST_V2 =
  "application/vnd.docker.distribution.manifest.v2+json";
const MEDIATYPE_DOCKER_MANIFEST_LIST_V2 =
  "application/vnd.docker.distribution.manifest.list.v2+json";
const MEDIATYPE_OCI_MANIFEST_V1 = "application/vnd.oci.image.manifest.v1+json";
const MEDIATYPE_OCI_MANIFEST_LIST_V1 =
  "application/vnd.oci.image.index.v1+json";

// Maximum size for JSON metadata files. Matches the limit in streamToJson.
// Files larger than this are layer blobs, not JSON metadata.
const MAX_JSON_SIZE_BYTES = 2 * 1024 * 1024;

/**
 * Retrieve the products of files content from the specified oci-archive.
 *
 * Uses a two-pass approach:
 * 1. First pass: Parse JSON metadata (manifests, configs, indexes) to determine
 *    which layers are needed for the target platform.
 * 2. Second pass: Extract only the required layer blobs.
 *
 * This avoids memory issues from buffering large layer blobs unnecessarily.
 *
 * @param ociArchiveFilesystemPath Path to image file saved in oci-archive format.
 * @param extractActions Array of pattern-callbacks pairs.
 * @param options PluginOptions
 * @returns Array of extracted files products sorted by the reverse order of the layers from last to first.
 */
export async function extractArchive(
  ociArchiveFilesystemPath: string,
  extractActions: ExtractAction[],
  options: PluginOptions,
): Promise<ExtractedLayersAndManifest> {
  // Pass 1: Extract JSON metadata
  const metadata = await extractMetadata(ociArchiveFilesystemPath);

  // Determine which manifest and layers we need
  const { manifest, imageConfig } = resolveManifestAndConfig(metadata, options);

  // Get the list of layer digests we need to extract
  const requiredLayerDigests = new Set(
    manifest.layers.map((layer) => layer.digest),
  );

  // Pass 2: Extract the required layers
  const { layers, failedDigests } = await extractLayers(
    ociArchiveFilesystemPath,
    requiredLayerDigests,
    extractActions,
  );

  // Report any layer extraction failures
  if (failedDigests.size > 0) {
    const failures = Array.from(failedDigests.entries())
      .map(([digest, error]) => `${digest}: ${error}`)
      .join("; ");
    debug(`Failed to extract ${failedDigests.size} layer(s): ${failures}`);
  }

  // Build the result
  const filteredLayers = manifest.layers
    .filter((layer) => layers[layer.digest])
    .map((layer) => layers[layer.digest])
    .reverse();

  if (filteredLayers.length === 0) {
    // Provide more context about why extraction failed
    if (failedDigests.size > 0) {
      const failedList = Array.from(failedDigests.keys()).join(", ");
      throw new InvalidArchiveError(
        `Failed to extract any layers from the image. ` +
          `${failedDigests.size} layer(s) failed: ${failedList}`,
      );
    }
    throw new InvalidArchiveError(
      "We found no layers in the provided image. " +
        "The archive may be corrupted or in an unsupported format.",
    );
  }

  // Warn if some but not all layers failed (partial extraction)
  const missingLayers = manifest.layers.filter(
    (layer) => !layers[layer.digest],
  );
  if (missingLayers.length > 0) {
    debug(
      `Warning: ${missingLayers.length} layer(s) from manifest were not extracted: ` +
        missingLayers.map((l) => l.digest).join(", "),
    );
  }

  return {
    layers: filteredLayers,
    manifest,
    imageConfig,
  };
}

interface ArchiveMetadata {
  mainIndexFile?: OciImageIndex;
  manifests: Record<string, OciArchiveManifest>;
  indexFiles: Record<string, OciImageIndex>;
  configs: ImageConfig[];
}

/**
 * Pass 1: Extract only JSON metadata from the archive.
 *
 * Skips large files (> MAX_JSON_SIZE_BYTES) since they're layer blobs, not JSON.
 * For small files, attempts JSON parse; binary data fails fast on the first byte check.
 */
async function extractMetadata(
  ociArchiveFilesystemPath: string,
): Promise<ArchiveMetadata> {
  return new Promise((resolve, reject) => {
    const tarExtractor: Extract = extract();

    const manifests: Record<string, OciArchiveManifest> = {};
    const configs: ImageConfig[] = [];
    let mainIndexFile: OciImageIndex | undefined;
    const indexFiles: Record<string, OciImageIndex> = {};

    tarExtractor.on("entry", async (header, stream, next) => {
      try {
        if (header.type === "file") {
          const normalizedHeaderName = normalizePath(header.name);

          if (isMainIndexFile(normalizedHeaderName)) {
            mainIndexFile = await streamToJson<OciImageIndex>(stream);
          } else if (
            isBlobPath(normalizedHeaderName) &&
            (header.size === undefined || header.size <= MAX_JSON_SIZE_BYTES)
          ) {
            // Small blob file - try to parse as JSON metadata
            // Large files and non-blob files (oci-layout, etc.) are skipped
            const jsonContent = await tryParseJsonMetadata(stream);

            if (jsonContent !== undefined) {
              const digest = getDigestFromPath(normalizedHeaderName);
              if (isArchiveManifest(jsonContent)) {
                manifests[digest] = jsonContent;
              } else if (isImageIndexFile(jsonContent)) {
                indexFiles[digest] = jsonContent as OciImageIndex;
              } else if (isImageConfigFile(jsonContent)) {
                configs.push(jsonContent as ImageConfig);
              }
            }
          }
          // All other files (non-blob, large blobs) are drained below
        }
      } catch (err) {
        debug(
          `Error processing OCI archive entry ${header.name}: ${err.message}`,
        );
      }

      stream.resume(); // Drain the stream
      next();
    });

    tarExtractor.on("finish", () => {
      resolve({ mainIndexFile, manifests, indexFiles, configs });
    });

    tarExtractor.on("error", (error) => {
      reject(error);
    });

    createReadStream(ociArchiveFilesystemPath)
      .pipe(decompressMaybe())
      .pipe(tarExtractor);
  });
}

/**
 * Attempts to parse a stream as JSON metadata.
 * Returns undefined if the stream doesn't contain valid JSON (e.g., it's a layer blob).
 *
 * Uses a fast-fail check: if the first byte isn't '{' or '[', it's not JSON.
 * Note: This doesn't handle JSON with leading whitespace, which is technically valid
 * but never produced by standard OCI tooling.
 */
async function tryParseJsonMetadata(stream: Readable): Promise<unknown> {
  return new Promise((resolve) => {
    let firstChunk = true;
    const chunks: string[] = [];
    let bytes = 0;
    let resolved = false;

    const cleanup = () => {
      stream.removeAllListeners("data");
      stream.removeAllListeners("end");
      // Keep a no-op error handler to prevent unhandled error events
      // when the stream is drained after fast-fail
      stream.removeAllListeners("error");
      // tslint:disable-next-line:no-empty
      stream.on("error", () => {});
    };

    stream.on("data", (chunk: Buffer) => {
      if (firstChunk) {
        firstChunk = false;
        // Fast-fail: JSON must start with { or [
        const firstByte = chunk[0];
        if (firstByte !== 0x7b && firstByte !== 0x5b) {
          // 0x7b = '{', 0x5b = '['
          resolved = true;
          cleanup();
          resolve(undefined);
          return;
        }
      }

      bytes += chunk.length;
      if (bytes <= MAX_JSON_SIZE_BYTES) {
        chunks.push(chunk.toString("utf8"));
      }
    });

    stream.on("end", () => {
      if (resolved) {
        return;
      }
      if (chunks.length === 0) {
        resolve(undefined);
        return;
      }
      try {
        resolve(JSON.parse(chunks.join("")));
      } catch {
        resolve(undefined);
      }
    });

    stream.on("error", () => {
      if (!resolved) {
        resolve(undefined);
      }
    });
  });
}

interface LayerExtractionResult {
  layers: Record<string, ExtractedLayers>;
  failedDigests: Map<string, string>;
}

/**
 * Pass 2: Extract only the specified layer blobs.
 *
 * Tracks extraction failures so the caller can report which layers failed
 * rather than silently returning incomplete results.
 */
async function extractLayers(
  ociArchiveFilesystemPath: string,
  requiredDigests: Set<string>,
  extractActions: ExtractAction[],
): Promise<LayerExtractionResult> {
  return new Promise((resolve, reject) => {
    const tarExtractor: Extract = extract();
    const layers: Record<string, ExtractedLayers> = {};
    const failedDigests: Map<string, string> = new Map();

    tarExtractor.on("entry", async (header, stream, next) => {
      try {
        if (header.type === "file") {
          const normalizedHeaderName = normalizePath(header.name);

          if (
            !isMainIndexFile(normalizedHeaderName) &&
            isBlobPath(normalizedHeaderName)
          ) {
            const digest = getDigestFromPath(normalizedHeaderName);

            if (requiredDigests.has(digest)) {
              // This is a layer we need - extract it
              try {
                const layer = await extractImageLayer(stream, extractActions);
                layers[digest] = layer;
              } catch (error) {
                const errorMessage =
                  error instanceof Error ? error.message : String(error);
                debug(`Failed to extract layer ${digest}: ${errorMessage}`);
                failedDigests.set(digest, errorMessage);
              }
            }
          }
        }
      } catch (err) {
        debug(`Error processing archive entry ${header.name}: ${err.message}`);
      }

      stream.resume();
      next();
    });

    tarExtractor.on("finish", () => {
      resolve({ layers, failedDigests });
    });

    tarExtractor.on("error", (error) => {
      reject(error);
    });

    createReadStream(ociArchiveFilesystemPath)
      .pipe(decompressMaybe())
      .pipe(tarExtractor);
  });
}

/**
 * Checks if a path is in the blobs directory (blobs/<algo>/<hash>).
 * Non-blob files like oci-layout should be skipped.
 */
function isBlobPath(normalizedPath: string): boolean {
  const parts = normalizedPath.split(pathSeparator);
  return parts[0] === "blobs" && parts.length >= 3;
}

/**
 * Extracts digest from a blob path in the format blobs/<algo>/<hash>.
 * Returns the digest as <algo>:<hash> to match manifest digest format.
 *
 * Caller should verify isBlobPath() first.
 */
function getDigestFromPath(normalizedPath: string): string {
  const headerParts = normalizedPath.split(pathSeparator);
  const algorithm = headerParts[1];
  const hash = headerParts[headerParts.length - 1];
  return `${algorithm}:${hash}`;
}

function resolveManifestAndConfig(
  metadata: ArchiveMetadata,
  options: Partial<PluginOptions>,
): {
  manifest: OciArchiveManifest;
  platformInfo: OciPlatformInfo;
  imageConfig: ImageConfig;
} {
  const filteredConfigs = metadata.configs.filter((config) => {
    return config?.os !== "unknown" || config?.architecture !== "unknown";
  });

  const platform =
    options?.platform ||
    (filteredConfigs.length === 1
      ? getPlatformFromConfig(filteredConfigs[0])
      : "linux/amd64");

  const platformInfo = getOciPlatformInfoFromOptionString(platform as string);

  const manifest = getManifest(
    metadata.mainIndexFile,
    metadata.manifests,
    metadata.indexFiles,
    platformInfo,
  );

  if (!manifest) {
    throw new InvalidArchiveError(
      `Could not find manifest for platform ${platformInfo.os}/${platformInfo.architecture} in archive`,
    );
  }

  const imageConfig = getImageConfig(metadata.configs, platformInfo);

  if (imageConfig === undefined) {
    throw new InvalidArchiveError(
      "Could not find the image config in the provided image",
    );
  }

  return { manifest, platformInfo, imageConfig };
}

function getManifest(
  imageIndex: OciImageIndex | undefined,
  manifestCollection: Record<string, OciArchiveManifest>,
  indexFiles: Record<string, OciImageIndex>,
  platformInfo: OciPlatformInfo,
): OciArchiveManifest | undefined {
  if (!imageIndex) {
    return manifestCollection[Object.keys(manifestCollection)[0]];
  }

  const allManifests = getAllManifestsIndexItems(imageIndex, indexFiles);
  const manifestInfo = getImageManifestInfo(allManifests, platformInfo);

  if (manifestInfo === undefined) {
    throw new InvalidArchiveError(
      "Image does not support the requested CPU architecture or operating system",
    );
  }

  return manifestCollection[manifestInfo.digest];
}

function getAllManifestsIndexItems(
  imageIndex: OciImageIndex,
  indexFiles: Record<string, OciImageIndex>,
): OciManifestInfo[] {
  const allManifestsInfo: OciManifestInfo[] = [];
  for (const manifest of imageIndex.manifests) {
    if (
      manifest.mediaType === MEDIATYPE_OCI_MANIFEST_V1 ||
      manifest.mediaType === MEDIATYPE_DOCKER_MANIFEST_V2
    ) {
      // an archive manifest file
      allManifestsInfo.push(manifest);
    } else if (
      manifest.mediaType === MEDIATYPE_OCI_MANIFEST_LIST_V1 ||
      manifest.mediaType === MEDIATYPE_DOCKER_MANIFEST_LIST_V2
    ) {
      // nested index
      const index = indexFiles[manifest.digest];
      if (index) {
        allManifestsInfo.push(...getAllManifestsIndexItems(index, indexFiles));
      }
    }
  }
  return allManifestsInfo;
}

function isArchiveManifest(manifest: any): manifest is OciArchiveManifest {
  return (
    manifest !== undefined && manifest.layers && Array.isArray(manifest.layers)
  );
}

function isImageConfigFile(json: any): json is ImageConfig {
  return json !== undefined && json.architecture && json.rootfs;
}

function isImageIndexFile(json: any): boolean {
  return (
    (json?.mediaType === MEDIATYPE_OCI_MANIFEST_LIST_V1 ||
      json?.mediaType === MEDIATYPE_DOCKER_MANIFEST_LIST_V2) &&
    Array.isArray(json?.manifests)
  );
}

function isMainIndexFile(name: string): boolean {
  return name === "index.json";
}

function getOciPlatformInfoFromOptionString(platform: string): OciPlatformInfo {
  const [os, architecture, variant] = platform.split("/") as [
    os: string,
    architecture: string,
    variant: string | undefined,
  ];

  return {
    os,
    architecture,
    variant,
  };
}

function getImageManifestInfo(
  manifests: OciManifestInfo[],
  platformInfo: OciPlatformInfo,
): OciManifestInfo | undefined {
  // manifests do not always have a plaform, this is the case for OCI
  // images built with Docker when no platform is specified
  if (manifests.length === 1 && !manifests[0].platform) {
    return manifests[0];
  }

  return getBestMatchForPlatform(
    manifests,
    platformInfo,
    (target: OciManifestInfo): OciPlatformInfo => {
      return {
        os: target.platform?.os,
        architecture: target.platform?.architecture,
        variant: target.platform?.variant,
      };
    },
  );
}

function getImageConfig(
  manifests: ImageConfig[],
  platformInfo: OciPlatformInfo,
): ImageConfig | undefined {
  return getBestMatchForPlatform(
    manifests,
    platformInfo,
    (target: ImageConfig): OciPlatformInfo => {
      return {
        os: target.os,
        architecture: target.architecture,
      };
    },
  );
}

function getBestMatchForPlatform<T>(
  manifests: T[],
  platformInfo: OciPlatformInfo,
  extractPlatformInfoFromManifest: (target: T) => OciPlatformInfo,
): T | undefined {
  const matches = manifests.filter((item) => {
    const { os, architecture } = extractPlatformInfoFromManifest(item);

    return os === platformInfo.os && architecture === platformInfo.architecture;
  });

  if (matches.length > 1) {
    return matches.find((item) => {
      const { variant } = extractPlatformInfoFromManifest(item);

      return variant === platformInfo.variant;
    });
  }

  return matches[0] || undefined;
}
