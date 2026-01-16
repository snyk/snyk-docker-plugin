import * as Debug from "debug";
import { createReadStream } from "fs";
import { normalize as normalizePath, sep as pathSeparator } from "path";
import { extract, Extract } from "tar-stream";
import { getPlatformFromConfig } from "..";
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
  const { manifest, imageConfig } = resolveManifestAndConfig(
    metadata,
    options,
  );

  // Get the list of layer digests we need to extract
  const requiredLayerDigests = new Set(
    manifest.layers.map((layer) => layer.digest),
  );

  // Pass 2: Extract the required layers
  const layers = await extractLayers(
    ociArchiveFilesystemPath,
    requiredLayerDigests,
    extractActions,
  );

  // Build the result
  const filteredLayers = manifest.layers
    .filter((layer) => layers[layer.digest])
    .map((layer) => layers[layer.digest])
    .reverse();

  if (filteredLayers.length === 0) {
    throw new Error("We found no layers in the provided image");
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
 * This is fast because JSON files are small.
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
          } else {
            // Try to parse as JSON - this will fail fast for binary layer blobs
            let jsonContent: any;
            try {
              jsonContent = await streamToJson(stream);
            } catch {
              jsonContent = undefined;
            }

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
        }
      } catch (err) {
        debug(`Error processing OCI archive entry ${header.name}: ${err.message}`);
      }

      stream.resume();
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
 * Pass 2: Extract only the specified layer blobs.
 */
async function extractLayers(
  ociArchiveFilesystemPath: string,
  requiredDigests: Set<string>,
  extractActions: ExtractAction[],
): Promise<Record<string, ExtractedLayers>> {
  return new Promise((resolve, reject) => {
    const tarExtractor: Extract = extract();
    const layers: Record<string, ExtractedLayers> = {};

    tarExtractor.on("entry", async (header, stream, next) => {
      try {
        if (header.type === "file") {
          const normalizedHeaderName = normalizePath(header.name);

          if (!isMainIndexFile(normalizedHeaderName)) {
            const digest = getDigestFromPath(normalizedHeaderName);

            if (requiredDigests.has(digest)) {
              // This is a layer we need - extract it
              try {
                const layer = await extractImageLayer(stream, extractActions);
                layers[digest] = layer;
              } catch {
                // Not a valid layer tarball, skip
              }
            }
          }
        }
      } catch (err) {
        debug(`Error extracting layer ${header.name}: ${err.message}`);
      }

      stream.resume();
      next();
    });

    tarExtractor.on("finish", () => {
      resolve(layers);
    });

    tarExtractor.on("error", (error) => {
      reject(error);
    });

    createReadStream(ociArchiveFilesystemPath)
      .pipe(decompressMaybe())
      .pipe(tarExtractor);
  });
}

function getDigestFromPath(normalizedPath: string): string {
  // header format is /blobs/hash_name/hash_value
  // we're extracting hash_name:hash_value format to match manifest digest
  const headerParts = normalizedPath.split(pathSeparator);
  const hashName = headerParts[1];
  const hashValue = headerParts[headerParts.length - 1];
  return `${hashName}:${hashValue}`;
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
    throw new Error(
      `Could not find manifest for platform ${platformInfo.os}/${platformInfo.architecture} in archive`,
    );
  }

  const imageConfig = getImageConfig(metadata.configs, platformInfo);

  if (imageConfig === undefined) {
    throw new Error("Could not find the image config in the provided image");
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
    throw new Error(
      "Image does not support type of CPU architecture or operating system",
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
