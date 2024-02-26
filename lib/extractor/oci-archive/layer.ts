import * as Debug from "debug";
import { createReadStream } from "fs";
import * as gunzip from "gunzip-maybe";
import { normalize as normalizePath, sep as pathSeparator } from "path";
import { PassThrough } from "stream";
import { extract, Extract } from "tar-stream";
import { InvalidArchiveError } from "..";
import { streamToJson } from "../../stream-utils";
import { PluginOptions } from "../../types";
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
 * @param ociArchiveFilesystemPath Path to image file saved in oci-archive format.
 * @param extractActions Array of pattern-callbacks pairs.
 * @returns Array of extracted files products sorted by the reverse order of the layers from last to first.
 */
export async function extractArchive(
  ociArchiveFilesystemPath: string,
  extractActions: ExtractAction[],
  options: PluginOptions,
): Promise<ExtractedLayersAndManifest> {
  return new Promise((resolve, reject) => {
    const tarExtractor: Extract = extract();

    const layers: Record<string, ExtractedLayers> = {};
    const manifests: Record<string, OciArchiveManifest> = {};
    const configs: ImageConfig[] = [];
    let mainIndexFile: OciImageIndex;
    const indexFiles: Record<string, OciImageIndex> = {};

    tarExtractor.on("entry", async (header, stream, next) => {
      if (header.type === "file") {
        const normalizedHeaderName = normalizePath(header.name);
        if (isMainIndexFile(normalizedHeaderName)) {
          mainIndexFile = await streamToJson<OciImageIndex>(stream);
        } else {
          const jsonStream = new PassThrough();
          const layerStream = new PassThrough();
          stream.pipe(jsonStream);
          stream.pipe(layerStream);

          const promises = [
            streamToJson(jsonStream).catch(() => undefined),
            extractImageLayer(layerStream, extractActions).catch(
              () => undefined,
            ),
          ];
          const [manifest, layer] = await Promise.all(promises);

          // header format is /blobs/hash_name/hash_value
          // we're extracting hash_name:hash_value format to match manifest digest
          const headerParts = normalizedHeaderName.split(pathSeparator);
          const hashName = headerParts[1];
          const hashValue = headerParts[headerParts.length - 1];
          const digest = `${hashName}:${hashValue}`;
          if (isArchiveManifest(manifest)) {
            manifests[digest] = manifest;
          } else if (isImageIndexFile(manifest)) {
            indexFiles[digest] = manifest as OciImageIndex;
          } else if (isImageConfigFile(manifest)) {
            configs.push(manifest);
          }
          if (layer !== undefined) {
            layers[digest] = layer as ExtractedLayers;
          }
        }
      }

      stream.resume(); // auto drain the stream
      next(); // ready for next entry
    });

    tarExtractor.on("finish", () => {
      try {
        resolve(
          getLayersContentAndArchiveManifest(
            mainIndexFile,
            manifests,
            indexFiles,
            configs,
            layers,
            options,
          ),
        );
      } catch (error) {
        debug(
          `Error getting layers and manifest content from oci archive: '${error.message}'`,
        );
        reject(new InvalidArchiveError("Invalid OCI archive"));
      }
    });

    tarExtractor.on("error", (error) => {
      reject(error);
    });

    createReadStream(ociArchiveFilesystemPath)
      .pipe(gunzip())
      .pipe(tarExtractor);
  });
}

function getLayersContentAndArchiveManifest(
  imageIndex: OciImageIndex | undefined,
  manifestCollection: Record<string, OciArchiveManifest>,
  indexFiles: Record<string, OciImageIndex>,
  configs: ImageConfig[],
  layers: Record<string, ExtractedLayers>,
  options: Partial<PluginOptions>,
): {
  layers: ExtractedLayers[];
  manifest: OciArchiveManifest;
  imageConfig: ImageConfig;
} {
  const platform = options?.platform || "linux/amd64";
  const platformInfo = getOciPlatformInfoFromOptionString(platform as string);

  // get manifest file first
  const manifest = getManifest(
    imageIndex,
    manifestCollection,
    indexFiles,
    platformInfo,
  );
  const filteredLayers = manifest.layers
    .filter((layer) => layers[layer.digest])
    .map((layer) => layers[layer.digest])
    .reverse();

  // filter empty layers
  // get the layers content without the name
  // reverse layers order from last to first
  if (filteredLayers.length === 0) {
    throw new Error("We found no layers in the provided image");
  }

  const imageConfig = getImageConfig(configs, platformInfo);

  if (imageConfig === undefined) {
    throw new Error("Could not find the image config in the provided image");
  }

  return {
    layers: filteredLayers,
    manifest,
    imageConfig,
  };
}

function getManifest(
  imageIndex: OciImageIndex | undefined,
  manifestCollection: Record<string, OciArchiveManifest>,
  indexFiles: Record<string, OciImageIndex>,
  platformInfo: OciPlatformInfo,
): OciArchiveManifest {
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
      allManifestsInfo.push(...getAllManifestsIndexItems(index, indexFiles));
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
