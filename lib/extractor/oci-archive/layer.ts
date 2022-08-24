import * as Debug from "debug";
import { createReadStream } from "fs";
import * as gunzip from "gunzip-maybe";
import { normalize as normalizePath, sep as pathSeparator } from "path";
import { PassThrough } from "stream";
import { extract, Extract } from "tar-stream";
import { streamToJson } from "../../stream-utils";
import { extractImageLayer } from "../layer";
import {
  ExtractAction,
  ExtractedLayers,
  ImageConfig,
  OciArchiveManifest,
  OciImageIndex,
  OciManifestInfo,
} from "../types";

const debug = Debug("snyk");

/**
 * Retrieve the products of files content from the specified oci-archive.
 * @param ociArchiveFilesystemPath Path to image file saved in oci-archive format.
 * @param extractActions Array of pattern-callbacks pairs.
 * @returns Array of extracted files products sorted by the reverse order of the layers from last to first.
 */
export async function extractArchive(
  ociArchiveFilesystemPath: string,
  extractActions: ExtractAction[],
): Promise<{
  layers: ExtractedLayers[];
  manifest: OciArchiveManifest;
  imageConfig: ImageConfig;
}> {
  return new Promise((resolve, reject) => {
    const tarExtractor: Extract = extract();

    const layers: Record<string, ExtractedLayers> = {};
    const manifests: Record<string, OciArchiveManifest> = {};
    let imageConfig: ImageConfig | undefined;
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
            imageConfig = manifest;
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
            imageConfig,
            layers,
          ),
        );
      } catch (error) {
        debug(
          `Error getting layers and manifest content from oci archive: '${JSON.stringify(
            error,
          )}'`,
        );
        reject(new Error("Invalid OCI archive"));
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
  imageConfig: ImageConfig | undefined,
  layers: Record<string, ExtractedLayers>,
): {
  layers: ExtractedLayers[];
  manifest: OciArchiveManifest;
  imageConfig: ImageConfig;
} {
  // filter empty layers
  // get the layers content without the name
  // reverse layers order from last to first

  // get manifest file first
  const manifest = getManifest(imageIndex, manifestCollection, indexFiles);
  const filteredLayers = manifest.layers
    .filter((layer) => layers[layer.digest])
    .map((layer) => layers[layer.digest])
    .reverse();

  if (filteredLayers.length === 0) {
    throw new Error("We found no layers in the provided image");
  }

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
): OciArchiveManifest {
  if (!imageIndex) {
    return manifestCollection[Object.keys(manifestCollection)[0]];
  }
  const allManifests = getAllManifestsIndexItems(imageIndex, indexFiles);
  const manifestInfo: OciManifestInfo | undefined = allManifests.find((item) =>
    item.platform
      ? item.platform.architecture === "amd64" && item.platform.os === "linux"
      : item,
  );

  if (manifestInfo === undefined) {
    throw new Error("Unsupported type of CPU architecture or operating system");
  }

  return manifestCollection[manifestInfo.digest];
}

function getAllManifestsIndexItems(
  imageIndex: OciImageIndex,
  indexFiles: Record<string, OciImageIndex>,
): OciManifestInfo[] {
  const allManifestsInfo: OciManifestInfo[] = [];
  for (const manifest of imageIndex.manifests) {
    if (manifest.mediaType === "application/vnd.oci.image.manifest.v1+json") {
      // an archive manifest file
      allManifestsInfo.push(manifest);
    } else if (
      manifest.mediaType === "application/vnd.oci.image.index.v1+json"
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
    json?.mediaType === "application/vnd.oci.image.index.v1+json" &&
    Array.isArray(json?.manifests)
  );
}

function isMainIndexFile(name: string): boolean {
  return name === "index.json";
}
