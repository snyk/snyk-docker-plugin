import { createReadStream } from "fs";
import * as gunzip from "gunzip-maybe";
import { basename, resolve as resolvePath } from "path";
import { PassThrough, Readable } from "stream";
import { extract, Extract } from "tar-stream";
import { streamToJson } from "../stream-utils";
import { applyCallbacks } from "./callbacks";
import {
  DockerArchiveManifest,
  ExtractAction,
  ExtractedLayers,
  ExtractedLayersAndManifest,
  FileNameAndContent,
  OciArchiveManifest,
  OciImageIndex,
  OciManifestInfo,
} from "./types";

/**
 * Retrieve the products of files content from the specified docker-archive.
 * @param dockerArchiveFilesystemPath Path to image file saved in docker-archive format.
 * @param extractActions Array of pattern-callbacks pairs.
 * @returns Array of extracted files products sorted by the reverse order of the layers from last to first.
 */
export async function extractDockerArchive(
  dockerArchiveFilesystemPath: string,
  extractActions: ExtractAction[],
): Promise<ExtractedLayersAndManifest> {
  return new Promise((resolve, reject) => {
    const tarExtractor: Extract = extract();
    const layers: Record<string, ExtractedLayers> = {};
    let manifest: DockerArchiveManifest;

    tarExtractor.on("entry", async (header, stream, next) => {
      if (header.type === "file") {
        if (isTarFile(header.name)) {
          layers[header.name] = await extractImageLayer(stream, extractActions);
        } else if (isManifestFile(header.name)) {
          manifest = await getManifestFile(stream);
        }
      }

      stream.resume(); // auto drain the stream
      next(); // ready for next entry
    });

    tarExtractor.on("finish", () => {
      resolve(getLayersContentAndArchiveManifest(manifest, layers));
    });

    tarExtractor.on("error", (error) => reject(error));

    createReadStream(dockerArchiveFilesystemPath)
      .pipe(gunzip())
      .pipe(tarExtractor);
  });
}

export async function extractOciArchive(
  ociArchiveFilesystemPath: string,
  extractActions: ExtractAction[],
): Promise<{
  layers: ExtractedLayers[];
  manifest: OciArchiveManifest;
}> {
  return new Promise((resolve, reject) => {
    const tarExtractor: Extract = extract();

    const layers: Record<string, ExtractedLayers> = {};
    const manifests: Record<string, OciArchiveManifest> = {};
    let imageIndex: OciImageIndex | undefined;

    tarExtractor.on("entry", async (header, stream, next) => {
      if (header.type === "file") {
        if (isImageIndexFile(header.name)) {
          imageIndex = await streamToJson<OciImageIndex>(stream);
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
          const headerParts = header.name.split("/");
          const hashName = headerParts[1];
          const hashValue = headerParts[headerParts.length - 1];
          const digest = `${hashName}:${hashValue}`;
          if (isOciArchiveManifest(manifest)) {
            manifests[digest] = manifest;
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
          getOciLayersContentAndArchiveManifest(imageIndex, manifests, layers),
        );
      } catch (error) {
        reject(error);
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

/**
 * Extract key files from the specified TAR stream.
 * @param layerTarStream image layer as a Readable TAR stream. Note: consumes the stream.
 * @param extractActions array of pattern, callbacks pairs
 * @returns extracted file products
 */
export async function extractImageLayer(
  layerTarStream: Readable,
  extractActions: ExtractAction[],
): Promise<ExtractedLayers> {
  return new Promise((resolve, reject) => {
    const result: ExtractedLayers = {};
    const tarExtractor: Extract = extract();

    tarExtractor.on("entry", async (headers, stream, next) => {
      if (headers.type === "file") {
        const absoluteFileName = resolvePath("/", headers.name);
        // TODO wouldn't it be simpler to first check
        // if the filename matches any patterns?
        const processedResult = await extractFileAndProcess(
          absoluteFileName,
          stream,
          extractActions,
        );
        if (processedResult !== undefined) {
          result[absoluteFileName] = processedResult;
        }
      }

      stream.resume(); // auto drain the stream
      next(); // ready for next entry
    });

    tarExtractor.on("finish", () => {
      // all layer level entries read
      resolve(result);
    });

    tarExtractor.on("error", (error) => reject(error));

    layerTarStream.pipe(gunzip()).pipe(tarExtractor);
  });
}

/**
 * Note: consumes the stream.
 */
async function extractFileAndProcess(
  fileName: string,
  fileStream: Readable,
  extractActions: ExtractAction[],
): Promise<FileNameAndContent | undefined> {
  const matchedActions = extractActions.filter((action) =>
    action.filePathMatches(fileName),
  );

  if (matchedActions.length > 0) {
    return await applyCallbacks(matchedActions, fileStream);
  }

  return undefined;
}

function getLayersContentAndArchiveManifest(
  manifest: DockerArchiveManifest,
  layers: Record<string, ExtractedLayers>,
): ExtractedLayersAndManifest {
  // skip (ignore) non-existent layers
  // get the layers content without the name
  // reverse layers order from last to first
  const filteredLayers = manifest.Layers.filter(
    (layersName) => layers[layersName],
  )
    .map((layerName) => layers[layerName])
    .reverse();

  return {
    layers: filteredLayers,
    manifest,
  };
}

function getOciLayersContentAndArchiveManifest(
  imageIndex: OciImageIndex | undefined,
  manifestCollection: Record<string, OciArchiveManifest>,
  layers: Record<string, ExtractedLayers>,
): { layers: ExtractedLayers[]; manifest: OciArchiveManifest } {
  // filter empty layers
  // get the layers content without the name
  // reverse layers order from last to first

  // get manifest file first
  const manifest = getOciManifest(imageIndex, manifestCollection);
  const filteredLayers = manifest.layers
    .filter((layer) => Object.keys(layers[layer.digest]).length !== 0)
    .map((layer) => layers[layer.digest])
    .reverse();

  return {
    layers: filteredLayers,
    manifest,
  };
}

function getOciManifest(
  imageIndex: OciImageIndex | undefined,
  manifestCollection: Record<string, OciArchiveManifest>,
): OciArchiveManifest {
  if (!imageIndex) {
    return manifestCollection[Object.keys(manifestCollection)[0]];
  }

  const manifestInfo:
    | OciManifestInfo
    | undefined = imageIndex.manifests.find((item) =>
    item.platform
      ? item.platform.architecture === "amd64" && item.platform.os === "linux"
      : item,
  );

  if (manifestInfo === undefined) {
    throw new Error("Unsupported type of CPU architecture or operating system");
  }

  return manifestCollection[manifestInfo.digest];
}

/**
 * Note: consumes the stream.
 */
function getManifestFile(stream: Readable): Promise<DockerArchiveManifest> {
  return streamToJson<DockerArchiveManifest>(stream).then((manifest) => {
    return manifest[0];
  });
}

function isOciArchiveManifest(manifest: any): manifest is OciArchiveManifest {
  return (
    manifest !== undefined && manifest.layers && manifest.layers.length >= 0
  );
}

function isManifestFile(name: string): boolean {
  return name === "manifest.json";
}

function isImageIndexFile(name: string): boolean {
  return name === "index.json";
}

function isTarFile(name: string): boolean {
  // For both "docker save" and "skopeo copy" style archives the
  // layers are represented as tar archives whose names end in .tar.
  // For Docker this is "layer.tar", for Skopeo - "<sha256ofLayer>.tar".
  return basename(name).endsWith(".tar");
}
