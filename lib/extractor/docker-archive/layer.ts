import * as Debug from "debug";
import { createReadStream } from "fs";
import * as gunzip from "gunzip-maybe";
import { basename } from "path";
import { Readable } from "stream";
import { extract, Extract } from "tar-stream";
import { streamToJson } from "../../stream-utils";
import { extractImageLayer } from "../layer";
import {
  DockerArchiveManifest,
  ExtractAction,
  ExtractedLayers,
  ExtractedLayersAndManifest,
} from "../types";

const debug = Debug("snyk");

/**
 * Retrieve the products of files content from the specified docker-archive.
 * @param dockerArchiveFilesystemPath Path to image file saved in docker-archive format.
 * @param extractActions Array of pattern-callbacks pairs.
 * @returns Array of extracted files products sorted by the reverse order of the layers from last to first.
 */
export async function extractArchive(
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
          try {
            layers[header.name] = await extractImageLayer(
              stream,
              extractActions,
            );
          } catch (error) {
            debug(`Error extracting layer content from: '${error}'`);
            reject(new Error("Error reading tar archive"));
          }
        } else if (isManifestFile(header.name)) {
          manifest = await getManifestFile(stream);
        }
      }

      stream.resume(); // auto drain the stream
      next(); // ready for next entry
    });

    tarExtractor.on("finish", () => {
      try {
        resolve(getLayersContentAndArchiveManifest(manifest, layers));
      } catch (error) {
        debug(
          `Error getting layers and manifest content from docker archive: '${error}'`,
        );
        reject(new Error("Invalid Docker archive"));
      }
    });

    tarExtractor.on("error", (error) => reject(error));

    createReadStream(dockerArchiveFilesystemPath)
      .pipe(gunzip())
      .pipe(tarExtractor);
  });
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

  if (filteredLayers.length === 0) {
    throw new Error("We found no layers in the provided image");
  }

  return {
    layers: filteredLayers,
    manifest,
  };
}

/**
 * Note: consumes the stream.
 */
function getManifestFile(stream: Readable): Promise<DockerArchiveManifest> {
  return streamToJson<DockerArchiveManifest>(stream).then((manifest) => {
    return manifest[0];
  });
}

function isManifestFile(name: string): boolean {
  return name === "manifest.json";
}

function isTarFile(name: string): boolean {
  // For both "docker save" and "skopeo copy" style archives the
  // layers are represented as tar archives whose names end in .tar.
  // For Docker this is "layer.tar", for Skopeo - "<sha256ofLayer>.tar".
  return basename(name).endsWith(".tar");
}
