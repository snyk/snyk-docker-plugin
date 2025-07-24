import * as Debug from "debug";
import { createReadStream } from "fs";
import * as gunzip from "gunzip-maybe";
import { basename, normalize as normalizePath } from "path";
import { Readable } from "stream";
import { extract, Extract } from "tar-stream";
import { InvalidArchiveError } from "..";
import { streamToJson } from "../../stream-utils";
import { PluginOptions } from "../../types";
import { extractImageLayer } from "../layer";
import {
  DockerArchiveManifest,
  ExtractAction,
  ExtractedLayers,
  ExtractedLayersAndManifest,
  ImageConfig,
} from "../types";

const debug = Debug("snyk");

/**
 * Retrieve the products of files content from the specified docker-archive.
 * @param dockerArchiveFilesystemPath Path to image file saved in docker-archive format.
 * @param extractActions Array of pattern-callbacks pairs.
 * @param options PluginOptions
 * @returns Array of extracted files products sorted by the reverse order of the layers from last to first.
 */
export async function extractArchive(
  dockerArchiveFilesystemPath: string,
  extractActions: ExtractAction[],
  _options: Partial<PluginOptions>,
): Promise<ExtractedLayersAndManifest> {
  return new Promise((resolve, reject) => {
    const tarExtractor: Extract = extract();
    const layers: Record<string, ExtractedLayers> = {};
    let manifest: DockerArchiveManifest;
    let imageConfig: ImageConfig;
    


    tarExtractor.on("entry", async (header, stream, next) => {
      if (header.type === "file") {
        const normalizedName = normalizePath(header.name);
        if (isManifestFile(normalizedName)) {
          const manifestArray = await getManifestFile<DockerArchiveManifest[]>(
            stream,
          );
          manifest = manifestArray[0];
        } else if (isTarFile(normalizedName)) {
          try {
            layers[normalizedName] = await extractImageLayer(
              stream,
              extractActions,
            );
          } catch (error) {
            debug(`Error extracting layer content from: '${error.message}'}`);
            // Don't reject for blob extraction errors - some blobs aren't layers
            if (!normalizedName.startsWith("blobs/sha256/")) {
              reject(new Error("Error reading tar archive"));
            }
          }
        } else if (isImageConfigFile(normalizedName)) {
          imageConfig = await getManifestFile<ImageConfig>(stream);
        } else if (normalizedName.startsWith("blobs/sha256/")) {
          // Handle blob-based files - try config first, then layer
          // Buffer the stream content so we can try both approaches
          const chunks: Buffer[] = [];
          stream.on('data', (chunk) => chunks.push(chunk));
          await new Promise((resolve) => stream.on('end', resolve));
          const content = Buffer.concat(chunks);
          
          // First try as JSON config
          try {
            const potentialConfig = JSON.parse(content.toString());
            if (potentialConfig && potentialConfig.created) {
              imageConfig = potentialConfig;
            } else {
              // Try as layer
              const Readable = require('stream').Readable;
              const layerStream = new Readable();
              layerStream.push(content);
              layerStream.push(null);
              try {
                layers[normalizedName] = await extractImageLayer(
                  layerStream,
                  extractActions,
                );
              } catch (layerError) {
                // Failed as both config and layer, skip silently
              }
            }
          } catch (jsonError) {
            // Not JSON, try as layer
            const Readable = require('stream').Readable;
            const layerStream = new Readable();
            layerStream.push(content);
            layerStream.push(null);
            try {
              layers[normalizedName] = await extractImageLayer(
                layerStream,
                extractActions,
              );
            } catch (layerError) {
              // Failed as layer, skip silently
            }
          }
        }
      }

      stream.resume(); // auto drain the stream
      next(); // ready for next entry
    });

    tarExtractor.on("finish", () => {
      try {
        resolve(
          getLayersContentAndArchiveManifest(manifest, imageConfig, layers),
        );
      } catch (error) {
        debug(
          `Error getting layers and manifest content from docker archive: ${error.message}`,
        );
        reject(new InvalidArchiveError("Invalid Docker archive"));
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
  imageConfig: ImageConfig,
  layers: Record<string, ExtractedLayers>,
): ExtractedLayersAndManifest {
  // skip (ignore) non-existent layers
  // get the layers content without the name
  // reverse layers order from last to first
  const layersWithNormalizedNames = manifest.Layers.map((layersName) =>
    normalizePath(layersName),
  );
  const filteredLayers = layersWithNormalizedNames
    .filter((layersName) => layers[layersName])
    .map((layerName) => layers[layerName])
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

/**
 * Note: consumes the stream.
 */
async function getManifestFile<T>(stream: Readable): Promise<T> {
  return streamToJson<T>(stream);
}

function isManifestFile(name: string): boolean {
  return name === "manifest.json";
}

function isImageConfigFile(name: string): boolean {
  const configRegex = new RegExp("[A-Fa-f0-9]{64}\\.json");
  return configRegex.test(name);
}

function isTarFile(name: string): boolean {
  // For both "docker save" and "skopeo copy" style archives the
  // layers are represented as tar archives whose names end in .tar.
  // For Docker this is "layer.tar", for Skopeo - "<sha256ofLayer>.tar".
  // Note: blobs/sha256/ files are handled separately now
  return basename(name).endsWith(".tar");
}


