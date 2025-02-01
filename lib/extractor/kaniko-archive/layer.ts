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
  ExtractAction,
  ImageConfig,
  KanikoArchiveManifest,
  KanikoExtractedLayers,
  KanikoExtractedLayersAndManifest,
} from "../types";

const debug = Debug("snyk");

/**
 * Retrieve the products of files content from the specified kaniko-archive.
 * @param kanikoArchiveFilesystemPath Path to image file saved in kaniko-archive format.
 * @param extractActions Array of pattern-callbacks pairs.
 * @param options PluginOptions
 * @returns Array of extracted files products sorted by the reverse order of the layers from last to first.
 */
export async function extractArchive(
  kanikoArchiveFilesystemPath: string,
  extractActions: ExtractAction[],
  _options: Partial<PluginOptions>,
): Promise<KanikoExtractedLayersAndManifest> {
  return new Promise((resolve, reject) => {
    const tarExtractor: Extract = extract();
    const layers: Record<string, KanikoExtractedLayers> = {};
    let manifest: KanikoArchiveManifest;
    let imageConfig: ImageConfig;

    tarExtractor.on("entry", async (header, stream, next) => {
      if (header.type === "file") {
        const normalizedName = normalizePath(header.name);
        if (isTarGzFile(normalizedName)) {
          try {
            layers[normalizedName] = await extractImageLayer(
              stream,
              extractActions,
            );
          } catch (error) {
            debug(`Error extracting layer content from: '${error.message}'`);
            reject(new Error("Error reading tar.gz archive"));
          }
        } else if (isManifestFile(normalizedName)) {
          const manifestArray = await getManifestFile<KanikoArchiveManifest[]>(
            stream,
          );

          manifest = manifestArray[0];
        } else if (isImageConfigFile(normalizedName)) {
          imageConfig = await getManifestFile<ImageConfig>(stream);
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
          `Error getting layers and manifest content from Kaniko archive: ${error.message}`,
        );
        reject(new InvalidArchiveError("Invalid Kaniko archive"));
      }
    });

    tarExtractor.on("error", (error) => reject(error));

    createReadStream(kanikoArchiveFilesystemPath)
      .pipe(gunzip())
      .pipe(tarExtractor);
  });
}

function getLayersContentAndArchiveManifest(
  manifest: KanikoArchiveManifest,
  imageConfig: ImageConfig,
  layers: Record<string, KanikoExtractedLayers>,
): KanikoExtractedLayersAndManifest {
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
  const configRegex = new RegExp("sha256:[A-Fa-f0-9]{64}");
  return configRegex.test(name);
}

function isTarGzFile(name: string): boolean {
  return basename(name).endsWith(".tar.gz");
}
