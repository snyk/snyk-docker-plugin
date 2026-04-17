import * as Debug from "debug";
import { createReadStream } from "fs";
import * as gunzip from "gunzip-maybe";
import { basename, normalize as normalizePath } from "path";
import { Readable } from "stream";
import { extract, Extract } from "tar-stream";
import { getErrorMessage } from "../error-utils";
import { streamToJson } from "../stream-utils";

export class InvalidArchiveError extends Error {
  constructor(message: string) {
    super();
    this.name = "InvalidArchiveError";
    this.message = message;
  }
}
import { HashAlgorithm, PluginOptions } from "../types";
import { extractImageLayer } from "./layer";
import {
  ExtractAction,
  ExtractedLayers,
  ExtractedLayersAndManifest,
  ImageConfig,
  TarArchiveManifest,
} from "./types";

const debug = Debug("snyk");

export interface ArchiveConfig {
  isLayerFile: (name: string) => boolean;
  isImageConfigFile: (name: string) => boolean;
  formatLabel: string;
  layerErrorType: string;
  extractImageId: (configValue: string) => string;
}

export const dockerArchiveConfig: ArchiveConfig = {
  isLayerFile: (name) => basename(name).endsWith(".tar"),
  isImageConfigFile: (name) => new RegExp("[A-Fa-f0-9]{64}\\.json").test(name),
  formatLabel: "Docker",
  layerErrorType: "tar",
  extractImageId: (configValue) => configValue.split(".")[0],
};

export const kanikoArchiveConfig: ArchiveConfig = {
  isLayerFile: (name) => basename(name).endsWith(".tar.gz"),
  isImageConfigFile: (name) => new RegExp("sha256:[A-Fa-f0-9]{64}").test(name),
  formatLabel: "Kaniko",
  layerErrorType: "tar.gz",
  extractImageId: (configValue) => configValue,
};

export function createExtractArchive(
  config: ArchiveConfig,
): (
  archiveFilesystemPath: string,
  extractActions: ExtractAction[],
  options: Partial<PluginOptions>,
) => Promise<ExtractedLayersAndManifest> {
  return (archiveFilesystemPath, extractActions, _options) =>
    new Promise((resolve, reject) => {
      const tarExtractor: Extract = extract();
      const layers: Record<string, ExtractedLayers> = {};
      let manifest: TarArchiveManifest;
      let imageConfig: ImageConfig;

      tarExtractor.on("entry", async (header, stream, next) => {
        if (header.type === "file") {
          const normalizedName = normalizePath(header.name);
          if (config.isLayerFile(normalizedName)) {
            try {
              layers[normalizedName] = await extractImageLayer(
                stream,
                extractActions,
              );
            } catch (error) {
              debug(`Error extracting layer content from: '${getErrorMessage(error)}'`);
              reject(
                new Error(`Error reading ${config.layerErrorType} archive`),
              );
            }
          } else if (isManifestFile(normalizedName)) {
            const manifestArray = await getManifestFile<TarArchiveManifest[]>(
              stream,
            );
            manifest = manifestArray[0];
          } else if (config.isImageConfigFile(normalizedName)) {
            imageConfig = await getManifestFile<ImageConfig>(stream);
          }
        }

        stream.resume();
        next();
      });

      tarExtractor.on("finish", () => {
        try {
          resolve(assembleLayersAndManifest(manifest, imageConfig, layers));
        } catch (error) {
          debug(
            `Error getting layers and manifest content from ${config.formatLabel} archive: ${getErrorMessage(error)}`,
          );
          reject(
            new InvalidArchiveError(`Invalid ${config.formatLabel} archive`),
          );
        }
      });

      tarExtractor.on("error", (error) => reject(error));

      createReadStream(archiveFilesystemPath)
        .on("error", (error) => reject(error))
        .pipe(gunzip())
        .pipe(tarExtractor);
    });
}

function assembleLayersAndManifest(
  manifest: TarArchiveManifest,
  imageConfig: ImageConfig,
  layers: Record<string, ExtractedLayers>,
): ExtractedLayersAndManifest {
  const layersWithNormalizedNames = manifest.Layers.map((layerName) =>
    normalizePath(layerName),
  );
  const filteredLayers = layersWithNormalizedNames
    .filter((layerName) => layers[layerName])
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

async function getManifestFile<T>(stream: Readable): Promise<T> {
  return streamToJson<T>(stream);
}

function isManifestFile(name: string): boolean {
  return name === "manifest.json";
}

export function createGetImageIdFromManifest(
  config: ArchiveConfig,
): (manifest: TarArchiveManifest) => string {
  return (manifest) => {
    try {
      const imageId = config.extractImageId(manifest.Config);
      if (imageId.includes(":")) {
        return imageId;
      }
      return `${HashAlgorithm.Sha256}:${imageId}`;
    } catch (err) {
      throw new Error("Failed to extract image ID from archive manifest");
    }
  };
}

export function getManifestLayers(manifest: TarArchiveManifest): string[] {
  return manifest.Layers.map((layer) => normalizePath(layer));
}
