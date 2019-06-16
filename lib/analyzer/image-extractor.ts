import { createReadStream } from "fs";
import * as minimatch from "minimatch";
import { basename } from "path";
import { Readable } from "stream";
import { extract, Extract } from "tar-stream";
import { streamToString } from "../stream-utils";

export {
  extractFromTar,
  ExtractedFiles,
  ExtractFileCallback,
  mapLookups,
  LookupEntry,
};

interface ExtractedFiles {
  [key: string]: string;
}

interface ExtractedFilesByLayers {
  [key: string]: ExtractedFiles;
}

type ExtractFileCallback = (stream: Readable) => Promise<string>;

interface LookupEntry {
  p: string; // path pattern to look for
  c: ExtractFileCallback; // handler to manipulate stream into a string
}

/**
 * Create lookup entries array by mapping the specified callback with each of the specified patterns
 * @param patterns array of path pattern strings
 * @param callback handler to manipulate stream into a string
 */
const mapLookups = (patterns, callback) => {
  return patterns.map((pattern) => {
    return { p: pattern, c: callback };
  });
};

/**
 * Extract key files form the specified TAR stream.
 * @param layerTarStream image layer as a Readable TAR stream
 * @param lookups array of pattern, callback pairs
 * @returns extracted file products
 */
async function extractFromLayer(
  layerTarStream: Readable,
  lookups: LookupEntry[],
): Promise<ExtractedFiles> {
  return new Promise((resolve) => {
    const result: ExtractedFiles = {};
    const layerExtract: Extract = extract();
    layerExtract.on("entry", (header, stream, next) => {
      lookups.forEach((lookup) => {
        if (minimatch(`/${header.name}`, lookup.p, { dot: true })) {
          lookup.c(stream).then((value) => (result[`/${header.name}`] = value));
        }
      });
      stream.resume(); // auto drain the stream
      next(); // ready for next entry
    });
    layerExtract.on("finish", () => {
      // all layer level entries read
      resolve(result);
    });
    layerTarStream.pipe(layerExtract);
  });
}

/**
 * Extract key files textual content and MD5 sum from the specified TAR file.
 * @param imageTarPath path to image file saved in tar format
 * @param lookups array of pattern, callback pairs
 * @returns extracted files products
 */
async function extractFromTar(
  imageTarPath: string,
  lookups: LookupEntry[],
): Promise<ExtractedFiles> {
  return new Promise((resolve) => {
    const imageExtract: Extract = extract();
    const layers: ExtractedFilesByLayers = {};
    let layersNames: string[];

    imageExtract.on("entry", (header, stream, next) => {
      if (header.type === "file") {
        if (basename(header.name) === "layer.tar") {
          extractFromLayer(stream, lookups).then((extractedKeyFiles) => {
            layers[header.name] = extractedKeyFiles;
          });
        } else if (header.name === "manifest.json") {
          streamToString(stream).then((manifestFile) => {
            const manifest = JSON.parse(manifestFile);
            layersNames = manifest[0].Layers;
          });
        }
      }
      stream.resume(); // auto drain the stream
      next(); // ready for next entry
    });

    imageExtract.on("finish", () => {
      const result: ExtractedFiles = {};

      if (layers) {
        // reverse layer order from last to first
        for (const layerName of layersNames.reverse()) {
          // layer exists, files found for this layer
          if (layerName in layers) {
            const layer: ExtractedFiles = layers[layerName];
            // go over extracted files found in this layer
            for (const filename of Object.keys(layer)) {
              // file was not found in previous layer
              if (!Reflect.has(result, filename)) {
                result[filename] = layer[filename];
              }
            }
          }
        }
      }
      resolve(result);
    });

    createReadStream(imageTarPath).pipe(imageExtract);
  });
}
