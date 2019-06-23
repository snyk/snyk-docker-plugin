import * as Debug from "debug";
import { createReadStream } from "fs";
import * as minimatch from "minimatch";
import { basename } from "path";
import { Readable } from "stream";
import { extract, Extract } from "tar-stream";
import { streamToBuffer, streamToString } from "../stream-utils";

export {
  extractFromTar,
  SearchActionProducts,
  SearchActionCallback,
  mapActionsToFiles,
  SearchAction,
};

const debug = Debug("snyk");

interface SearchActionProducts {
  [key: string]: { [key: string]: string | Buffer };
}

interface SearchActionCallback {
  name: string; // name, should be unique, for this action
  callback: (buffer: Buffer) => string | Buffer; // convert Buffer into a string or Buffer
}

interface SearchAction {
  pattern: string; // path pattern to look for
  callbacks: SearchActionCallback[]; // array of handlers
}

/**
 * Create lookup entries array by mapping the specified callback with each of
 *  the specified patterns
 * @param patterns array of path pattern strings
 * @param callback handler to process files content
 *  a stream into a string
 */
const mapActionsToFiles = (
  patterns: string[],
  callback: SearchActionCallback,
) => {
  return patterns.map((p) => {
    return { pattern: p, callbacks: [callback] };
  });
};

/**
 * Extract key files form the specified TAR stream.
 * @param layerTarStream image layer as a Readable TAR stream
 * @param searchActions array of pattern, callbacks pairs
 * @returns extracted file products
 */
async function extractFromLayer(
  layerTarStream: Readable,
  searchActions: SearchAction[],
): Promise<SearchActionProducts> {
  return new Promise((resolve) => {
    const result: SearchActionProducts = {};
    const layerExtract: Extract = extract();
    layerExtract.on("entry", async (header, stream, next) => {
      if (
        header.type === "file" ||
        header.type === "link" ||
        header.type === "symlink"
      ) {
        const name = `/${header.name}`;
        let buffer: Buffer | undefined;
        for (const searchAction of searchActions) {
          if (minimatch(name, searchAction.pattern, { dot: true })) {
            if (header.type === "file") {
              // convert stream to buffer
              buffer = buffer || (await streamToBuffer(stream));
              // initialize the files associated products dict
              result[name] = result[name] || {};
              // go over the callbacks and assign each product under its callback name
              for (const callback of searchAction.callbacks) {
                // already found?
                if (Reflect.has(result[name], callback.name)) {
                  debug(`duplicate match ${name} for ${searchAction.pattern}`);
                }
                // store product
                result[name][callback.name] = callback.callback(buffer);
              }
            } else {
              // target is a link or a symlink
              debug(`${header.type} '${header.name}' -> '${header.linkname}'`);
            }
          }
        }
      }
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
 * Retrieve the products of files content from the specified TAR file.
 * @param imageTarPath path to image file saved in tar format
 * @param searchActions array of pattern, callbacks pairs
 * @returns array of extracted files products sorted by the reverse order of
 *  the layers from last to first
 */
async function extractLayersFromTar(
  imageTarPath: string,
  searchActions: SearchAction[],
): Promise<SearchActionProducts[]> {
  return new Promise((resolve) => {
    const imageExtract: Extract = extract();
    const layers: { [key: string]: SearchActionProducts } = {};
    let layersNames: string[];

    imageExtract.on("entry", async (header, stream, next) => {
      if (header.type === "file") {
        if (basename(header.name) === "layer.tar") {
          layers[header.name] = await extractFromLayer(stream, searchActions);
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
      // reverse layers order from last to first
      // skip (ignore) non-existent layers
      // return the layers content without the layer name
      resolve(
        layersNames
          .reverse()
          .filter((layersName) => layers[layersName])
          .map((layerName) => layers[layerName]),
      );
    });
    createReadStream(imageTarPath).pipe(imageExtract);
  });
}

/**
 * Extract key files textual content and MD5 sum from the specified TAR file
 * @param imageTarPath path to image file saved in tar format
 * @param searchActions array of pattern, callbacks pairs
 * @returns extracted files products
 */
async function extractFromTar(
  imageTarPath: string,
  searchActions: SearchAction[],
): Promise<SearchActionProducts> {
  const layers: SearchActionProducts[] = await extractLayersFromTar(
    imageTarPath,
    searchActions,
  );

  if (!layers) {
    return {};
  }

  const result: SearchActionProducts = {};

  // reverse layer order from last to first
  for (const layer of layers) {
    // go over extracted files products found in this layer
    for (const filename of Object.keys(layer)) {
      // file was not found
      if (!Reflect.has(result, filename)) {
        result[filename] = layer[filename];
      }
    }
  }
  return result;
}
