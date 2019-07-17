import * as Debug from "debug";
import { createReadStream } from "fs";
import * as minimatch from "minimatch";
import { basename } from "path";
import { Readable } from "stream";
import { extract, Extract } from "tar-stream";
import { streamToBuffer, streamToString } from "../stream-utils";

export {
  extractFromTar,
  ExtractProductsByFilename,
  ExtractCallback,
  ExtractAction,
};

const debug = Debug("snyk");

type ExtractCallback = (buffer: Buffer) => string | Buffer;

interface ExtractProducts {
  [callbackName: string]: string | Buffer;
}

interface ExtractProductsByFilename {
  [filename: string]: ExtractProducts;
}

interface ExtractAction {
  name: string; // name, should be unique, for this action
  pattern: string; // path pattern to look for
  callback?: ExtractCallback; // convert Buffer into a string or Buffer
}

/**
 * Extract key files form the specified TAR stream.
 * @param layerTarStream image layer as a Readable TAR stream
 * @param extractActions array of pattern, callbacks pairs
 * @returns extracted file products
 */
async function extractFromLayer(
  layerTarStream: Readable,
  extractActions: ExtractAction[],
): Promise<ExtractProductsByFilename> {
  return new Promise((resolve) => {
    const result: ExtractProductsByFilename = {};
    const layerExtract: Extract = extract();
    layerExtract.on("entry", async (header, stream, next) => {
      if (
        header.type === "file" ||
        header.type === "link" ||
        header.type === "symlink"
      ) {
        const filename = `/${header.name}`;
        // convert stream to buffer in order to allow it
        //  to be processed multiple times by the callback
        const buffer = await streamToBuffer(stream);
        for (const extractAction of extractActions) {
          const callback = extractAction.callback;
          if (minimatch(filename, extractAction.pattern, { dot: true })) {
            if (header.type === "file") {
              // initialize the files associated products dict
              if (!result[filename]) {
                result[filename] = {};
              }
              // store the product under the search action name
              result[filename][extractAction.name] = callback
                ? callback(buffer)
                : buffer;
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
 * @param extractActions array of pattern, callbacks pairs
 * @returns array of extracted files products sorted by the reverse order of
 *  the layers from last to first
 */
async function extractLayersFromTar(
  imageTarPath: string,
  extractActions: ExtractAction[],
): Promise<ExtractProductsByFilename[]> {
  return new Promise((resolve) => {
    const imageExtract: Extract = extract();
    const layers: { [layerName: string]: ExtractProductsByFilename } = {};
    let layersNames: string[];

    imageExtract.on("entry", async (header, stream, next) => {
      if (header.type === "file") {
        if (basename(header.name) === "layer.tar") {
          layers[header.name] = await extractFromLayer(stream, extractActions);
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
      // return the layers content without the name
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
 * @param extractActions array of pattern, callbacks pairs
 * @returns extracted files products
 */
async function extractFromTar(
  imageTarPath: string,
  extractActions: ExtractAction[],
): Promise<ExtractProductsByFilename> {
  const layers: ExtractProductsByFilename[] = await extractLayersFromTar(
    imageTarPath,
    extractActions,
  );

  if (!layers) {
    return {};
  }

  const result: ExtractProductsByFilename = {};

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
