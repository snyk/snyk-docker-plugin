import { createReadStream } from "fs";
import * as md5 from "md5";
import * as minimatch from "minimatch";
import { basename } from "path";
import { Readable } from "stream";
import { extract, Extract } from "tar-stream";
import { streamToBuffer, streamToString } from "../stream-utils";

export { extractImageKeyFiles, ExtractedImage, ExtractedKeyFiles };

interface ExtractedKeyFiles {
  txt: { [key: string]: string };
  md5: { [key: string]: string };
}

interface ExtractedImage {
  manifest: string;
  layers: Layers;
}

interface Layers {
  [key: string]: ExtractedKeyFiles;
}

/**
 * Extract key files form the specified TAR stream.
 * @param stream image layer as a Readable TAR stream
 * @param name layer name
 * @param txtPatterns list of plain text key files paths patterns to extract and return as strings
 * @param md5Patterns list of binary key files paths patterns to extract and return their MD5 sum
 * @returns key files found in the specified layer TAR stream
 */
async function extractLayerKeyFiles(
  stream: Readable,
  txtPatterns: string[],
  md5Patterns: string[] = [],
): Promise<ExtractedKeyFiles> {
  return new Promise((resolve) => {
    const result: ExtractedKeyFiles = { txt: {}, md5: {} };
    const layerExtract: Extract = extract();
    layerExtract.on("entry", (header, stream, next) => {
      txtPatterns.forEach((pattern) => {
        if (minimatch(header.name, pattern, { dot: true })) {
          streamToString(stream).then((value) => {
            result.txt[header.name] = value;
          });
        }
      });
      md5Patterns.forEach((pattern) => {
        if (minimatch(header.name, pattern, { dot: true })) {
          streamToBuffer(stream).then((value) => {
            result.md5[header.name] = md5(value);
          });
        }
      });
      stream.resume(); // auto drain the stream
      next(); // ready for next entry
    });
    layerExtract.on("finish", () => {
      // all layer level entries read
      resolve(result);
    });
    stream.pipe(layerExtract);
  });
}

/**
 * Extract key files textual content and MD5 sum from the specified TAR file.
 * @param imageTarPath path to image file saved in tar format
 * @param txtPatterns list of plain text key files paths patterns to extract and return as strings
 * @param md5Patterns list of binary key files paths patterns to extract and return their MD5 sum
 * @returns manifest file and key files by inner layers
 */
async function extractImageKeyFiles(
  imageTarPath: string,
  txtPatterns: string[],
  md5Patterns: string[] = [],
): Promise<ExtractedImage> {
  return new Promise((resolve) => {
    const imageExtract: Extract = extract();
    let manifest: string;
    const layers: Layers = {};

    imageExtract.on("entry", (header, stream, next) => {
      if (header.type === "file") {
        if (basename(header.name) === "layer.tar") {
          extractLayerKeyFiles(stream, txtPatterns, md5Patterns).then(
            (extractedKeyFiles) => {
              layers[header.name] = extractedKeyFiles;
            },
          );
        } else if (header.name === "manifest.json") {
          streamToString(stream).then((manifestFile) => {
            manifest = manifestFile;
          });
        }
      }
      stream.resume(); // auto drain the stream
      next(); // ready for next entry
    });
    imageExtract.on("finish", () => {
      // all image level entries read
      resolve({
        manifest,
        layers,
      });
    });
    createReadStream(imageTarPath).pipe(imageExtract);
  });
}
