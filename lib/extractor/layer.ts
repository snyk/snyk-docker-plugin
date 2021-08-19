import * as Debug from "debug";
import * as gunzip from "gunzip-maybe";
import * as path from "path";
import { Readable } from "stream";
import { extract, Extract } from "tar-stream";
import * as unzipper from "unzipper";
import { getJarFileContentAction } from "../inputs/java/static";
import { applyCallbacks, isResultEmpty } from "./callbacks";
import { ExtractAction, ExtractedLayers } from "./types";

const debug = Debug("snyk");

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
        const absoluteFileName = path.join(path.sep, headers.name);
        const matchedActions = extractActions.filter((action) =>
          action.filePathMatches(absoluteFileName),
        );
        if (matchedActions.length > 0) {
          try {
            if (absoluteFileName.endsWith("service.jar")) {
              await extractNestedJar(stream, result);
            }

            const callbackResult = await applyCallbacks(
              matchedActions,
              stream,
              headers.size,
            );

            if (!isResultEmpty(callbackResult)) {
              result[absoluteFileName] = callbackResult;
            }
          } catch (error) {
            // An ExtractAction has thrown an uncaught exception, likely a bug in the code!
            debug(
              "Exception thrown while applying callbacks during image layer extraction",
              JSON.stringify(error),
            );
            reject(error);
          }
        }
      }

      stream.resume(); // auto drain the stream
      next(); // ready for next entry
    });

    tarExtractor.on("finish", () => {
      // all layer level entries read
      resolve(result);
    });

    tarExtractor.on("error", (error) => {
      console.log(
        "🚀 ~ file: layer.ts ~ line 74 ~ tarExtractor.on ~ error",
        error,
      );

      reject(error);
    });

    layerTarStream.pipe(gunzip()).pipe(tarExtractor);
  });
}

async function extractNestedJar(jarStream: Readable, result) {
  return new Promise((resolve, reject) => {
    const allPaths: string[] = [];
    // const parsed = jarStream.pipe(unzip.Parse());
    // jarStream.pipe(unzip.Parse()).on("entry", async (entry) => {
    jarStream
      .pipe(unzipper.Parse())
      .on("entry", async (entry) => {
        allPaths.push(entry.path);
        if (entry.type === "File" && entry.path.endsWith(".jar")) {
          const callbackResult = await applyCallbacks(
            [getJarFileContentAction],
            jarStream,
          );

          if (!isResultEmpty(callbackResult)) {
            result[entry.path] = callbackResult;
          }
        }
        // else {
        //   // entry.autodrain();
        // }

        // entry.resume(); // auto drain the stream
        // next(); // ready for next entry
        console.log(
          "🚀 ~ file: layer.ts ~ line 123 ~ .on ~ allPaths",
          allPaths,
        );
      })

      .on("finish", () => {
        resolve(result);
      })

      .on("error", (error) => {
        console.log(
          "🚀 ~ file: layer.ts ~ line 122 ~ returnnewPromise ~ error",
          error,
        );
        reject(error);
      });
  });
}
