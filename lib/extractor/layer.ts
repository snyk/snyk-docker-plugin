import * as Debug from "debug";
import * as path from "path";
import { Readable } from "stream";
import { extract, Extract } from "tar-stream";
import { getErrorMessage } from "../error-utils";
import { applyCallbacks, isResultEmpty } from "./callbacks";
import { decompressMaybe } from "./decompress-maybe";
import { ExtractAction, ExtractedLayers, SymlinkMap } from "./types";

export function isWhitedOutFile(filename: string) {
  return filename.match(/.wh./gm);
}

const debug = Debug("snyk");

/**
 * Extract key files from the specified TAR stream.
 *
 * Layer streams may be compressed with gzip, zstd, or uncompressed.
 * The decompressMaybe transform handles all three formats automatically.
 * @param layerTarStream image layer as a Readable TAR stream. Note: consumes the stream.
 * @param extractActions array of pattern, callbacks pairs
 * @returns extracted file products
 */
export interface LayerExtractionResult {
  extractedLayers: ExtractedLayers;
  symlinks: SymlinkMap;
}

export async function extractImageLayer(
  layerTarStream: Readable,
  extractActions: ExtractAction[],
): Promise<LayerExtractionResult> {
  return new Promise((resolve, reject) => {
    const result: ExtractedLayers = {};
    const symlinks: SymlinkMap = {};
    const tarExtractor: Extract = extract();

    tarExtractor.on("entry", async (headers, stream, next) => {
      const absoluteFileName = path.join(path.sep, headers.name);

      // Symlinks are path redirects; hard links are alternate names for the same
      // inode and must not be treated as redirects during path canonicalization.
      if (headers.type === "symlink") {
        const linkTarget = headers.linkname;
        if (linkTarget) {
          symlinks[absoluteFileName] = absoluteLinkTarget(
            headers.name,
            linkTarget,
          );
        }
      } else if (headers.type === "file") {
        const matchedActions = extractActions.filter((action) =>
          action.filePathMatches(absoluteFileName),
        );
        if (matchedActions.length > 0) {
          try {
            const callbackResult = await applyCallbacks(
              matchedActions,
              stream,
              headers.size,
            );
            if (
              !isResultEmpty(callbackResult) ||
              isWhitedOutFile(absoluteFileName)
            ) {
              result[absoluteFileName] = callbackResult;
            }
          } catch (error) {
            // An ExtractAction has thrown an uncaught exception, likely a bug in the code!
            debug(
              `Exception thrown while applying callbacks during image layer extraction: ${getErrorMessage(
                error,
              )}`,
            );
            reject(error);
            return;
          }
        } else if (isWhitedOutFile(absoluteFileName)) {
          result[absoluteFileName] = {};
        }
      }

      stream.resume(); // auto drain the stream
      next(); // ready for next entry
    });

    tarExtractor.on("finish", () => {
      // all layer level entries read
      resolve({ extractedLayers: result, symlinks });
    });

    tarExtractor.on("error", (error) => reject(error));

    layerTarStream.pipe(decompressMaybe()).pipe(tarExtractor);
  });
}

/**
 * Resolve a tar symlink target to an absolute path within the image.
 * A relative target resolves against the symlink's own directory; tar entry
 * names always use forward slashes, so this is posix math on every platform.
 */
function absoluteLinkTarget(entryName: string, linkTarget: string): string {
  if (linkTarget.startsWith("/")) {
    return path.posix.normalize(linkTarget);
  }
  const linkDir = path.posix.dirname(path.posix.normalize("/" + entryName));
  return path.posix.normalize(path.posix.join(linkDir, linkTarget));
}
