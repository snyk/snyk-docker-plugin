import * as Debug from "debug";
import { Decompress as ZstdDecompress } from "fzstd";
import { normalize as normalizePath } from "path";
import { ChiselPackage } from "../../analyzer/types";
import { getContentAsBuffer } from "../../extractor";
import { ExtractAction, ExtractedLayers } from "../../extractor/types";
import { streamToBuffer } from "../../stream-utils";

const debug = Debug("snyk");

/**
 * Extract action for Ubuntu Chisel manifest files.
 *
 * Chisel is Ubuntu's tool for creating minimal container images by installing
 * only specific "slices" of Debian packages. The manifest.wall file is a
 * zstd-compressed NDJSON (newline-delimited JSON) file that records all
 * installed packages, slices, and files for integrity verification and SBOM generation.
 *
 * See: https://documentation.ubuntu.com/chisel/en/latest/reference/manifest/
 */
export const getChiselManifestAction: ExtractAction = {
  actionName: "chisel-manifest",
  filePathMatches: (filePath) =>
    filePath === normalizePath("/var/lib/chisel/manifest.wall"),
  callback: streamToBuffer,
};

/**
 * Extracts and parses Chisel package information from Docker image layers.
 *
 * Searches for the Chisel manifest file (/var/lib/chisel/manifest.wall), decompresses it,
 * and extracts package entries. The manifest uses NDJSON format where each line is a
 * separate JSON object with a "kind" field indicating the entry type.
 *
 * @param extractedLayers - Layers extracted from the Docker image
 * @returns Array of Chisel packages found in the manifest, or empty array if not found
 */
export function getChiselManifestContent(
  extractedLayers: ExtractedLayers,
): ChiselPackage[] {
  const compressedManifest = getContentAsBuffer(
    extractedLayers,
    getChiselManifestAction,
  );

  if (!compressedManifest) {
    return [];
  }

  try {
    const decompressed = decompressZstd(compressedManifest);
    const manifestText = decompressed.toString("utf8");

    const packages: ChiselPackage[] = [];
    const lines = manifestText.split("\n");

    for (const line of lines) {
      if (!line.trim()) {
        continue;
      }

      try {
        const entry = JSON.parse(line);
        // Only extract package entries; manifest also contains "slice", "path", and "content" entries
        if (entry.kind === "package") {
          // Validate required fields exist before creating package object
          if (!entry.name || !entry.version || !entry.sha256 || !entry.arch) {
            debug(
              `Skipping package entry with missing required fields: ${JSON.stringify(
                entry,
              )}`,
            );
            continue;
          }
          packages.push({
            kind: entry.kind,
            name: entry.name,
            version: entry.version,
            sha256: entry.sha256,
            arch: entry.arch,
          });
        }
      } catch (parseError) {
        // Skip malformed JSON lines - manifest may be corrupted or have trailing newlines
        debug(
          `Failed to parse Chisel manifest line: ${
            parseError instanceof Error
              ? parseError.message
              : String(parseError)
          }`,
        );
        continue;
      }
    }

    debug(`Found ${packages.length} Chisel packages in manifest`);
    return packages;
  } catch (error) {
    debug(
      `Failed to process Chisel manifest: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
    return [];
  }
}

/**
 * Decompresses zstd-compressed Chisel manifest data.
 * Chisel uses zstd for better compression ratios on small manifests.
 */
function decompressZstd(compressed: Buffer): Buffer {
  const chunks: Buffer[] = [];

  try {
    const decompressor = new ZstdDecompress((data: Uint8Array) => {
      chunks.push(Buffer.from(data));
    });

    decompressor.push(new Uint8Array(compressed), true);

    return Buffer.concat(chunks);
  } catch (error) {
    throw new Error(
      `Zstd decompression failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}
