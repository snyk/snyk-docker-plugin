import { spawn } from "child_process";
import { Transform } from "stream";
import { createGunzip } from "zlib";

/**
 * Creates a transform stream that automatically detects and decompresses data based on magic numbers.
 *
 * Supports three formats:
 * - gzip (magic: 1f 8b) - Decompressed using Node.js built-in zlib
 * - zstd (magic: 28 b5 2f fd) - Decompressed using system zstd command
 * - uncompressed - Passed through unchanged
 *
 * This is necessary because OCI images from containerd may use zstd compression,
 * while older Docker archives use gzip. Additionally, manifest and config files
 * within OCI archives are typically uncompressed JSON.
 *
 * Named after the gunzip-maybe library, which only handled gzip detection.
 */
export function decompressMaybe(): Transform {
  let headerRead = false;
  let compressionType: "gzip" | "zstd" | "none" | null = null;
  let decompressionStream: Transform | null = null;
  const buffer: Buffer[] = [];

  const transform = new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      if (!headerRead) {
        buffer.push(chunk);
        const combined = Buffer.concat(buffer);

        // Check for gzip magic number (1f 8b)
        if (
          combined.length >= 2 &&
          combined[0] === 0x1f &&
          combined[1] === 0x8b
        ) {
          compressionType = "gzip";
          headerRead = true;

          // Setup gzip decompressor
          decompressionStream = createGunzip();
          decompressionStream.on("data", (data: Buffer) =>
            transform.push(data),
          );
          decompressionStream.on("error", (err: Error) =>
            transform.destroy(err),
          );

          // Write buffered data
          decompressionStream.write(combined);
          buffer.length = 0;
          callback();
        }
        // Check for zstd magic number (28 b5 2f fd)
        else if (
          combined.length >= 4 &&
          combined[0] === 0x28 &&
          combined[1] === 0xb5 &&
          combined[2] === 0x2f &&
          combined[3] === 0xfd
        ) {
          compressionType = "zstd";
          headerRead = true;
          // Buffer all zstd data and decompress in flush() since we use the system
          // zstd command which requires the complete compressed data at once.
          callback();
        }
        // After 8 bytes, assume uncompressed
        else if (combined.length >= 8) {
          compressionType = "none";
          headerRead = true;

          // Push buffered data as-is
          this.push(combined);
          buffer.length = 0;
          callback();
        } else {
          // Need more data
          callback();
        }
      } else {
        // Header already read
        if (compressionType === "gzip" && decompressionStream) {
          decompressionStream.write(chunk);
          callback();
        } else if (compressionType === "zstd") {
          buffer.push(chunk);
          callback();
        } else {
          // No compression
          callback(null, chunk);
        }
      }
    },

    async flush(callback) {
      if (compressionType === "gzip" && decompressionStream) {
        decompressionStream.once("end", () => callback());
        decompressionStream.end();
      } else if (compressionType === "zstd") {
        // Use system zstd command for decompression. Available npm packages either
        // lack streaming APIs or fail to compile with modern Node.js versions.
        // Since containerd uses zstd, the command should be available on the system.
        const combined = Buffer.concat(buffer);

        if (combined.length === 0) {
          callback(new Error("No zstd data to decompress"));
          return;
        }

        const zstd = spawn("zstd", ["-d", "-c"], {
          stdio: ["pipe", "pipe", "pipe"],
        });

        let errorOutput = "";

        zstd.stdout.on("data", (chunk: Buffer) => {
          // Push each chunk immediately as it arrives for streaming behavior
          transform.push(chunk);
        });

        zstd.stderr.on("data", (chunk: Buffer) => {
          errorOutput += chunk.toString();
        });

        zstd.on("close", (code: number) => {
          if (code !== 0) {
            callback(
              new Error(
                `zstd decompression failed (exit code ${code}): ${errorOutput}`,
              ),
            );
          } else {
            callback();
          }
        });

        zstd.on("error", (err: Error) => {
          callback(
            new Error(
              `Failed to spawn zstd command: ${err.message}. Ensure zstd is installed.`,
            ),
          );
        });

        // Write compressed data and close stdin
        zstd.stdin.write(combined);
        zstd.stdin.end();
      } else if (!headerRead && buffer.length > 0) {
        // Stream ended before determining compression, assume uncompressed
        this.push(Buffer.concat(buffer));
        callback();
      } else {
        callback();
      }
    },
  });

  return transform;
}
