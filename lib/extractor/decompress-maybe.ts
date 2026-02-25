import { Decompress as ZstdDecompress } from "fzstd";
import { Transform } from "stream";
import { createGunzip } from "zlib";

/**
 * Creates a transform stream that automatically detects and decompresses data based on magic numbers.
 *
 * Supports three formats:
 * - gzip (magic: 1f 8b) - Streamed through Node.js built-in zlib
 * - zstd (magic: 28 b5 2f fd) - Streamed through fzstd library
 * - uncompressed - Passed through unchanged
 *
 * Both gzip and zstd use streaming decompression to avoid buffering entire layers in memory.
 * This is critical for handling large image layers (multiple GB) without excessive memory usage.
 *
 * OCI images from containerd may use zstd compression, while older Docker archives use gzip.
 * Manifest and config files within OCI archives are typically uncompressed JSON.
 *
 * Named after the gunzip-maybe library, which only handled gzip detection.
 */
export function decompressMaybe(): Transform {
  let headerRead = false;
  let compressionType: "gzip" | "zstd" | "none" | null = null;
  let gzipStream: Transform | null = null;
  let zstdStream: ZstdDecompress | null = null;
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

          gzipStream = createGunzip();
          gzipStream.on("data", (data: Buffer) => transform.push(data));
          gzipStream.on("error", (err: Error) => transform.destroy(err));

          try {
            gzipStream.write(combined);
          } catch (err) {
            callback(err instanceof Error ? err : new Error(String(err)));
            return;
          }
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

          zstdStream = new ZstdDecompress(
            (data: Uint8Array, final?: boolean) => {
              transform.push(Buffer.from(data));
            },
          );

          try {
            zstdStream.push(new Uint8Array(combined), false);
          } catch (err) {
            callback(
              new Error(
                `zstd decompression failed: ${
                  err instanceof Error ? err.message : String(err)
                }`,
              ),
            );
            return;
          }
          buffer.length = 0;
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
        if (compressionType === "gzip" && gzipStream) {
          try {
            gzipStream.write(chunk);
          } catch (err) {
            callback(err instanceof Error ? err : new Error(String(err)));
            return;
          }
          callback();
        } else if (compressionType === "zstd" && zstdStream) {
          try {
            zstdStream.push(new Uint8Array(chunk), false);
            callback();
          } catch (err) {
            callback(
              new Error(
                `zstd decompression failed: ${
                  err instanceof Error ? err.message : String(err)
                }`,
              ),
            );
          }
        } else {
          // No compression
          callback(null, chunk);
        }
      }
    },

    flush(callback) {
      if (compressionType === "gzip" && gzipStream) {
        gzipStream.once("end", () => callback());
        gzipStream.once("error", (err) => callback(err));
        gzipStream.end();
      } else if (compressionType === "zstd" && zstdStream) {
        try {
          zstdStream.push(new Uint8Array(0), true);
          callback();
        } catch (err) {
          callback(
            new Error(
              `zstd decompression failed: ${
                err instanceof Error ? err.message : String(err)
              }`,
            ),
          );
        }
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
