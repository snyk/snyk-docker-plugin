import { Decompress as ZstdDecompress } from "fzstd";

/**
 * Decompresses zstd-compressed data from a buffer.
 *
 * This is a synchronous buffer-to-buffer decompression utility.
 * For streaming zstd decompression, use the decompressMaybe transform stream.
 *
 * @param compressed Buffer containing zstd-compressed data
 * @returns Decompressed data as a Buffer
 * @throws Error if decompression fails
 */
export function decompressZstd(compressed: Buffer): Buffer {
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
